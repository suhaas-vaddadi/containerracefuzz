//! One judged run, and what a seed makes of them: its baseline, a discovery
//! per window, and a new Violation's confirmation and minimization. `replay`
//! does the last two from a schedule file.

use crate::cli;
use anyhow::{bail, ensure, Context, Result};
use scx_crfuzz::backend::{self, GateBackend};
use scx_crfuzz::engine::{self, Decision, End, Judge, Replay};
use scx_crfuzz::gate;
use scx_crfuzz::name::EventId;
use scx_crfuzz::oracle::{self, Alice, Canary, Class, Finding};
use scx_crfuzz::pos::Pos;
use scx_crfuzz::schedule::{self, Config, Fixed, Schedule};
use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::os::unix::{ffi::OsStrExt, fs::DirBuilderExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Replays a discovery gets to reproduce before it counts as unconfirmed.
const CONFIRM_TRIES: u32 = 3;

/// One judged run: the probe's and the canary's findings, and the ending.
pub struct Judged {
    /// None: the deadline, or a self-check failed on a changed canary.
    pub end: Option<ExitStatus>,
    /// Read and write halves together.
    found: Vec<Finding>,
    /// Ended by the deadline (a replay may end there too).
    deadline: bool,
    /// `found`, normalized: what replays compare.
    norm: BTreeSet<Finding>,
    /// Removed on drop unless kept (the evidence of a Violation).
    pub canary: Canary,
}

/// What became of a run that did not fail.
enum Ran {
    Judged(Judged),
    /// Not started, or cut short: a signal, `--time`, another worker's
    /// failure, a lost scheduler. Nothing records it.
    Stopped,
    /// A replay left its schedule, or the mutator failed (so it never
    /// attacked, and an unflagged run would pass as Clean): one confirm try
    /// or minimize step lost; anywhere else an invalid run.
    Missed(String),
}

/// A seed's baseline: its exit (for the oracle), the holds a mutator could
/// fire at, and its time.
pub struct Baseline {
    pub end: Option<ExitStatus>,
    pub targets: Vec<EventId>,
    pub secs: f64,
}

/// A confirmation's result.
pub enum Confirmed {
    Stopped,
    No,
    /// With the guilty step; None: no single guilty hold, or a confirmed
    /// non-Violation.
    Yes(Option<usize>),
}

/// What every run of this crfuzz shares.
pub struct Runner {
    pub cfg: Config,
    pub alice: Alice,
    verbose: bool,
    /// `--time`: no run starts past it.
    until: Option<Instant>,
    /// A worker failed: the others stop as on a signal.
    pub fatal: AtomicBool,
    /// The gate scheduler is gone (ejected, or the crfuzz whose it was
    /// exited) or was restarted: every run from then on would fail.
    pub lost: AtomicBool,
    seq: u64,
    /// Canary numbers, one per run: a kept canary is never reused.
    runs: AtomicU32,
    /// The `--private` copies, `work/<worker>/<i>`; removed on drop.
    work: PathBuf,
    /// Ours for this process's life unless crfuzz's already runs.
    _sched: Option<gate::Scheduler>,
}

/// `--private` directories that can't be: refused before anything starts.
/// `output`: the campaign's DIR.
pub fn check_private(cfg: &Config, output: Option<&Path>) -> Result<()> {
    // The canaries stay shared (unique names), the campaign's output too.
    let canaries = std::fs::canonicalize(oracle::ROOT).unwrap_or_else(|_| oracle::ROOT.into());
    let output = output.map(|d| std::fs::canonicalize(d).or_else(|_| std::path::absolute(d))).transpose()?;
    for d in &cfg.private {
        ensure!(d.is_dir(), "--private {}: not a directory", d.display());
        ensure!(!canaries.starts_with(d) && !d.starts_with(&canaries), "--private {}: overlaps {}, where the canaries must stay shared", d.display(), canaries.display());
        ensure!(!output.as_ref().is_some_and(|o| o.starts_with(d)), "--private {}: holds DIR, whose output would land in a private copy", d.display());
    }
    Ok(())
}

/// This thread in its own mount namespace, `/` rslave (host mounts still
/// show, nothing leaks out), each of `dirs` covered by a bind mount of its
/// copy under `work` (`cp -a` of DIR itself: its owner and mode too).
/// What the thread forks inherits it. Then the cwd again: one inside a DIR
/// still points at the original.
fn isolate(dirs: &[PathBuf], work: &Path) -> Result<()> {
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).context("NUL in path");
    let ok = |r: i32, what: &dyn std::fmt::Display| -> Result<()> {
        ensure!(r == 0, "{what}: {}", std::io::Error::last_os_error());
        Ok(())
    };
    let cwd = std::env::current_dir()?;
    ok(unsafe { libc::unshare(libc::CLONE_NEWNS) }, &"unshare(CLONE_NEWNS)")?;
    ok(unsafe { libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_SLAVE, std::ptr::null()) }, &"make / rslave")?;
    // work/<pid>/<w> root-only: alice must not reach another worker's copies.
    // Ours go through the bind mount, whose root is the copy itself.
    let base = work.parent().and_then(Path::parent).context("work dir")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o755).create(base).with_context(|| base.display().to_string())?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(work).with_context(|| work.display().to_string())?;
    for (i, d) in dirs.iter().enumerate() {
        let copy = work.join(i.to_string());
        let st = Command::new("cp").arg("-a").arg("--").arg(d).arg(&copy).status().context("cp")?;
        ensure!(st.success(), "cp -a {} {}: {st}", d.display(), copy.display());
        let r = unsafe { libc::mount(c(&copy)?.as_ptr(), c(d)?.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
        ok(r, &format_args!("bind {} over {}", copy.display(), d.display()))?;
    }
    std::env::set_current_dir(&cwd).with_context(|| cwd.display().to_string())
}

/// Telemetry from a baseline: the size of one run and how much there is for
/// the mutator to hit. It sizes the campaign's estimate.
pub fn telemetry(log: &[Decision], targets: usize, secs: f64) -> String {
    let threads: BTreeSet<&str> = log.iter().map(|d| d.id.thread.as_str()).collect();
    format!(
        "telemetry: {} decisions ({} partial), {} threads, {targets} mutation targets, {secs:.1}s",
        log.len(),
        log.iter().filter(|d| d.partial).count(),
        threads.len(),
    )
}

impl Runner {
    /// The preflight, the gate scheduler, and what a dead crfuzz left behind.
    /// `time`: `--time`, counted from here.
    pub fn new(cfg: Config, verbose: bool, time: Option<Duration>) -> Result<Self> {
        let alice = Alice::parse(&cfg.attacker)?;
        cli::preflight_ok(vec![])?;
        engine::stop_on_signals();
        let sched = gate::Scheduler::start()?;
        let seq = gate::enable_seq()?;
        backend::sweep();
        let work = Path::new(oracle::ROOT).join(format!("work/{}", std::process::id()));
        // A crfuzz killed with our pid left these (sweep keeps a live pid's): never ours yet.
        let _ = std::fs::remove_dir_all(&work);
        let until = time.map(|t| Instant::now() + t);
        Ok(Runner { cfg, alice, verbose, until, fatal: AtomicBool::new(false), lost: AtomicBool::new(false), seq, runs: AtomicU32::new(0), work, _sched: sched })
    }

    /// Worker `w` (a thread) gets its own copy of every `--private` directory.
    pub fn isolate(&self, w: usize) -> Result<()> {
        if self.cfg.private.is_empty() {
            return Ok(());
        }
        isolate(&self.cfg.private, &self.work.join(w.to_string()))
    }

    /// No run starts any more.
    fn stopped(&self) -> bool {
        engine::stopped() || self.until.is_some_and(|u| Instant::now() >= u) || self.fatal.load(Relaxed) || self.lost.load(Relaxed)
    }

    /// One run with its own canary; its decisions go to `log` whatever the
    /// ending, and with -v to stdout. Its output and the layout's go to `out`
    /// after a `== <name>` line; with no `out`, nowhere, or with -v to stderr.
    /// Stdin is /dev/null.
    #[allow(clippy::too_many_arguments)]
    fn judged(&self, seed: u64, mutator: Option<&Path>, target: Option<&EventId>, replay: Option<&mut Replay>, out: Option<&Path>, name: &str, log: &mut Vec<Decision>) -> Result<Ran> {
        if self.stopped() {
            return Ok(Ran::Stopped);
        }
        let r = self.judge(seed, mutator, target, replay, out, name, log);
        // Ended once stopped (a terminal ^C also reaches the SUT): whatever
        // it says, it is not the run's own.
        if engine::stopped() {
            return Ok(Ran::Stopped);
        }
        if r.is_err() && (!gate::running().unwrap_or(false) || gate::enable_seq().ok() != Some(self.seq)) {
            if !self.lost.swap(true, Relaxed) {
                eprintln!("the gate scheduler is gone (ejected, or the crfuzz that ran it exited); --resume reruns the unfinished seeds");
            }
            return Ok(Ran::Stopped);
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn judge(&self, seed: u64, mutator: Option<&Path>, target: Option<&EventId>, replay: Option<&mut Replay>, out: Option<&Path>, name: &str, log: &mut Vec<Decision>) -> Result<Ran> {
        let file = out
            .map(|p| -> Result<std::fs::File> {
                let mut f = std::fs::File::options().create(true).append(true).open(p).with_context(|| p.display().to_string())?;
                writeln!(f, "== {name}")?;
                Ok(f)
            })
            .transpose()?;
        let stdio = |c: &mut Command| -> Result<()> {
            let (o, e): (Stdio, Stdio) = match &file {
                Some(f) => (f.try_clone()?.into(), f.try_clone()?.into()),
                None if self.verbose => (std::io::stderr().into(), std::io::stderr().into()),
                None => (Stdio::null(), Stdio::null()),
            };
            c.stdin(Stdio::null()).stdout(o).stderr(e);
            Ok(())
        };
        if let Some(l) = &self.cfg.layout {
            let mut c = Command::new(l);
            stdio(&mut c)?;
            let st = c.status().with_context(|| l.display().to_string())?;
            ensure!(st.success(), "invalid: layout {} failed: {st}", l.display());
        }
        let canary = Canary::create(self.runs.fetch_add(1, Relaxed))?;
        ensure!(backend::read_before(&canary, &self.alice)?, "invalid: self-check: the canary gate does not stop alice before the SUT has run");
        let (prog, rest) = self.cfg.cmd.split_first().context("no CMD")?;
        let mut sut = Command::new(prog);
        sut.args(rest);
        stdio(&mut sut)?;
        let mut be = GateBackend::spawn(sut)?;
        let mut j = Judge { canary: &canary, alice: self.alice.clone(), reached: None, task: None };
        let until = Instant::now().checked_add(Duration::from_secs(self.cfg.timeout)).context("--timeout too large")?;
        let end = engine::run(&mut be, &mut Pos::new(seed), mutator, target, replay, Some(&mut j), until, log);
        if self.verbose {
            // One block per run, whatever other workers print.
            let mut so = std::io::stdout().lock();
            log.iter().try_for_each(|d| writeln!(so, "{d:?}"))?;
        }
        let status = if matches!(end, Ok(End::Exited)) { Some(be.child().wait()?) } else { None };
        // Clears gates and cgroup, ending what is left of the SUT, before the
        // write half: a gated task may serve a mount inside the canary.
        drop(be);
        // Ended without the final hold (no read half), or judged on the write half alone.
        let deadline = match end? {
            End::Exited => false,
            End::Deadline => true,
            // read before passed, so alice's credentials were right: a gate
            // that stops failing her later was opened by the SUT, and the
            // write half shows it (a chmod'd gate). Judged, not invalid.
            End::SelfCheck if !canary.changed().is_empty() => false,
            End::SelfCheck => bail!("invalid: self-check: alice's credentials are not stopped by the canary gate"),
            End::Interrupted => return Ok(Ran::Stopped),
            End::Diverged(d) => return Ok(Ran::Missed(d.to_string())),
        };
        let mut found = j.reached.unwrap_or_default();
        found.extend(canary.changed());
        let failed = log.iter().find_map(|d| match &d.mutation {
            Some(Err(e)) => Some(e.clone()),
            Some(Ok(st)) if !st.success() => Some(st.to_string()),
            _ => None,
        });
        if let (true, Some(e)) = (found.is_empty(), failed) {
            return Ok(Ran::Missed(format!("invalid: mutator failed: {e}")));
        }
        let task = j.task.as_ref().map(|(tid, tgid, name)| (*tid, *tgid, name.as_str()));
        let norm = found.iter().map(|f| schedule::normalize(f, &canary.dir, task)).collect();
        Ok(Ran::Judged(Judged { end: status, found, deadline, norm, canary }))
    }

    /// A run outside a replay: None if stopped; missed is invalid.
    fn valid(r: Ran) -> Result<Option<Judged>> {
        match r {
            Ran::Judged(j) => Ok(Some(j)),
            Ran::Stopped => Ok(None),
            Ran::Missed(why) => bail!(why),
        }
    }

    /// A seed's baseline, which must leak nothing. Its targets are its holds
    /// with a known path, decoded keys and a named thread (not `?tid`), with
    /// `--scope` only those under a scope directory, one per (syscall, path,
    /// occurrence): the engine matches those in any thread. None: stopped.
    pub fn baseline(&self, seed: u64, out: Option<&Path>, log: &mut Vec<Decision>) -> Result<Option<Baseline>> {
        log.clear();
        let t = Instant::now();
        let Some(mut b) = Self::valid(self.judged(seed, None, None, None, out, "baseline", log)?)? else { return Ok(None) };
        if !b.found.is_empty() {
            b.canary.keep(); // the evidence
            bail!("invalid: the scenario leaks with no mutation: {:?}", b.found);
        }
        let scope = &self.cfg.scope;
        let in_scope = |p: &Path| scope.is_empty() || scope.iter().any(|d| p.starts_with(d));
        let mut seen = HashSet::new();
        let targets = log
            .iter()
            .filter(|d| d.id.path.as_deref().is_some_and(in_scope) && !d.keys.all && !d.id.thread.starts_with('?'))
            .filter(|d| seen.insert((d.id.nr, d.id.path.clone(), d.id.n)))
            .map(|d| d.id.clone())
            .collect();
        Ok(Some(Baseline { end: b.end, targets, secs: t.elapsed().as_secs_f64() }))
    }

    /// Window k (from 1) mutates target k alone; with no mutator or no target
    /// the seed is one unmutated run, window 0.
    pub fn windows(&self, targets: &[EventId]) -> Vec<(usize, Option<EventId>)> {
        if self.cfg.mutator.is_none() || targets.is_empty() {
            vec![(0, None)]
        } else {
            (1..).zip(targets.iter().cloned().map(Some)).collect()
        }
    }

    /// The run in `log` as a schedule.
    pub fn schedule(&self, seed: u64, class: Class, deadline: bool, findings: BTreeSet<Finding>, log: &[Decision]) -> Schedule {
        Schedule { seed, cfg: self.cfg.clone(), class, deadline, findings, steps: engine::project(log) }
    }

    /// Discovery against the seed's baseline `end`: its class and schedule; a
    /// Violation's canary is kept (the evidence). None: stopped.
    pub fn discover(&self, seed: u64, target: Option<&EventId>, end: Option<ExitStatus>, out: &Path, log: &mut Vec<Decision>) -> Result<Option<(Class, Judged, Schedule)>> {
        log.clear();
        let mutator = target.and(self.cfg.mutator.as_deref());
        let Some(mut run) = Self::valid(self.judged(seed, mutator, target, None, Some(out), "discovery", log)?)? else { return Ok(None) };
        let class = oracle::outcome(&run.found, run.end, end);
        if class == Class::Violation {
            run.canary.keep();
        }
        let s = self.schedule(seed, class, run.deadline, std::mem::take(&mut run.norm), log);
        Ok(Some((class, run, s)))
    }

    /// Confirm `sched`, then on a Violation minimize it, each line to `w`
    /// after `pre`, the runs' output to `out`.
    pub fn confirm(&self, sched: &Schedule, end: Option<ExitStatus>, out: Option<&Path>, log: &mut Vec<Decision>, pre: &str, w: &mut dyn Write) -> Result<Confirmed> {
        let mutator = self.cfg.mutator.as_deref();
        let fixed = || Fixed { steps: &sched.steps, next: 0, deadline: sched.deadline };
        // Confirm: every recorded mutation, any divergence fails it.
        // Code between holds may not be deterministic (M:N runtimes): one
        // replay that misses is not proof of a spurious finding.
        // ponytail: first match wins; report a rate over all tries if one is needed.
        let mut confirmed = None;
        for t in 1..=CONFIRM_TRIES {
            log.clear();
            let mut r = Replay { fixed: fixed(), only: None, diverged: None };
            let run = match self.judged(sched.seed, mutator, None, Some(&mut r), out, &format!("confirm {t}/{CONFIRM_TRIES}"), log)? {
                Ran::Stopped => return Ok(Confirmed::Stopped),
                Ran::Missed(why) => {
                    writeln!(w, "{pre}not confirmed ({t}/{CONFIRM_TRIES}): {why}")?;
                    continue;
                }
                Ran::Judged(run) => run,
            };
            let class = oracle::outcome(&run.found, run.end, end);
            if class != sched.class || run.norm != sched.findings {
                writeln!(w, "{pre}not confirmed ({t}/{CONFIRM_TRIES}): {class}, normalized {:?}", run.norm)?;
                continue;
            }
            confirmed = Some(run);
            break;
        }
        let Some(mut run) = confirmed else { return Ok(Confirmed::No) };
        writeln!(w, "{pre}confirmed: {}", sched.class)?;
        if sched.class != Class::Violation {
            return Ok(Confirmed::Yes(None));
        }
        run.canary.keep(); // the evidence
        drop(run);

        // Minimize: the first hold whose mutation alone flags a finding of the
        // schedule's. ponytail: one bug, single holds only; a pair search when
        // findings need two mutations.
        for k in (0..sched.steps.len()).filter(|&k| sched.steps[k].mutate) {
            log.clear();
            let mut r = Replay { fixed: fixed(), only: Some(k), diverged: None };
            let run = match self.judged(sched.seed, mutator, None, Some(&mut r), out, &format!("minimize step {k}"), log)? {
                Ran::Stopped => return Ok(Confirmed::Stopped),
                Ran::Missed(why) => {
                    writeln!(w, "{pre}minimize step {k}: not guilty, {why}")?;
                    continue;
                }
                Ran::Judged(run) => run,
            };
            let class = oracle::outcome(&run.found, run.end, end);
            let tail = r.diverged.map(|d| format!(" (then POS: {d})")).unwrap_or_default();
            writeln!(w, "{pre}minimize step {k}: {class} {:?}{tail}", run.norm)?;
            if class == Class::Violation && !run.norm.is_disjoint(&sched.findings) {
                writeln!(w, "{pre}guilty: step {k} {:?}", sched.steps[k].id)?;
                return Ok(Confirmed::Yes(Some(k)));
            }
        }
        writeln!(w, "{pre}guilty: needs more than one hold")?;
        Ok(Confirmed::Yes(None))
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.work) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => eprintln!("left {}: {e}", self.work.display()),
            _ => {}
        }
    }
}

/// `replay FILE`: everything comes from the file. One baseline, a replay with
/// every recorded mutation that must give the same class and normalized
/// findings, then one replay per recorded mutation alone, in order, until one
/// flags a finding of the schedule's: the guilty hold.
pub fn replay(file: &str, verbose: bool) -> Result<i32> {
    let s: Schedule = std::fs::read_to_string(file).context(file.to_string())?.parse().context(file.to_string())?;
    // The layout's, SUT's and mutator's inputs, as in discovery. One thread yet.
    for (k, v) in &s.cfg.env {
        std::env::set_var(k, v);
    }
    check_private(&s.cfg, None)?;
    let r = Runner::new(s.cfg.clone(), verbose, None)?;
    println!("{}", r.alice);
    r.isolate(0)?;
    let mut log = Vec::new();
    let hint = |_: &anyhow::Error| {
        if !verbose && !engine::stopped() {
            eprintln!("(rerun with -v for the decision log)");
        }
    };
    // Stopped by SIGINT/SIGTERM, every Drop run; or the scheduler was lost.
    let stopped = || -> Result<i32> {
        ensure!(!r.lost.load(Relaxed), "the gate scheduler is gone");
        eprintln!("interrupted");
        Ok(130)
    };
    let Some(b) = r.baseline(s.seed, None, &mut log).inspect_err(hint)? else { return stopped() };
    println!("{}", telemetry(&log, b.targets.len(), b.secs));
    println!("discovery: {}", s.class);
    match r.confirm(&s, b.end, None, &mut log, "", &mut std::io::stdout()).inspect_err(hint)? {
        Confirmed::Stopped => stopped(),
        // Not reproduced: an error, never a clean exit.
        Confirmed::No => Err(anyhow::anyhow!("not reproduced in {CONFIRM_TRIES} tries: {}", s.class)).inspect_err(hint),
        Confirmed::Yes(_) => Ok(if s.class == Class::Violation { 3 } else { 0 }),
    }
}
