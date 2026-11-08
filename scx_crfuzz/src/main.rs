//! scx_crfuzz run DIR --attacker UID:GID --seeds N [--first-seed S] [--mutator PROG] [--layout PROG] [--scope DIR]... [--timeout SECS] [-v] -- CMD [ARGS...]
//! scx_crfuzz replay FILE [-v]
//!
//! `run` sweeps seeds S..S+N (default S 0; §3.10), each exhaustive over its
//! windows. A seed runs CMD under POS (discovery): a baseline under the seed,
//! no mutator, then once per window, each run with its own canary, judged
//! against the attacker alice (UID:GID, no groups, no caps: §1). The windows
//! are the baseline's holds with a known path, not keys.all and not a `?tid`,
//! one per (syscall, path, occurrence): with `--mutator`, PROG (a binary or a
//! script with a #!) runs at window k's hold alone, once, as alice in the held
//! task's view: its namespaces, root and cwd, the path as issued in argv[1]
//! (§10.1). `--scope DIR` (repeatable) keeps only windows whose absolute path
//! is under one of the DIRs: where alice can act. A window that never reaches
//! its target is unmutated. `--layout PROG` (absolute, recorded in the
//! schedule) runs as root before every run to restore the starting
//! filesystem, so no run sees what an earlier one's SUT or mutator left
//! behind; a failure makes the run invalid. `--timeout SECS` (1 to 30,
//! default 30, recorded) ends a run still going.
//!
//! Window k's schedule (§3.8) goes to `DIR/runs/<seed>/<k>.sched` and a row to
//! `DIR/runs.tsv`. A Violation repeating a finding (`Dedup::repeated_by`) is
//! only counted; a new one is confirmed and minimized, as `replay` does, and
//! if confirmed is finding n: `DIR/findings/<n>/{schedule,seeds}`, `seeds` one
//! `seed:k` per line. An invalid run or baseline is recorded and the sweep
//! goes on. Each seed ends with its verdict: `safe` (every window valid,
//! mutated and no Violation), `unsafe` (a window's Violation), `incomplete`
//! (else), or `no windows` (no mutator or no target: the seed is one unmutated
//! run, window 0); the sweep with a summary.
//!
//! `replay FILE`: everything comes from the file. One baseline, a replay with
//! every recorded mutation that must give the same class and normalized
//! findings, then one replay per recorded mutation alone, in order, until one
//! flags a finding of the schedule's: the guilty hold.
//!
//! `-v` prints every run's decisions. Exit status: 0 done, 3 done with a
//! confirmed finding (`replay`: a confirmed Violation), 2 a usage error, 1
//! any other error (`replay`: the schedule not reproduced). Needs root and a running scx_crfuzz_gated.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
const USAGE: &str = "usage: scx_crfuzz run DIR --attacker UID:GID --seeds N [--first-seed S] [--mutator PROG]
                      [--layout PROG] [--scope DIR]... [--timeout SECS] [-v] -- CMD [ARGS...]
       scx_crfuzz replay FILE [-v]
       scx_crfuzz --help | --version";

/// A bad or missing argument: exit 2, after the usage.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Usage(String);
#[cfg(target_os = "linux")]
impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n{USAGE}", self.0)
    }
}
#[cfg(target_os = "linux")]
impl std::error::Error for Usage {}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(match crfuzz() {
        Ok(code) => code,
        Err(e) if e.is::<Usage>() => {
            eprintln!("{e}");
            2
        }
        Err(e) => {
            eprintln!("Error: {e:?}");
            1
        }
    });
}

/// The exit status: 0, or 3 for a confirmed finding.
#[cfg(target_os = "linux")]
fn crfuzz() -> anyhow::Result<i32> {
    use anyhow::{bail, ensure, Context, Result};
    use scx_crfuzz::backend::{self, GateBackend, SelfCheckFailed};
    use scx_crfuzz::engine::{self, Deadline, Decision, Judge, Replay};
    use scx_crfuzz::oracle::{self, Alice, Canary, Finding, Outcome};
    use scx_crfuzz::pos::{EventId, Pos};
    use scx_crfuzz::schedule::{self, Dedup, Divergence, Fixed, Schedule};
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::io::{IsTerminal, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};
    use std::time::{Duration, Instant};

    /// Replays a discovery gets to reproduce before it counts as unconfirmed.
    const CONFIRM_TRIES: u32 = 3;
    // ponytail: a fixed watch set (the path syscalls D3 decodes, minus execve,
    // which needs CMD as a path) and fixed timing; flags when a scenario needs them.
    const WATCHED: &[i64] = &[
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlinkat,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_chdir,
        // The final hold (§5): its keys are `all`, so no mutator fires there.
        libc::SYS_exit_group,
    ];

    /// A run's mutator failed: invalid, but one minimize step or confirm try only.
    #[derive(Debug)]
    struct MutatorFailed(String);
    impl std::fmt::Display for MutatorFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid: mutator failed: {}", self.0)
        }
    }
    impl std::error::Error for MutatorFailed {}

    let usage = |why: String| anyhow::Error::new(Usage(why));
    type Args = std::iter::Skip<std::env::Args>;
    let val = |args: &mut Args, flag: &str| args.next().ok_or_else(|| usage(format!("{flag} needs a value")));
    let num = |args: &mut Args, flag: &str| -> Result<u64> { val(args, flag)?.parse().map_err(|_| usage(format!("{flag}: not a number"))) };
    let mut args = std::env::args().skip(1);
    let (mut mutator, mut layout, mut attacker, mut scope) = (None, None, None, Vec::<PathBuf>::new());
    let (mut verbose, mut timeout) = (false, 30);
    // campaign: DIR and the seeds; loaded: the schedule to replay.
    let (campaign, loaded, cmd) = match args.next().as_deref() {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return Ok(0);
        }
        Some("-V" | "--version") => {
            println!("scx_crfuzz {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        // Everything comes from the file.
        Some("replay") => {
            let mut file = None;
            for a in args {
                match a.as_str() {
                    "-v" => verbose = true,
                    _ if file.is_none() && !a.starts_with('-') => file = Some(a),
                    _ => return Err(usage(format!("unknown argument {a}"))),
                }
            }
            let f = file.ok_or_else(|| usage("replay needs a FILE".into()))?;
            let s = std::fs::read_to_string(&f).context(f.clone())?.parse::<Schedule>().context(f)?;
            (mutator, layout, timeout, attacker) = (s.mutator.clone(), s.layout.clone(), s.timeout, Some(Alice::parse(&s.attacker)?));
            let cmd = s.cmd.clone();
            (None, Some(s), cmd)
        }
        Some("run") => {
            let dir = args.next().filter(|d| !d.starts_with('-')).ok_or_else(|| usage("run needs a DIR".into()))?;
            let (mut first, mut seeds) = (0, None);
            let cmd: Vec<String> = loop {
                match args.next().as_deref() {
                    Some("--attacker") => attacker = Some(Alice::parse(&val(&mut args, "--attacker")?).map_err(|e| usage(format!("{e:#}")))?),
                    Some("--seeds") => seeds = Some(num(&mut args, "--seeds")?),
                    Some("--first-seed") => first = num(&mut args, "--first-seed")?,
                    // Absolute: the mutator is exec'd after a chdir into the task's cwd.
                    Some("--mutator") => mutator = Some(std::fs::canonicalize(val(&mut args, "--mutator")?).context("--mutator")?),
                    Some("--layout") => layout = Some(std::fs::canonicalize(val(&mut args, "--layout")?).context("--layout")?),
                    Some("--scope") => scope.push(std::fs::canonicalize(val(&mut args, "--scope")?).context("--scope")?),
                    Some("--timeout") => timeout = Some(num(&mut args, "--timeout")?).filter(|t| (1..=30).contains(t)).ok_or_else(|| usage("--timeout: 1 to 30 seconds".into()))?,
                    Some("-v") => verbose = true,
                    Some("--") => break args.collect(),
                    Some(a) => return Err(usage(format!("unknown argument {a}"))),
                    None => return Err(usage("run needs -- CMD".into())),
                }
            };
            let n = seeds.ok_or_else(|| usage("--seeds is required".into()))?;
            first.checked_add(n).ok_or_else(|| usage("--first-seed + --seeds overflows".into()))?;
            (Some((PathBuf::from(dir), first, n)), None, cmd)
        }
        Some(a) => return Err(usage(format!("unknown command {a}"))),
        None => return Err(usage("a command is required".into())),
    };
    // §1: an input, never inferred; refused before anything starts.
    let alice = attacker.ok_or_else(|| usage("--attacker is required".into()))?;
    let (prog, rest) = cmd.split_first().ok_or_else(|| usage("run needs a CMD after --".into()))?;
    // No resume: an old campaign's runs/ and findings/ would read as this one's.
    if let Some((d, ..)) = &campaign {
        ensure!(std::fs::read_dir(d).map_or(true, |mut e| e.next().is_none()), "run: {} is not empty", d.display());
    }

    /// One judged run (§5, §6).
    struct Judged {
        /// None: the deadline, or a self-check failed on a changed canary.
        end: Option<ExitStatus>,
        /// Read and write halves together.
        found: Vec<Finding>,
        /// Ended by the deadline (§3.8: replay lets it end there too).
        deadline: bool,
        /// `found`, normalized: what replays compare (§3.8).
        norm: BTreeSet<Finding>,
        /// Removed on drop unless kept (§10.2).
        canary: Canary,
    }

    // Canary numbers, one per run of this crfuzz: a kept canary is never reused.
    let runs = Cell::new(0u32);
    // One run with its own canary; its decisions go to `log` whatever the
    // ending, and with -v to stdout.
    let judged = |seed: u64, mutator: Option<&Path>, target: Option<&EventId>, replay: Option<&mut Replay>, log: &mut Vec<Decision>| -> Result<Judged> {
        if let Some(l) = &layout {
            let st = Command::new(l).status().with_context(|| l.display().to_string())?;
            ensure!(st.success(), "invalid: layout {} failed: {st}", l.display());
        }
        let canary = Canary::create(runs.replace(runs.get() + 1))?;
        backend::read_before(&canary, &alice)?;
        let mut sut = Command::new(prog);
        sut.args(rest);
        let mut be = GateBackend::spawn(sut, WATCHED)?;
        let mut j = Judge { canary: &canary, alice: alice.clone(), reached: None, task: None };
        let until = Instant::now().checked_add(Duration::from_secs(timeout)).context("--timeout too large")?;
        let r = engine::run(&mut be, &mut Pos::new(seed), mutator, target, replay, Some(&mut j), until, log);
        if verbose {
            log.iter().for_each(|d| println!("{d:?}"));
        }
        let end = if r.is_ok() { Some(be.child().wait()?) } else { None };
        // Clears gates and cgroup, ending what is left of the SUT, before the
        // write half: a gated task may serve a mount inside the canary.
        drop(be);
        let deadline = matches!(&r, Err(e) if e.is::<Deadline>());
        // Ended without the final hold (no read half), or judged on the write half alone.
        match r {
            Ok(()) => {}
            Err(e) if e.is::<Deadline>() => {}
            // read before passed, so alice's credentials were right: a gate
            // that stops failing her later was opened by the SUT, and the
            // write half shows it (a chmod'd gate). Judged, not invalid.
            Err(e) if e.is::<SelfCheckFailed>() && !canary.changed().is_empty() => {}
            Err(e) => return Err(e), // invalid: self-check, probe, crfuzz itself
        }
        let mut found = j.reached.unwrap_or_default();
        found.extend(canary.changed());
        // A mutator that failed (error, timeout, nonzero exit) never attacked,
        // so an unflagged run would pass as Clean: invalid, unless it flagged.
        let failed = log.iter().find_map(|d| match &d.mutation {
            Some(Err(e)) => Some(e.clone()),
            Some(Ok(st)) if !st.success() => Some(st.to_string()),
            _ => None,
        });
        if let (true, Some(e)) = (found.is_empty(), failed) {
            return Err(anyhow::Error::new(MutatorFailed(e)));
        }
        let task = j.task.as_ref().map(|(tid, tgid, name)| (*tid, *tgid, name.as_str()));
        let norm = found.iter().map(|f| schedule::normalize(f, &canary.dir, task)).collect();
        Ok(Judged { end, found, deadline, norm, canary })
    };

    // A seed's baseline, which must leak nothing: its exit (for the oracle),
    // its windows' targets and its time. The targets are the holds a mutator
    // could fire at, named stably (not `?tid`), with --scope only those under
    // a scope directory, one per (syscall, path, occurrence): the engine
    // matches those in any thread.
    let in_scope = |p: &Path| scope.is_empty() || scope.iter().any(|d| p.starts_with(d));
    let baseline = |seed: u64, log: &mut Vec<Decision>| -> Result<(Option<ExitStatus>, Vec<EventId>, f64)> {
        log.clear();
        let t = Instant::now();
        let mut b = judged(seed, None, None, None, log)?;
        if !b.found.is_empty() {
            b.canary.keep(); // the evidence
            bail!("invalid: the scenario leaks with no mutation: {:?}", b.found);
        }
        let mut seen = HashSet::new();
        let targets = log
            .iter()
            .filter(|d| d.id.path.as_deref().is_some_and(in_scope) && !d.keys.all && !d.id.thread.starts_with('?'))
            .filter(|d| seen.insert((d.id.nr, d.id.path.clone(), d.id.n)))
            .map(|d| d.id.clone())
            .collect();
        Ok((b.end, targets, t.elapsed().as_secs_f64()))
    };
    // Window k (from 1) mutates target k alone; with no mutator or no target
    // the seed is one unmutated run, window 0.
    let windows = |targets: &[EventId]| -> Vec<(usize, Option<EventId>)> {
        if mutator.is_none() || targets.is_empty() {
            vec![(0, None)]
        } else {
            (1..).zip(targets.iter().cloned().map(Some)).collect()
        }
    };
    const VERDICTS: [&str; 4] = ["safe", "unsafe", "incomplete", "no windows"];
    // bad: a window's Violation; gap: a window invalid or unmutated.
    let verdict = |ws: &[(usize, Option<EventId>)], bad: bool, gap: bool| if bad { 1 } else if ws[0].0 == 0 { 3 } else if gap { 2 } else { 0 };
    // Telemetry from a baseline: the size of one run and how much there is
    // for the mutator to hit. It sizes the campaign's estimate.
    let telemetry = |log: &[Decision], targets: usize, secs: f64| {
        let threads: BTreeSet<&str> = log.iter().map(|d| d.id.thread.as_str()).collect();
        format!(
            "telemetry: {} decisions ({} partial), {} threads, {targets} mutation targets, {secs:.1}s",
            log.len(),
            log.iter().filter(|d| d.partial).count(),
            threads.len(),
        )
    };

    // The run in `log` as a schedule (§3.8); `mutated`: it had a target.
    let attacker = format!("{}:{}", alice.uid, alice.gid);
    let schedule = |seed: u64, mutated: bool, class: &str, deadline: bool, findings: BTreeSet<Finding>, log: &[Decision]| Schedule {
        seed,
        attacker: attacker.clone(),
        mutator: mutator.clone().filter(|_| mutated),
        layout: layout.clone(),
        timeout,
        cmd: cmd.clone(),
        class: class.into(),
        deadline,
        findings,
        steps: engine::project(log),
    };
    // Discovery against the seed's baseline `end`: its class and schedule; a
    // Violation's canary is kept (the evidence).
    let discover = |seed: u64, target: Option<&EventId>, end: Option<ExitStatus>, log: &mut Vec<Decision>| -> Result<(Outcome, Judged, Schedule)> {
        log.clear();
        let mut run = judged(seed, target.and(mutator.as_deref()), target, None, log)?;
        let class = oracle::outcome(std::mem::take(&mut run.found), run.end, end);
        if matches!(class, Outcome::Violation(_)) {
            run.canary.keep();
        }
        let s = schedule(seed, target.is_some(), class.name(), run.deadline, std::mem::take(&mut run.norm), log);
        Ok((class, run, s))
    };

    // Confirm, then on a Violation minimize, each line after `pre`. None: not
    // confirmed; Some(Some(k)): guilty step k; Some(None): no single guilty
    // hold, or a confirmed non-Violation.
    let confirm = |sched: &Schedule, end: Option<ExitStatus>, log: &mut Vec<Decision>, pre: &str| -> Result<Option<Option<usize>>> {
        // Confirm: every recorded mutation, any divergence fails it.
        let fixed = || Fixed { steps: &sched.steps, next: 0, deadline: sched.deadline };
        // Code between holds may not be deterministic (M:N runtimes): one
        // replay that misses is not proof of a spurious finding.
        // ponytail: first match wins; report a rate over all tries if one is needed.
        let mut confirmed = None;
        for t in 1..=CONFIRM_TRIES {
            log.clear();
            let mut r = Replay { fixed: fixed(), only: None, diverged: None };
            let mut run = match judged(sched.seed, sched.mutator.as_deref(), None, Some(&mut r), log) {
                Err(e) if e.is::<Divergence>() || e.is::<MutatorFailed>() => {
                    println!("{pre}not confirmed ({t}/{CONFIRM_TRIES}): {e:#}");
                    continue;
                }
                r => r?,
            };
            let class = oracle::outcome(std::mem::take(&mut run.found), run.end, end);
            if class.name() != sched.class || run.norm != sched.findings {
                println!("{pre}not confirmed ({t}/{CONFIRM_TRIES}): {class:?}, normalized {:?}", run.norm);
                continue;
            }
            confirmed = Some((class, run));
            break;
        }
        let Some((class, mut run)) = confirmed else { return Ok(None) };
        println!("{pre}confirmed: {}", sched.class);
        if !matches!(class, Outcome::Violation(_)) {
            return Ok(Some(None));
        }
        run.canary.keep(); // the evidence
        drop(run);

        // Minimize: the first hold whose mutation alone flags a finding of the
        // schedule's. ponytail: one bug, single holds only; a pair search when
        // findings need two mutations.
        for k in (0..sched.steps.len()).filter(|&k| sched.steps[k].mutate) {
            log.clear();
            let mut r = Replay { fixed: fixed(), only: Some(k), diverged: None };
            let mut run = match judged(sched.seed, sched.mutator.as_deref(), None, Some(&mut r), log) {
                Err(e) if e.is::<Divergence>() || e.is::<MutatorFailed>() => {
                    println!("{pre}minimize step {k}: not guilty, {e:#}");
                    continue;
                }
                res => res?,
            };
            let class = oracle::outcome(std::mem::take(&mut run.found), run.end, end);
            let tail = r.diverged.map(|d| format!(" (then POS: {d})")).unwrap_or_default();
            println!("{pre}minimize step {k}: {class:?}{tail}");
            if matches!(class, Outcome::Violation(_)) && !run.norm.is_disjoint(&sched.findings) {
                println!("{pre}guilty: step {k} {:?}", sched.steps[k].id);
                return Ok(Some(Some(k)));
            }
        }
        println!("{pre}guilty: needs more than one hold");
        Ok(Some(None))
    };

    backend::sweep();
    println!("{alice}");
    let mut log = Vec::new();
    let Some((dir, first, n)) = campaign else {
        let s = loaded.expect("replay");
        let hint = |_: &anyhow::Error| {
            if !verbose {
                eprintln!("(rerun with -v for the decision log)");
            }
        };
        let (end, targets, secs) = baseline(s.seed, &mut log).inspect_err(hint)?;
        println!("{}", telemetry(&log, targets.len(), secs));
        println!("discovery: {}", s.class);
        // Not reproduced in CONFIRM_TRIES: an error, never a clean exit.
        confirm(&s, end, &mut log, "").and_then(|c| c.with_context(|| format!("not reproduced in {CONFIRM_TRIES} tries: {}", s.class))).inspect_err(hint)?;
        return Ok(if s.class == "Violation" { 3 } else { 0 });
    };

    // §3.10: the sweep. Each row is written as its run ends: an interrupted
    // campaign keeps them.
    std::fs::create_dir_all(dir.join("runs")).with_context(|| dir.display().to_string())?;
    let mut tsv = std::fs::File::create(dir.join("runs.tsv"))?;
    writeln!(tsv, "seed\twindow\tclass\tstatus\tfinding\tdecisions\tpartial\tsecs\tnote")?;
    let hold = |t: &str, nr: i64, p: &Option<PathBuf>| format!("({t} {nr} {})", p.as_deref().map_or("-".into(), |p| p.display().to_string()));
    let mut found: Vec<(Dedup, Vec<String>)> = Vec::new();
    let (mut total, mut invalid, mut decisions, mut partial, mut time) = (0, 0, 0, 0, Duration::ZERO);
    let mut orders = HashSet::new();
    let (mut unmutated, mut classes, mut verdicts) = (0, BTreeMap::<&str, u64>::new(), [0u64; 4]);
    let hms = |s: f64| {
        let s = s.round() as u64;
        if s >= 3600 { format!("{}h{:02}m", s / 3600, s / 60 % 60) } else if s >= 60 { format!("{}m{:02}s", s / 60, s % 60) } else { format!("{s}s") }
    };
    // On a terminal and without -v, a progress line over seeds on stderr below
    // the per-run lines; cleared before anything prints to stdout.
    let tty = !verbose && std::io::stderr().is_terminal();
    let started = Instant::now();
    let clear = || if tty { eprint!("\r\x1b[K") };
    let bar = |done: u64, classes: &BTreeMap<&str, u64>| {
        if !tty {
            return;
        }
        let w = 24;
        let fill = (done * w / n.max(1)) as usize;
        // From the seeds so far (confirms included); the plan line has the first guess.
        let eta = if done == 0 { "?".into() } else { hms(started.elapsed().as_secs_f64() / done as f64 * (n - done) as f64) };
        let counts: Vec<String> = classes.iter().map(|(c, k)| format!("{c} {k}")).collect();
        eprint!("\r[{}{}] {done}/{n} seeds  ETA {eta}  {}\x1b[K", "#".repeat(fill), ".".repeat(w as usize - fill), counts.join("  "));
    };
    for idx in 0..n {
        let seed = first + idx;
        let t = Instant::now();
        let b = baseline(seed, &mut log);
        clear();
        let (end, targets, secs) = match b {
            Ok(b) => b,
            Err(e) => {
                invalid += 1;
                verdicts[2] += 1;
                *classes.entry("invalid").or_default() += 1;
                let note = format!("baseline: {e:#}").replace(['\t', '\n'], " ");
                let part = log.iter().filter(|d| d.partial).count();
                writeln!(tsv, "{seed}\t-\tinvalid\t-\t-\t{}\t{part}\t{:.3}\t{note}", log.len(), t.elapsed().as_secs_f64())?;
                println!("[{}/{n}] seed {seed}: incomplete, {note}", idx + 1);
                bar(idx + 1, &classes);
                continue;
            }
        };
        let ws = windows(&targets);
        // The plan, sized by the first baseline: a discovery costs about one
        // baseline, plus a confirm and minimization per new Violation.
        if idx == 0 {
            let per = ws.len() as u64 + 1;
            println!("plan: {n} seeds, {} windows in seed {seed}, ~{} runs, est. {} (+ confirms)", ws.len(), n * per, hms((n * per) as f64 * secs));
        }
        println!("[{}/{n}] seed {seed}: {}", idx + 1, telemetry(&log, targets.len(), secs));
        bar(idx, &classes);
        std::fs::create_dir_all(dir.join(format!("runs/{seed}")))?;
        let (mut bad, mut gap) = (false, false);
        for (k, target) in &ws {
            let t = Instant::now();
            let r = discover(seed, target.as_ref(), end, &mut log);
            let secs = t.elapsed();
            // Its target never came up: the run says nothing about the mutator.
            let unmut = r.is_ok() && target.is_some() && !log.iter().any(|d| d.mutation.is_some());
            unmutated += unmut as u64;
            gap |= unmut || r.is_err();
            (total, time) = (total + 1, time + secs);
            let (len, part) = (log.len(), log.iter().filter(|d| d.partial).count());
            (decisions, partial) = (decisions + len, partial + part);
            let file = dir.join(format!("runs/{seed}/{k}.sched"));
            // status: new, repeat, unconfirmed or invalid on a Violation, else "-".
            let (class, status, finding, note) = match r {
                Err(e) => {
                    invalid += 1;
                    std::fs::write(&file, schedule(seed, target.is_some(), "invalid", false, BTreeSet::new(), &log).to_string())?;
                    ("invalid", "-", None, format!("{e:#}"))
                }
                Ok((class, run, s)) => {
                    drop(run);
                    std::fs::write(&file, s.to_string())?;
                    orders.insert(schedule::canonical(&log.iter().map(|d| (&d.id, &d.keys)).collect::<Vec<_>>()));
                    if !matches!(class, Outcome::Violation(_)) {
                        (class.name(), "-", None, String::new())
                    } else if let Some(i) = found.iter().position(|(d, _)| d.repeated_by(&s.findings, &s.steps)) {
                        found[i].1.push(format!("{seed}:{k}"));
                        ("Violation", "repeat", Some(i + 1), String::new())
                    } else {
                        clear();
                        println!("[{}/{n}] seed {seed} window {k}: Violation, confirming", idx + 1);
                        match confirm(&s, end, &mut log, "  ") {
                            Err(e) => {
                                invalid += 1;
                                ("Violation", "invalid", None, format!("{e:#}"))
                            }
                            Ok(None) => ("Violation", "unconfirmed", None, String::new()),
                            Ok(Some(g)) => {
                                let id = g.map(|g| &s.steps[g].id);
                                let note = match (g, id) {
                                    (Some(g), Some(id)) => format!("guilty step {g} {}", hold(&id.thread, id.nr, &id.path)),
                                    _ => "needs more than one hold".into(),
                                };
                                let guilty = id.map(|id| (id.thread.clone(), id.nr, id.path.clone()));
                                found.push((Dedup { guilty, findings: s.findings.clone() }, vec![format!("{seed}:{k}")]));
                                let f = dir.join(format!("findings/{}", found.len()));
                                std::fs::create_dir_all(&f)?;
                                std::fs::write(f.join("schedule"), s.to_string())?;
                                ("Violation", "new", Some(found.len()), note)
                            }
                        }
                    }
                }
            };
            bad |= class == "Violation";
            if let Some(i) = finding {
                let list: String = found[i - 1].1.iter().map(|s| format!("{s}\n")).collect();
                std::fs::write(dir.join(format!("findings/{i}/seeds")), list)?;
            }
            *classes.entry(class).or_default() += 1;
            let note = match (unmut, note.is_empty()) {
                (false, _) => note,
                (true, true) => "unmutated".into(),
                (true, false) => format!("unmutated; {note}"),
            };
            let note = note.replace(['\t', '\n'], " ");
            let f = finding.map_or("-".into(), |i| i.to_string());
            writeln!(tsv, "{seed}\t{k}\t{class}\t{status}\t{f}\t{len}\t{part}\t{:.3}\t{note}", secs.as_secs_f64())?;
            let what = match status {
                "new" => format!("Violation → confirmed, {note} → finding #{f} (new)"),
                "repeat" => format!("Violation → repeat of finding #{f}"),
                "unconfirmed" => "Violation → not confirmed".into(),
                "invalid" => format!("Violation → invalid: {note}"),
                _ if class == "invalid" => format!("invalid: {note}"),
                _ => class.into(),
            };
            clear();
            println!("[{}/{n}] seed {seed} window {k}/{}: {what}{}  {:.1}s", idx + 1, ws.len(), if unmut { " (unmutated)" } else { "" }, secs.as_secs_f64());
            bar(idx, &classes);
        }
        let v = verdict(&ws, bad, gap);
        verdicts[v] += 1;
        clear();
        println!("[{}/{n}] seed {seed}: {}", idx + 1, VERDICTS[v]);
        bar(idx + 1, &classes);
    }
    clear();

    println!("campaign: {n} seeds, {total} runs, {invalid} invalid, discovery {:.1}s", time.as_secs_f64());
    let v: Vec<String> = VERDICTS.iter().zip(verdicts).map(|(name, c)| format!("{c} {name}")).collect();
    println!("seeds: {}", v.join(", "));
    println!("distinct partial orders: {}", orders.len());
    println!("partial decisions: {partial}/{decisions} ({:.0}%)", 100.0 * partial as f64 / decisions.max(1) as f64);
    if unmutated > 0 {
        println!("unmutated: {unmutated}/{total} runs never reached their target");
    }
    println!("findings: {}", found.len());
    for (i, (d, runs)) in found.iter().enumerate() {
        let guilty = d.guilty.as_ref().map_or("needs more than one hold".into(), |(t, nr, p)| hold(t, *nr, p));
        println!("finding #{}: {} runs, guilty {guilty}, {:?}, {}", i + 1, runs.len(), d.findings, dir.join(format!("findings/{}", i + 1)).display());
    }
    Ok(if found.is_empty() { 0 } else { 3 })
}
