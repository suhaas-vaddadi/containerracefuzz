//! scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] [--layout PROG] [--log FILE] -- CMD [ARGS...]
//! scx_crfuzz --replay FILE
//! scx_crfuzz --campaign DIR --seeds N --attacker UID:GID [--mutator PROG] [--layout PROG] -- CMD [ARGS...]
//!
//! A seed is exhaustive over its windows. Run CMD under POS (discovery) with
//! a baseline under the seed, no mutator, then once per window, each run with
//! its own canary, judged against the attacker alice (UID:GID, no groups, no
//! caps: §1). The windows are the baseline's holds with a known path, not
//! keys.all and not a `?tid`, one per (syscall, path, occurrence): with
//! `--mutator`, PROG (a binary or a script with a #!) runs at window k's hold
//! alone, once, as alice in the held task's view: its namespaces, root and
//! cwd, the path as issued in argv[1] (§10.1). Prints alice, then per window `window k/n target:`, its
//! decision log and outcome class (§6); a window that never reaches its
//! target is unmutated. Ends with the seed's verdict: `safe` (every window
//! valid, mutated and no Violation), `unsafe` (a window's Violation),
//! `incomplete` (else), or `no windows` (no mutator or no target: the seed is
//! one unmutated run, window 0). Exits 0 whatever the verdict; nonzero for an
//! invalid baseline, after printing its decisions. Needs root and a running
//! scx_crfuzz_gated.
//!
//! `--log FILE` writes each Violating window k as a schedule (§3.8) to
//! `FILE.k`, then confirms and minimizes it, as `--replay FILE` does: one
//! baseline, a replay with every recorded mutation that must give the same
//! class and normalized findings, then one replay per recorded mutation
//! alone, in order, until one flags a finding of the schedule's: the guilty
//! hold. `--layout PROG` (absolute, recorded in the schedule) runs as root
//! before every run to restore the starting filesystem, so no run sees what
//! an earlier one's SUT or mutator left behind; a failure makes the run invalid.
//!
//! `--campaign DIR` sweeps seeds 0..N, each its baseline and windows (§3.10):
//! window k's schedule goes to `DIR/runs/<seed>/<k>.sched` and a row to
//! `DIR/runs.tsv`. A Violation repeating a finding (`Dedup::repeated_by`) is
//! only counted; a new one is confirmed and minimized as `--log` does, and if
//! confirmed is finding n: `DIR/findings/<n>/{schedule,seeds}`, `seeds` one
//! `seed:k` per line. An invalid run or baseline is recorded and the sweep
//! goes on. Ends with a summary, the seeds' verdicts included.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
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
    const USAGE: &str = "usage: scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] [--layout PROG] [--log FILE] -- CMD [ARGS...]\n       scx_crfuzz --replay FILE\n       scx_crfuzz --campaign DIR --seeds N --attacker UID:GID [--mutator PROG] [--layout PROG] -- CMD [ARGS...]";
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
    /// Caps the telemetry's O(n²) racing-pair count.
    const RACING_MAX: usize = 4096;

    /// A run's mutator failed: invalid, but one minimize step or confirm try only.
    #[derive(Debug)]
    struct MutatorFailed(String);
    impl std::fmt::Display for MutatorFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid: mutator failed: {}", self.0)
        }
    }
    impl std::error::Error for MutatorFailed {}

    let argv: Vec<String> = std::env::args().skip(1).collect();
    // --replay: everything comes from the file.
    let loaded = match &argv[..] {
        [r, f] if r == "--replay" => Some(std::fs::read_to_string(f).context(f.clone())?.parse::<Schedule>().context(f.clone())?),
        _ => None,
    };
    let (mut seed, mut mutator, mut layout, mut attacker, mut log_file) = (0u64, None, None, None, None);
    let (mut campaign, mut seeds) = (None, None);
    let cmd: Vec<String> = match &loaded {
        Some(s) => {
            (seed, mutator, layout, attacker) = (s.seed, s.mutator.clone(), s.layout.clone(), Some(Alice::parse(&s.attacker)?));
            s.cmd.clone()
        }
        None => {
            let mut args = argv.into_iter();
            loop {
                match args.next().as_deref() {
                    Some("--seed") => seed = args.next().context(USAGE)?.parse().context("--seed")?,
                    // Absolute: the mutator is exec'd after a chdir into the task's cwd.
                    Some("--mutator") => mutator = Some(std::fs::canonicalize(args.next().context(USAGE)?).context("--mutator")?),
                    Some("--attacker") => attacker = Some(Alice::parse(&args.next().context(USAGE)?)?),
                    Some("--layout") => layout = Some(std::fs::canonicalize(args.next().context(USAGE)?).context("--layout")?),
                    Some("--log") => log_file = Some(PathBuf::from(args.next().context(USAGE)?)),
                    Some("--campaign") => campaign = Some(PathBuf::from(args.next().context(USAGE)?)),
                    Some("--seeds") => seeds = Some(args.next().context(USAGE)?.parse::<u64>().context("--seeds")?),
                    Some("--") => break args.collect(),
                    _ => bail!(USAGE),
                }
            }
        }
    };
    // §1: an input, never inferred; refused before anything starts.
    let alice = attacker.with_context(|| format!("--attacker is required\n{USAGE}"))?;
    ensure!(campaign.is_some() == seeds.is_some() && (campaign.is_none() || log_file.is_none()), USAGE);
    // No resume: an old campaign's runs/ and findings/ would read as this one's.
    if let Some(d) = &campaign {
        ensure!(std::fs::read_dir(d).map_or(true, |mut e| e.next().is_none()), "--campaign: {} is not empty", d.display());
    }
    let (prog, rest) = cmd.split_first().context(USAGE)?;
    let ms = Duration::from_millis;

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
        /// Some: why only the write half was judged.
        unjudged: Option<&'static str>,
        /// Removed on drop unless kept (§10.2).
        canary: Canary,
    }

    // Canary numbers, one per run of this crfuzz: a kept canary is never reused.
    let runs = Cell::new(0u32);
    // One run with its own canary; its decisions go to `log` whatever the ending.
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
        let r = engine::run(&mut be, &mut Pos::new(seed), mutator, target, replay, Some(&mut j), ms(1), ms(200), Instant::now() + Duration::from_secs(60), log);
        let end = if r.is_ok() { Some(be.child().wait()?) } else { None };
        // Clears gates and cgroup, ending what is left of the SUT, before the
        // write half: a gated task may serve a mount inside the canary.
        drop(be);
        let deadline = matches!(&r, Err(e) if e.is::<Deadline>());
        let why = match r {
            Ok(()) => "no final hold",
            Err(e) if e.is::<Deadline>() => "no final hold",
            // read before passed, so alice's credentials were right: a gate
            // that stops failing her later was opened by the SUT, and the
            // write half shows it (a chmod'd gate). Judged, not invalid.
            Err(e) if e.is::<SelfCheckFailed>() && !canary.changed().is_empty() => "the SUT opened the gate",
            Err(e) => return Err(e), // invalid: self-check, probe, crfuzz itself
        };
        let unjudged = j.reached.is_none().then_some(why);
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
        Ok(Judged { end, found, deadline, norm, unjudged, canary })
    };
    let name = |o: &Outcome| match o {
        Outcome::Violation(_) => "Violation",
        Outcome::RuntimeRefused => "RuntimeRefused",
        Outcome::RuntimeError => "RuntimeError",
        Outcome::Clean => "Clean",
    };
    let print = |log: &[Decision]| log.iter().for_each(|d| println!("{d:?}"));

    // A seed's baseline, which must leak nothing: its exit (for the oracle),
    // its windows' targets and its time. The targets are the holds a mutator
    // could fire at, named stably (not `?tid`), one per (syscall, path, occurrence): the engine
    // matches those in any thread.
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
            .filter(|d| d.id.path.is_some() && !d.keys.all && !d.id.thread.starts_with('?'))
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
    // Telemetry from a baseline: the size of one run, and how much there is
    // for seeds to reorder (pairs of holds in different threads whose keys
    // conflict) and for the mutator to hit. It sizes the campaign's estimate.
    let telemetry = |log: &[Decision], targets: usize, secs: f64| {
        let threads: BTreeSet<&str> = log.iter().map(|d| d.id.thread.as_str()).collect();
        // ponytail: O(n²) pair scan, skipped past RACING_MAX; index holds by key if it is needed there.
        let racing = if log.len() > RACING_MAX {
            "-".to_string()
        } else {
            (0..log.len())
                .flat_map(|i| (i + 1..log.len()).map(move |j| (i, j)))
                .filter(|&(i, j)| {
                    let (a, b) = (&log[i], &log[j]);
                    a.id.thread != b.id.thread && !a.keys.all && !b.keys.all && a.keys.conflicts(&b.keys)
                })
                .count()
                .to_string()
        };
        format!(
            "telemetry: {} decisions ({} partial), {} threads, {racing} racing pairs, {targets} mutation targets, {secs:.1}s",
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
        let s = schedule(seed, target.is_some(), name(&class), run.deadline, std::mem::take(&mut run.norm), log);
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
            if name(&class) != sched.class || run.norm != sched.findings {
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

    println!("{alice}");
    let mut log = Vec::new();
    let Some(dir) = campaign else {
        let (end, targets, secs) = baseline(seed, &mut log).inspect_err(|_| {
            println!("baseline:");
            print(&log);
        })?;
        println!("{}", telemetry(&log, targets.len(), secs));
        if let Some(s) = loaded {
            println!("discovery: {}", s.class);
            confirm(&s, end, &mut log, "").inspect_err(|_| print(&log))?;
            return Ok(());
        }
        let ws = windows(&targets);
        let (mut bad, mut gap) = (false, false);
        for (k, t) in &ws {
            if let Some(t) = t {
                println!("window {k}/{} target: {t:?}", ws.len());
            }
            let r = discover(seed, t.as_ref(), end, &mut log);
            print(&log);
            let (class, run, s) = match r {
                Ok(r) => r,
                Err(e) => {
                    println!("run failed: {e:#}");
                    gap = true;
                    continue;
                }
            };
            if t.is_some() && !s.steps.iter().any(|st| st.mutate) {
                println!("target not reached: unmutated");
                gap = true;
            }
            if let Some(why) = run.unjudged {
                println!("read half not judged: {why}");
            }
            println!("outcome: {class:?}");
            if !matches!(class, Outcome::Violation(_)) {
                continue;
            }
            bad = true;
            let Some(file) = &log_file else { continue };
            let mut file = file.clone().into_os_string();
            file.push(format!(".{k}"));
            std::fs::write(&file, s.to_string()).with_context(|| file.to_string_lossy().into_owned())?;
            println!("schedule: {}", file.to_string_lossy());
            confirm(&s, end, &mut log, "").inspect_err(|_| print(&log))?;
        }
        println!("seed {seed}: {}", VERDICTS[verdict(&ws, bad, gap)]);
        return Ok(());
    };

    // §3.10: the sweep. Each row is written as its run ends: an interrupted
    // campaign keeps them.
    let n = seeds.expect("checked with --campaign");
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
    // On a terminal, a progress line over seeds on stderr below the per-run
    // lines; cleared before anything prints to stdout.
    let tty = std::io::stderr().is_terminal();
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
    for seed in 0..n {
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
                println!("[{}/{n}] seed {seed}: incomplete, {note}", seed + 1);
                bar(seed + 1, &classes);
                continue;
            }
        };
        let ws = windows(&targets);
        // The plan, sized by the first baseline: a discovery costs about one
        // baseline, plus a confirm and minimization per new Violation.
        if seed == 0 {
            let per = ws.len() as u64 + 1;
            println!("plan: {n} seeds, {} windows in seed 0, ~{} runs, est. {} (+ confirms)", ws.len(), n * per, hms((n * per) as f64 * secs));
        }
        println!("[{}/{n}] seed {seed}: {}", seed + 1, telemetry(&log, targets.len(), secs));
        bar(seed, &classes);
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
                        (name(&class), "-", None, String::new())
                    } else if let Some(i) = found.iter().position(|(d, _)| d.repeated_by(&s.findings, &s.steps)) {
                        found[i].1.push(format!("{seed}:{k}"));
                        ("Violation", "repeat", Some(i + 1), String::new())
                    } else {
                        clear();
                        println!("[{}/{n}] seed {seed} window {k}: Violation, confirming", seed + 1);
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
            println!("[{}/{n}] seed {seed} window {k}/{}: {what}{}  {:.1}s", seed + 1, ws.len(), if unmut { " (unmutated)" } else { "" }, secs.as_secs_f64());
            bar(seed, &classes);
        }
        let v = verdict(&ws, bad, gap);
        verdicts[v] += 1;
        clear();
        println!("[{}/{n}] seed {seed}: {}", seed + 1, VERDICTS[v]);
        bar(seed + 1, &classes);
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
    Ok(())
}
