//! scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] [--layout PROG] [--log FILE] -- CMD [ARGS...]
//! scx_crfuzz --replay FILE
//!
//! Run CMD under POS (discovery) twice, a baseline with no mutator and then
//! the fuzzed run, each with its own canary, judged against the attacker
//! alice (UID:GID, no groups, no caps: §1). Prints alice, the fuzzed run's
//! decision log and its outcome class (§6). With `--mutator`, PROG (a binary
//! or a script with a #!) runs at every hold whose event has a known path, as
//! alice in the held task's view: its namespaces, root and cwd, the path as
//! issued in argv[1] (§10.1). Exits 0 whatever the class; nonzero for an
//! invalid run, after printing the decisions made so far. Needs root and a
//! running scx_crfuzz_gated.
//!
//! `--log FILE` writes the fuzzed run as a schedule (§3.8); on a Violation it
//! is then confirmed and minimized, as `--replay FILE` does: one baseline,
//! a replay with every recorded mutation that must give the same class and
//! normalized findings, then one replay per recorded mutation alone, in
//! order, until one flags a finding of the schedule's: the guilty hold.
//! `--layout PROG` (absolute, recorded in the schedule) runs as root before
//! every run to restore the starting filesystem, so no run sees what an
//! earlier one's SUT or mutator left behind; a failure makes the run invalid.

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
    use scx_crfuzz::pos::Pos;
    use scx_crfuzz::schedule::{self, Divergence, Fixed, Schedule};
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};
    use std::time::{Duration, Instant};

    const USAGE: &str = "usage: scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] [--layout PROG] [--log FILE] -- CMD [ARGS...]\n       scx_crfuzz --replay FILE";
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

    let argv: Vec<String> = std::env::args().skip(1).collect();
    // --replay: everything comes from the file.
    let loaded = match &argv[..] {
        [r, f] if r == "--replay" => Some(std::fs::read_to_string(f).context(f.clone())?.parse::<Schedule>().context(f.clone())?),
        _ => None,
    };
    let (mut seed, mut mutator, mut layout, mut attacker, mut log_file) = (0u64, None, None, None, None);
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
                    Some("--") => break args.collect(),
                    _ => bail!(USAGE),
                }
            }
        }
    };
    // §1: an input, never inferred; refused before anything starts.
    let alice = attacker.with_context(|| format!("--attacker is required\n{USAGE}"))?;
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

    // One run with its own canary; its decisions go to `log` whatever the ending.
    let judged = |mutator: Option<&Path>, replay: Option<&mut Replay>, n: u32, log: &mut Vec<Decision>| -> Result<Judged> {
        if let Some(l) = &layout {
            let st = Command::new(l).status().with_context(|| l.display().to_string())?;
            ensure!(st.success(), "invalid: layout {} failed: {st}", l.display());
        }
        let canary = Canary::create(n)?;
        backend::read_before(&canary, &alice)?;
        let mut sut = Command::new(prog);
        sut.args(rest);
        let mut be = GateBackend::spawn(sut, WATCHED)?;
        let mut j = Judge { canary: &canary, alice: alice.clone(), reached: None, task: None };
        let r = engine::run(&mut be, &mut Pos::new(seed), mutator, replay, Some(&mut j), ms(1), ms(200), Instant::now() + Duration::from_secs(60), log);
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

    println!("{alice}");
    let mut log = Vec::new();
    let base = match judged(None, None, 0, &mut log) {
        Ok(b) if b.found.is_empty() => b,
        r => {
            println!("baseline:");
            print(&log);
            let mut b = r?;
            b.canary.keep(); // the evidence
            bail!("invalid: the scenario leaks with no mutation: {:?}", b.found);
        }
    };
    drop(base.canary);
    let sched = match loaded {
        Some(s) => {
            println!("discovery: {}", s.class);
            s
        }
        None => {
            log.clear();
            let run = judged(mutator.as_deref(), None, 1, &mut log);
            print(&log);
            let mut run = run?;
            if let Some(why) = run.unjudged {
                println!("read half not judged: {why}");
            }
            let class = oracle::outcome(std::mem::take(&mut run.found), run.end, base.end);
            println!("outcome: {class:?}");
            if matches!(class, Outcome::Violation(_)) {
                run.canary.keep(); // the evidence
            }
            let Some(file) = log_file else { return Ok(()) };
            let attacker = format!("{}:{}", alice.uid, alice.gid);
            let s = Schedule { seed, attacker, mutator, layout: layout.clone(), cmd: cmd.clone(), class: name(&class).into(), deadline: run.deadline, findings: run.norm, steps: engine::project(&log) };
            std::fs::write(&file, s.to_string()).with_context(|| file.display().to_string())?;
            println!("schedule: {}", file.display());
            if !matches!(class, Outcome::Violation(_)) {
                return Ok(());
            }
            s
        }
    };

    // Confirm: every recorded mutation, any divergence fails it.
    let fixed = || Fixed { steps: &sched.steps, next: 0, deadline: sched.deadline };
    log.clear();
    let mut r = Replay { fixed: fixed(), only: None, diverged: None };
    let mut run = match judged(sched.mutator.as_deref(), Some(&mut r), 2, &mut log) {
        Err(e) if e.is::<Divergence>() => {
            println!("not confirmed: {e:#}");
            return Ok(());
        }
        r => r.inspect_err(|_| print(&log))?,
    };
    let class = oracle::outcome(std::mem::take(&mut run.found), run.end, base.end);
    if name(&class) != sched.class || run.norm != sched.findings {
        println!("not confirmed: {class:?}, normalized {:?}", run.norm);
        return Ok(());
    }
    println!("confirmed: {}", sched.class);
    if !matches!(class, Outcome::Violation(_)) {
        return Ok(());
    }
    run.canary.keep(); // the evidence
    drop(run);

    // Minimize: the first hold whose mutation alone flags a finding of the
    // schedule's. ponytail: one bug, single holds only; a pair search when
    // findings need two mutations.
    for k in (0..sched.steps.len()).filter(|&k| sched.steps[k].mutate) {
        log.clear();
        let mut r = Replay { fixed: fixed(), only: Some(k), diverged: None };
        let res = judged(sched.mutator.as_deref(), Some(&mut r), 3 + k as u32, &mut log);
        let mut run = match res {
            Err(e) if e.is::<Divergence>() => {
                println!("minimize step {k}: not guilty, {e:#}");
                continue;
            }
            res => res.inspect_err(|_| print(&log))?,
        };
        let class = oracle::outcome(std::mem::take(&mut run.found), run.end, base.end);
        let tail = r.diverged.map(|d| format!(" (then POS: {d})")).unwrap_or_default();
        println!("minimize step {k}: {class:?}{tail}");
        if matches!(class, Outcome::Violation(_)) && !run.norm.is_disjoint(&sched.findings) {
            println!("guilty: step {k} {:?}", sched.steps[k].id);
            return Ok(());
        }
    }
    println!("guilty: needs more than one hold");
    Ok(())
}
