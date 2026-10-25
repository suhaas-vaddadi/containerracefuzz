//! scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] -- CMD [ARGS...]
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{bail, Context, Result};
    use scx_crfuzz::backend::{self, GateBackend, SelfCheckFailed};
    use scx_crfuzz::engine::{self, Deadline, Decision, Judge};
    use scx_crfuzz::oracle::{self, Alice, Canary, Finding, Outcome};
    use scx_crfuzz::pos::Pos;
    use std::path::Path;
    use std::process::{Command, ExitStatus};
    use std::time::{Duration, Instant};

    const USAGE: &str = "usage: scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] -- CMD [ARGS...]";
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

    let mut args = std::env::args().skip(1);
    let (mut seed, mut mutator, mut attacker) = (0u64, None, None);
    let cmd: Vec<String> = loop {
        match args.next().as_deref() {
            Some("--seed") => seed = args.next().context(USAGE)?.parse().context("--seed")?,
            // Absolute: the mutator is exec'd after a chdir into the task's cwd.
            Some("--mutator") => mutator = Some(std::fs::canonicalize(args.next().context(USAGE)?).context("--mutator")?),
            Some("--attacker") => attacker = Some(Alice::parse(&args.next().context(USAGE)?)?),
            Some("--") => break args.collect(),
            _ => bail!(USAGE),
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
        /// Some: why only the write half was judged.
        unjudged: Option<&'static str>,
        /// Removed on drop unless kept (§10.2).
        canary: Canary,
    }

    // One run with its own canary; its decisions go to `log` whatever the ending.
    let judged = |mutator: Option<&Path>, n: u32, log: &mut Vec<Decision>| -> Result<Judged> {
        let canary = Canary::create(n)?;
        backend::read_before(&canary, &alice)?;
        let mut sut = Command::new(prog);
        sut.args(rest);
        let mut be = GateBackend::spawn(sut, WATCHED)?;
        let mut j = Judge { canary: &canary, alice: alice.clone(), reached: None };
        let r = engine::run(&mut be, &mut Pos::new(seed), mutator, Some(&mut j), ms(1), ms(200), Instant::now() + Duration::from_secs(60), log);
        let end = if r.is_ok() { Some(be.child().wait()?) } else { None };
        // Clears gates and cgroup, ending what is left of the SUT, before the
        // write half: a gated task may serve a mount inside the canary.
        drop(be);
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
        Ok(Judged { end, found, unjudged, canary })
    };
    let print = |log: &[Decision]| log.iter().for_each(|d| println!("{d:?}"));

    println!("{alice}");
    let mut log = Vec::new();
    let base = match judged(None, 0, &mut log) {
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
    log.clear();
    let run = judged(mutator.as_deref(), 1, &mut log);
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
    Ok(())
}
