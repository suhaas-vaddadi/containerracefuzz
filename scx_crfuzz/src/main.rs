//! scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] [--layout PROG] [--log FILE] -- CMD [ARGS...]
//! scx_crfuzz --replay FILE
//! scx_crfuzz --campaign DIR --seeds N --attacker UID:GID [--mutator PROG] [--layout PROG] -- CMD [ARGS...]
//!
//! Run CMD under POS (discovery) twice, a baseline with no mutator and then
//! the fuzzed run, each with its own canary, judged against the attacker
//! alice (UID:GID, no groups, no caps: §1). Prints alice, the fuzzed run's
//! decision log and its outcome class (§6). With `--mutator`, PROG (a binary
//! or a script with a #!) runs at one hold per run, as
//! alice in the held task's view: its namespaces, root and cwd, the path as
//! issued in argv[1] (§10.1). The hold is preselected from the baseline's
//! events with a known path, not keys.all and not a `?tid`: the one at index
//! (seed + seed / count) mod count, printed as `target:`; a run that never
//! reaches it is unmutated. Exits 0 whatever the class; nonzero for an
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
//!
//! `--campaign DIR` sweeps seeds 0..N after one baseline (§3.10): each
//! discovery's schedule goes to `DIR/runs/<seed>.sched` and a row to
//! `DIR/runs.tsv`. A Violation repeating a finding (`Dedup::repeated_by`) is
//! only counted; a new one is confirmed and minimized as `--log` does, and if
//! confirmed is finding n: `DIR/findings/<n>/{schedule,seeds}`. An invalid run
//! is recorded and the sweep goes on. Ends with a summary.

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
    use std::collections::{BTreeSet, HashSet};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};
    use std::time::{Duration, Instant};

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
    let base = match judged(seed, None, None, None, &mut log) {
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
    // The holds a mutator could fire at, named stably (not `?tid`); each run
    // preselects one.
    let targets: Vec<EventId> = log.iter().filter(|d| d.id.path.is_some() && !d.keys.all && !d.id.thread.starts_with('?')).map(|d| d.id.clone()).collect();
    if mutator.is_some() && targets.is_empty() && loaded.is_none() {
        println!("warning: no baseline hold to mutate at; runs are unmutated");
    }

    // The run in `log` as a schedule (§3.8).
    let attacker = format!("{}:{}", alice.uid, alice.gid);
    let schedule = |seed: u64, class: &str, deadline: bool, findings: BTreeSet<Finding>, log: &[Decision]| Schedule {
        seed,
        attacker: attacker.clone(),
        mutator: mutator.clone().filter(|_| !targets.is_empty()),
        layout: layout.clone(),
        cmd: cmd.clone(),
        class: class.into(),
        deadline,
        findings,
        steps: engine::project(log),
    };
    // Discovery: its class and schedule; a Violation's canary is kept (the evidence).
    // Every len seeds cover every target, each block shifted by one so a
    // target meets every POS seed residue: (seed + seed / len) % len, without
    // overflow.
    let len = targets.len() as u64;
    let pick = |seed: u64| (len > 0).then(|| &targets[((seed % len + seed / len % len) % len) as usize]);
    let discover = |seed: u64, log: &mut Vec<Decision>| -> Result<(Outcome, Judged, Schedule)> {
        log.clear();
        let target = pick(seed);
        let mut run = judged(seed, target.and(mutator.as_deref()), target, None, log)?;
        let class = oracle::outcome(std::mem::take(&mut run.found), run.end, base.end);
        if matches!(class, Outcome::Violation(_)) {
            run.canary.keep();
        }
        let s = schedule(seed, name(&class), run.deadline, std::mem::take(&mut run.norm), log);
        Ok((class, run, s))
    };

    // Confirm, then on a Violation minimize, each line after `pre`. None: not
    // confirmed; Some(Some(k)): guilty step k; Some(None): no single guilty
    // hold, or a confirmed non-Violation.
    let confirm = |sched: &Schedule, log: &mut Vec<Decision>, pre: &str| -> Result<Option<Option<usize>>> {
        // Confirm: every recorded mutation, any divergence fails it.
        let fixed = || Fixed { steps: &sched.steps, next: 0, deadline: sched.deadline };
        log.clear();
        let mut r = Replay { fixed: fixed(), only: None, diverged: None };
        let mut run = match judged(sched.seed, sched.mutator.as_deref(), None, Some(&mut r), log) {
            Err(e) if e.is::<Divergence>() => {
                println!("{pre}not confirmed: {e:#}");
                return Ok(None);
            }
            r => r?,
        };
        let class = oracle::outcome(std::mem::take(&mut run.found), run.end, base.end);
        if name(&class) != sched.class || run.norm != sched.findings {
            println!("{pre}not confirmed: {class:?}, normalized {:?}", run.norm);
            return Ok(None);
        }
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
                Err(e) if e.is::<Divergence>() => {
                    println!("{pre}minimize step {k}: not guilty, {e:#}");
                    continue;
                }
                res => res?,
            };
            let class = oracle::outcome(std::mem::take(&mut run.found), run.end, base.end);
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

    let Some(dir) = campaign else {
        let sched = match loaded {
            Some(s) => {
                println!("discovery: {}", s.class);
                s
            }
            None => {
                let target = mutator.as_ref().and(pick(seed));
                if let Some(t) = target {
                    println!("target: {t:?}");
                }
                let r = discover(seed, &mut log);
                print(&log);
                let (class, run, s) = r?;
                if target.is_some() && !s.steps.iter().any(|st| st.mutate) {
                    println!("target not reached: unmutated");
                }
                if let Some(why) = run.unjudged {
                    println!("read half not judged: {why}");
                }
                println!("outcome: {class:?}");
                let Some(file) = log_file else { return Ok(()) };
                std::fs::write(&file, s.to_string()).with_context(|| file.display().to_string())?;
                println!("schedule: {}", file.display());
                if !matches!(class, Outcome::Violation(_)) {
                    return Ok(());
                }
                s
            }
        };
        confirm(&sched, &mut log, "").inspect_err(|_| print(&log))?;
        return Ok(());
    };

    // §3.10: the sweep. Each row is written as its seed ends: an interrupted
    // campaign keeps them.
    let n = seeds.expect("checked with --campaign");
    if mutator.is_some() && n < targets.len() as u64 {
        println!("warning: {n} seeds < {} mutation targets; some are never mutated", targets.len());
    }
    std::fs::create_dir_all(dir.join("runs")).with_context(|| dir.display().to_string())?;
    let mut tsv = std::fs::File::create(dir.join("runs.tsv"))?;
    writeln!(tsv, "seed\tclass\tstatus\tfinding\tdecisions\tpartial\tsecs\tnote")?;
    let hold = |t: &str, nr: i64, p: &Option<PathBuf>| format!("({t} {nr} {})", p.as_deref().map_or("-".into(), |p| p.display().to_string()));
    let mut found: Vec<(Dedup, Vec<u64>)> = Vec::new();
    let (mut invalid, mut decisions, mut partial, mut time) = (0, 0, 0, Duration::ZERO);
    let mut orders = HashSet::new();
    for seed in 0..n {
        let t = Instant::now();
        let r = discover(seed, &mut log);
        let secs = t.elapsed();
        time += secs;
        let (len, part) = (log.len(), log.iter().filter(|d| d.partial).count());
        (decisions, partial) = (decisions + len, partial + part);
        let file = dir.join(format!("runs/{seed}.sched"));
        // status: new, repeat, unconfirmed or invalid on a Violation, else "-".
        let (class, status, finding, note) = match r {
            Err(e) => {
                invalid += 1;
                std::fs::write(&file, schedule(seed, "invalid", false, BTreeSet::new(), &log).to_string())?;
                ("invalid", "-", None, format!("{e:#}"))
            }
            Ok((class, run, s)) => {
                drop(run);
                std::fs::write(&file, s.to_string())?;
                orders.insert(schedule::canonical(&log.iter().map(|d| (&d.id, &d.keys)).collect::<Vec<_>>()));
                if !matches!(class, Outcome::Violation(_)) {
                    (name(&class), "-", None, String::new())
                } else if let Some(i) = found.iter().position(|(k, _)| k.repeated_by(&s.findings, &s.steps)) {
                    found[i].1.push(seed);
                    ("Violation", "repeat", Some(i + 1), String::new())
                } else {
                    println!("[{}/{n}] seed {seed}: Violation, confirming", seed + 1);
                    match confirm(&s, &mut log, "  ") {
                        Err(e) => {
                            invalid += 1;
                            ("Violation", "invalid", None, format!("{e:#}"))
                        }
                        Ok(None) => ("Violation", "unconfirmed", None, String::new()),
                        Ok(Some(k)) => {
                            let id = k.map(|k| &s.steps[k].id);
                            let note = match (k, id) {
                                (Some(k), Some(id)) => format!("guilty step {k} {}", hold(&id.thread, id.nr, &id.path)),
                                _ => "needs more than one hold".into(),
                            };
                            let guilty = id.map(|id| (id.thread.clone(), id.nr, id.path.clone()));
                            found.push((Dedup { guilty, findings: s.findings.clone() }, vec![seed]));
                            let f = dir.join(format!("findings/{}", found.len()));
                            std::fs::create_dir_all(&f)?;
                            std::fs::write(f.join("schedule"), s.to_string())?;
                            ("Violation", "new", Some(found.len()), note)
                        }
                    }
                }
            }
        };
        if let Some(i) = finding {
            let list: String = found[i - 1].1.iter().map(|s| format!("{s}\n")).collect();
            std::fs::write(dir.join(format!("findings/{i}/seeds")), list)?;
        }
        let note = note.replace(['\t', '\n'], " ");
        let f = finding.map_or("-".into(), |i| i.to_string());
        writeln!(tsv, "{seed}\t{class}\t{status}\t{f}\t{len}\t{part}\t{:.3}\t{note}", secs.as_secs_f64())?;
        let what = match status {
            "new" => format!("Violation → confirmed, {note} → finding #{f} (new)"),
            "repeat" => format!("Violation → repeat of finding #{f}"),
            "unconfirmed" => "Violation → not confirmed".into(),
            "invalid" => format!("Violation → invalid: {note}"),
            _ if class == "invalid" => format!("invalid: {note}"),
            _ => class.into(),
        };
        println!("[{}/{n}] seed {seed}: {what}  {:.1}s", seed + 1, secs.as_secs_f64());
    }

    println!("campaign: {n} runs, {invalid} invalid, discovery {:.1}s", time.as_secs_f64());
    println!("distinct partial orders: {}", orders.len());
    println!("partial decisions: {partial}/{decisions} ({:.0}%)", 100.0 * partial as f64 / decisions.max(1) as f64);
    println!("findings: {}", found.len());
    for (i, (k, seeds)) in found.iter().enumerate() {
        let guilty = k.guilty.as_ref().map_or("needs more than one hold".into(), |(t, nr, p)| hold(t, *nr, p));
        println!("finding #{}: {} seeds, guilty {guilty}, {:?}, {}", i + 1, seeds.len(), k.findings, dir.join(format!("findings/{}", i + 1)).display());
    }
    Ok(())
}
