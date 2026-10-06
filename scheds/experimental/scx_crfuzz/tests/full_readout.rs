// SPDX-License-Identifier: GPL-2.0
//
// Full-readout runs against real targets (design doc, "Testing": root, in the
// VM): the readout waits for every thread, the CPU watchdog freezes a thread
// that never comes to rest, and scenario 2 is seed-reproducible once it has no
// timers.
//
// Requires root and the `sched_ext` gate, so it is gated and skipped
// elsewhere. Build the fixtures first:
//
//     cd scheds/experimental/scx_crfuzz/scenarios && make
#![cfg(target_os = "linux")]

use scx_crfuzz::backend_gate::GateBackend;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::Engine;
use scx_crfuzz::RunOutcome;
use scx_crfuzz::ScenarioConfig;
use scx_crfuzz_gate::GateMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

/// What a finished run reports.
struct Ran {
    outcome: RunOutcome,
    /// `decision_trace`: each decision's ready set.
    trace: Vec<String>,
    /// The `role/tN` each decision released (POS never drains, so one per
    /// decision).
    released: Vec<String>,
    timed: u32,
    frozen: u32,
}

/// Run `config` over `spawn` in cgroup `/crfuzz/full-readout-<tag>`. The
/// engine is dropped, lifting its gates, before this returns.
fn run(
    config: &str,
    tag: &str,
    spawn: &[String],
    stop: Option<&'static AtomicBool>,
) -> anyhow::Result<Ran> {
    let specs = spawn.iter().map(|s| ProcessSpec::parse(s)).collect::<anyhow::Result<_>>()?;
    let seccomp = SeccompNotifyBackend::new(specs, format!("/crfuzz/full-readout-{tag}"))
        .with_sched_ext(true);
    let mut engine = Engine::new(ScenarioConfig::from_json(config)?, GateBackend::new(seccomp)?);
    if let Some(stop) = stop {
        engine = engine.with_stop(stop);
    }
    let outcome = engine.run()?;
    Ok(Ran {
        outcome,
        trace: engine.decision_trace().to_vec(),
        released: engine
            .canonical_log()
            .entries
            .iter()
            .map(|e| format!("{}/{}", e.role, e.thread.as_deref().unwrap_or("")))
            .collect(),
        timed: engine.timed_sleep_decisions(),
        frozen: engine.frozen_decisions(),
    })
}

/// Held by every test for its whole run. A backend reaps with
/// `waitpid(-1)`, so two runs in one process would reap each other's
/// children and wait forever for their own.
static SERIAL: Mutex<()> = Mutex::new(());

/// `None` when `test` cannot run here; else the serializing guard.
fn serial(test: &str) -> Option<MutexGuard<'static, ()>> {
    if skip_unless_root(test) {
        return None;
    }
    if !GateMap::scheduler_enabled() {
        eprintln!("skipping {test}: scx_crfuzz_gated is not running");
        return None;
    }
    Some(SERIAL.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The `role/tN` of each entry of a ready set.
fn threads(set: &str) -> Vec<&str> {
    set.split(',').map(|e| e.split('@').next().unwrap()).collect()
}

fn fixture(name: &str) -> String {
    scenarios_dir().join("fixtures").join(name).display().to_string()
}

/// A one-role config watching `newfstatat`.
fn one_role(comm: &str, extra: &str) -> String {
    format!(
        r#"{{
            "scenario_id": "{comm}",
            "cgroup": "/crfuzz",
            "roles": [{{ "id": "{comm}", "comm": "{comm}" }}],
            "checkpoints": [{{
                "id": "newfstatat", "kind": "syscall", "target": "newfstatat",
                "category": "resolving"
            }}],
            {extra}
            "policy": {{ "type": "pos", "seed": 1 }}
        }}"#
    )
}

/// Scenario 2's two processes, as `run.sh` spawns them, in `dir`. `still`
/// removes every timer from both: the victim's sibling waits on a signal and
/// it skips its warmup, and each attacker thread makes exactly 20 renames with
/// no sleep between them.
///
/// The binaries are copied into `dir` first: a page-in from a shared mount
/// (the VM's view of the repo) is an I/O wait, which counts as waking on its
/// own (`timed_sleep_decisions`).
fn scenario_2(dir: &Path, still: bool) -> Vec<String> {
    let s2 = scenarios_dir().join("02-multi-thread");
    for bin in ["threaded_victim", "mt_attacker"] {
        std::fs::copy(s2.join(bin), dir.join(bin)).unwrap();
    }
    std::fs::write(dir.join("target"), "BENIGN\n").unwrap();
    std::fs::create_dir(dir.join("scratch")).unwrap();
    vec![
        format!(
            "{} {} {} {}",
            dir.join("threaded_victim").display(),
            dir.join("target").display(),
            dir.join("progress").display(),
            if still { "still" } else { "" }
        ),
        format!(
            "{} {} 3 1 {}",
            dir.join("mt_attacker").display(),
            dir.join("scratch").display(),
            if still { "20" } else { "" }
        ),
    ]
}

fn scenario_2_config() -> String {
    std::fs::read_to_string(scenarios_dir().join("02-multi-thread/race.json")).unwrap()
}

/// Decision 1 holds all four threads that park (the victim's main thread
/// and the attacker's three workers), and nothing was frozen.
fn assert_first_decision_full(r: &Ran) {
    assert_eq!(r.outcome, RunOutcome::Completed);
    assert_eq!(r.frozen, 0, "no thread needed the watchdog");
    let mut first = threads(&r.trace[0]);
    first.sort_unstable();
    assert_eq!(
        first,
        ["attacker/t0.0", "attacker/t0.1", "attacker/t0.2", "victim/t0"],
        "decision 1: {}",
        r.trace[0]
    );
}

#[test]
fn scenario_2_decides_over_every_parked_thread() {
    let Some(_serial) = serial("scenario_2_decides_over_every_parked_thread") else {
        return;
    };
    abort_after(Duration::from_secs(300));
    let dir = tempfile::tempdir().unwrap();
    let r = run(&scenario_2_config(), "s2", &scenario_2(dir.path(), false), None).unwrap();
    assert_first_decision_full(&r);
    // The threads sleep on timers between their checkpoints, so a thread
    // missing from one ready set may simply have been asleep. What must hold:
    // a parked thread stays in every ready set until it is released.
    for (i, next) in r.trace.iter().enumerate().skip(1) {
        let next = threads(next);
        for t in threads(&r.trace[i - 1]) {
            assert!(
                t == r.released[i - 1] || next.contains(&t),
                "{t} left the ready set at decision {} without a release",
                i + 1
            );
        }
    }
    // A ready set missing a thread that parks later with no release of it in
    // between: only a decision taken while that thread slept on a timer.
    let sets: Vec<Vec<&str>> = r.trace.iter().map(|s| threads(s)).collect();
    let missing = (0..sets.len())
        .filter(|&i| {
            sets.iter().flatten().any(|t| {
                !sets[i].contains(t)
                    && (i + 1..sets.len())
                        .take_while(|&j| r.released[j - 1] != *t)
                        .any(|j| sets[j].contains(t))
            })
        })
        .count();
    assert!(r.timed > 0, "the shipped scenario sleeps on timers");
    assert!(missing <= r.timed as usize, "{missing} incomplete ready sets, {} timed", r.timed);
    eprintln!(
        "scenario 2: {} decisions, {} timed, {} frozen, {missing} missing a later parker; \
         decision 1: {}",
        r.trace.len(),
        r.timed,
        r.frozen,
        r.trace[0]
    );
}

#[test]
fn scenario_2_without_timers_is_seed_reproducible() {
    let Some(_serial) = serial("scenario_2_without_timers_is_seed_reproducible") else {
        return;
    };
    abort_after(Duration::from_secs(300));
    let runs: Vec<Ran> = ["s2-still-a", "s2-still-b"]
        .iter()
        .map(|tag| {
            let dir = tempfile::tempdir().unwrap();
            run(&scenario_2_config(), tag, &scenario_2(dir.path(), true), None).unwrap()
        })
        .collect();
    for r in &runs {
        assert_first_decision_full(r);
        assert_eq!(r.timed, 0, "nothing sleeps on a timer");
        // Nothing wakes on its own, so a thread in a ready set that was not
        // in the one before was released by it: anything else had parked
        // already, and the earlier decision missed it.
        for (i, next) in r.trace.iter().enumerate().skip(1) {
            let prev = threads(&r.trace[i - 1]);
            for t in threads(next) {
                assert!(
                    t == r.released[i - 1] || prev.contains(&t),
                    "decision {i} ({}) missed {t}, parked at decision {}",
                    r.trace[i - 1],
                    i + 1
                );
            }
        }
    }
    let first_diff = runs[0].trace.iter().zip(&runs[1].trace).position(|(a, b)| a != b);
    assert!(
        first_diff.is_none() && runs[0].trace.len() == runs[1].trace.len(),
        "traces differ at decision {:?} (lengths {} and {})",
        first_diff.map(|i| i + 1),
        runs[0].trace.len(),
        runs[1].trace.len()
    );
    eprintln!("scenario 2 without timers: {} identical decisions", runs[0].trace.len());
}

/// spin_park's spinner tid, once it has written it.
fn spinner_tid(out: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(out).unwrap_or_default();
        if let Some(tid) = text.lines().next().and_then(|l| l.parse().ok()) {
            return tid;
        }
        assert!(Instant::now() < deadline, "the spinner never wrote its tid");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn spin_park(dir: &Path) -> Vec<String> {
    let target = dir.join("target");
    std::fs::write(&target, "x").unwrap();
    vec![format!(
        "{} {} {}",
        fixture("spin_park"),
        target.display(),
        dir.join("out").display()
    )]
}

#[test]
fn the_watchdog_freezes_a_spinner_and_thaws_it() {
    let Some(_serial) = serial("the_watchdog_freezes_a_spinner_and_thaws_it") else {
        return;
    };
    abort_after(Duration::from_secs(300));
    let dir = tempfile::tempdir().unwrap();
    let config = one_role("spin_park", r#""watchdog_cpu_secs": 1,"#);
    let started = Instant::now();
    let r = run(&config, "spin", &spin_park(dir.path()), None).unwrap();

    assert_eq!(r.outcome, RunOutcome::Completed);
    assert_eq!(r.trace, ["spin_park/t0@newfstatat"]);
    assert_eq!(r.frozen, 1, "the one decision waited on the frozen spinner");
    let out = std::fs::read_to_string(dir.path().join("out")).unwrap();
    assert_eq!(
        out.lines().nth(1),
        Some("held"),
        "the spinner must not advance while frozen"
    );
    // The spinner exits only once thawed; the forced thaw comes at 20 s.
    assert!(started.elapsed() < Duration::from_secs(15), "{:?}", started.elapsed());
    assert!(!GateMap::open().unwrap().is_tid_gated(spinner_tid(&dir.path().join("out"))));
}

#[test]
fn a_run_stopped_while_a_thread_is_frozen_leaves_no_gate() {
    let Some(_serial) = serial("a_run_stopped_while_a_thread_is_frozen_leaves_no_gate") else {
        return;
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    abort_after(Duration::from_secs(300));
    let dir = tempfile::tempdir().unwrap();
    let spawn = spin_park(dir.path());
    let config = one_role("spin_park", r#""watchdog_cpu_secs": 1,"#);
    let engine = std::thread::spawn(move || run(&config, "spin-stop", &spawn, Some(&STOP)));

    let spinner = spinner_tid(&dir.path().join("out"));
    let pid = tgid_of(spinner);
    let map = GateMap::open().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !map.is_tid_gated(spinner) {
        assert!(Instant::now() < deadline, "the spinner was never frozen");
        std::thread::sleep(Duration::from_millis(5));
    }
    STOP.store(true, Ordering::Relaxed);
    let err = engine.join().unwrap().err().expect("a stopped run fails");
    assert!(err.to_string().contains("interrupted"), "{err:#}");

    // The main thread is still busy for its 5 s, so the spinner is alive
    // (its gate cannot have gone with it) and spinning again.
    assert!(Path::new(&format!("/proc/{spinner}")).exists(), "the spinner exited");
    assert!(!map.is_tid_gated(spinner), "the stopped run left tid {spinner} gated");
    // The stopped run did not reap its child; the next run's would.
    // SAFETY: waitpid on our own child.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

#[test]
fn no_decision_while_a_pinned_thread_is_waking() {
    let Some(_serial) = serial("no_decision_while_a_pinned_thread_is_waking") else {
        return;
    };
    abort_after(Duration::from_secs(300));
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, "x").unwrap();
    let spawn = [format!("{} {}", fixture("pinned_wake"), target.display())];
    for i in 0..10 {
        let r = run(&one_role("pinned_wake", ""), "pinned", &spawn, None).unwrap();
        assert_eq!(r.outcome, RunOutcome::Completed);
        assert_eq!(r.frozen, 0);
        // The main thread's release woke the reader, which then parked: the
        // decision at the main thread's second park must wait for it.
        assert_eq!(r.trace.len(), 3, "run {i}: {:?}", r.trace);
        assert_eq!(
            r.trace[1], "pinned_wake/t0@newfstatat,pinned_wake/t0.0@newfstatat",
            "run {i}: decision 2 must hold both threads"
        );
    }
}
