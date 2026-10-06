// SPDX-License-Identifier: GPL-2.0
//
//! End-to-end engine runs against `StubBackend`.
//!
//! These cover the design doc's section 10 validation methodology as far as it
//! can be covered without a real checkpoint backend:
//!
//! - **Ordering determinism** (section 10.1) -- same seed, same scenario,
//!   byte-identical canonical log.
//! - **The discover-to-replay loop** (sections 3.5 and 10.3) -- project a
//!   discovery log into `steps[]`, replay it, get the same log back.
//!
//! What they do NOT cover, and must not be read as covering:
//!
//! - **Checkpoint precision** (section 10.2) validates the synchronous-holding
//!   construction -- seccomp user-notify. `StubBackend` holds nothing, so
//!   nothing here says anything about it.
//! - **Section 14-A.** The stub scripts the thread-state records, so the
//!   determinism tests below show that the full readout and `decide()` give
//!   one decision sequence under any scripted interleaving -- not that the
//!   real sensor reports what the script assumes. See the crate docs,
//!   "Section 14-A". A green suite here is not evidence of end-to-end
//!   reproducibility and must not be cited as such.

use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::StubBackend;
use scx_crfuzz::backend::ThreadStateKind;
use scx_crfuzz::config::DivergencePolicy;
use scx_crfuzz::config::Mode;
use scx_crfuzz::config::ScenarioConfig;
use scx_crfuzz::engine::RunOutcome;
use scx_crfuzz::event::ConflictKey;
use scx_crfuzz::event::Direction;
use scx_crfuzz::event::FileToken;
use scx_crfuzz::role::TaskInfo;
use scx_crfuzz::Engine;

const CGROUP: &str = "/crfuzz";

fn task(pid: i32, tgid: i32, parent_tgid: i32, comm: &str) -> TaskInfo {
    TaskInfo {
        pid,
        tgid,
        parent_tgid,
        comm: comm.to_string(),
        cgroup: format!("{CGROUP}/run0"),
    }
}

/// A victim and one racer, each walking a short sequence of path-touching
/// syscalls. Identical every time it is called, so two runs differ only in
/// what the policy decided.
fn scenario() -> StubBackend {
    StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(200, 200, 1, "racer"))
        .hit(100, "chdir")
        .hit(100, "openat")
        .hit(100, "mount")
        .exit(100)
        .hit(200, "symlink")
        .hit(200, "rename")
        .exit(200)
}

fn config_with_roles(roles: &str, policy: &str) -> ScenarioConfig {
    ScenarioConfig::from_json(&format!(
        r#"{{
            "scenario_id": "toy-victim-racer",
            "cgroup": "{CGROUP}",
            "roles": [{roles}],
            "policy": {policy}
        }}"#
    ))
    .expect("discovery config should parse")
}

fn discovery_config(policy: &str) -> ScenarioConfig {
    config_with_roles(
        r#"{ "id": "victim", "comm": "runc" }, { "id": "racer", "comm": "racer", "cardinality": "pool" }"#,
        policy,
    )
}

/// Both roles `one`.
fn one_racer_config(seed: u64) -> ScenarioConfig {
    config_with_roles(
        r#"{ "id": "victim", "comm": "runc" }, { "id": "racer", "comm": "racer" }"#,
        &format!(r#"{{ "type": "pos", "seed": {seed} }}"#),
    )
}

/// The victim alone, for tests where no racer ever runs.
fn victim_only_config() -> ScenarioConfig {
    config_with_roles(
        r#"{ "id": "victim", "comm": "runc" }"#,
        r#"{ "type": "pos", "seed": 1 }"#,
    )
}

fn run(config: ScenarioConfig) -> (RunOutcome, String, Vec<scx_crfuzz::config::Step>) {
    let mut engine = Engine::new(config, scenario());
    let outcome = engine.run().expect("engine run");
    let log = engine.canonical_log();
    (outcome, log.render(), log.project_to_steps())
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

#[test]
fn a_scenario_runs_to_completion_and_every_release_is_recorded() {
    let (outcome, log, steps) = run(one_racer_config(1));
    assert_eq!(outcome, RunOutcome::Completed);
    // Five checkpoint hits; exits are not decisions.
    assert_eq!(steps.len(), 5, "log:\n{log}");
    assert!(log.starts_with("# scenario toy-victim-racer\n"));
}

#[test]
fn nothing_is_released_before_every_one_role_has_appeared() {
    // The racer reaches a checkpoint while the `one` role it is waiting on
    // has not appeared. It must be held, not released.
    let backend = StubBackend::new()
        .task(task(200, 200, 1, "racer"))
        .hit(200, "symlink");
    let config = discovery_config(r#"{ "type": "pos", "seed": 1 }"#);
    let mut engine = Engine::new(config, backend);
    let outcome = engine.run().expect("engine run");

    assert!(
        engine.canonical_log().is_empty(),
        "the readout was never complete, so nothing may have been enforced"
    );
    assert!(matches!(outcome, RunOutcome::Deadlocked { .. }), "{outcome:?}");
}

#[test]
fn a_pool_role_alone_does_not_complete_the_readout_but_does_not_block_it_either() {
    // Section 5: `all_roles_seen()` is evaluated over `one` roles only.
    // The full scenario completes even though no fixed number of pool members
    // was ever declared or waited for.
    let (outcome, _, steps) = run(discovery_config(r#"{ "type": "pos", "seed": 3 }"#));
    assert_eq!(outcome, RunOutcome::Completed);
    assert!(steps.iter().any(|s| s.role.starts_with("racer#")));
}

#[test]
fn a_task_belonging_to_no_role_is_released_without_being_recorded() {
    // The blast-radius guarantee: every other task on the machine is
    // dispatched unmodified.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(900, 900, 1, "sshd"))
        .hit(900, "openat")
        .hit(100, "chdir")
        .exit(100)
        .exit(900);
    let mut engine = Engine::new(victim_only_config(), backend);
    engine.run().expect("engine run");

    let log = engine.canonical_log().render();
    assert!(!log.contains("sshd"));
    assert_eq!(
        engine.canonical_log().len(),
        1,
        "only the victim's chdir: got\n{log}"
    );
}

// ---------------------------------------------------------------------------
// Determinism (section 10.1)
// ---------------------------------------------------------------------------

#[test]
fn discovery_with_the_same_seed_produces_a_byte_identical_canonical_log() {
    let cfg = r#"{ "type": "pos", "seed": 20260914 }"#;
    let (_, a, _) = run(discovery_config(cfg));
    let (_, b, _) = run(discovery_config(cfg));
    assert_eq!(a, b);
}

#[test]
fn different_seeds_explore_different_interleavings() {
    // Not a guarantee for any particular pair of seeds -- but if no seed ever
    // changed the interleaving, discovery mode would not be exploring anything.
    let logs: Vec<String> = (0..24).map(|seed| run(one_racer_config(seed)).1).collect();
    let distinct: std::collections::HashSet<&String> = logs.iter().collect();
    assert!(
        distinct.len() > 1,
        "24 seeds produced one interleaving; the policy is not exploring"
    );
}

// ---------------------------------------------------------------------------
// The discover-to-replay loop (sections 3.5, 10.3)
// ---------------------------------------------------------------------------

#[test]
fn projecting_a_discovery_log_into_steps_and_replaying_it_reproduces_it_exactly() {
    // This is the concrete, testable form of the document's central claim: a
    // bug discovery mode finds is replayable, because the log format already
    // *is* the schedule format. Against a real backend this same shape becomes
    // section 10.3's check (replay the projection, confirm the same oracle
    // violation); here it confirms the projection itself is faithful.
    let discovery = discovery_config(r#"{ "type": "pos", "seed": 4242 }"#);
    let (outcome, discovered, steps) = run(discovery.clone());
    assert_eq!(outcome, RunOutcome::Completed);
    assert!(!steps.is_empty());

    let replay = discovery.as_replay_with(steps);
    let (replay_outcome, replayed, _) = run(replay);

    assert_eq!(replay_outcome, RunOutcome::Completed);
    assert_eq!(
        replayed, discovered,
        "replaying the projection must reproduce the run it came from"
    );
}

#[test]
fn the_projection_survives_a_round_trip_through_the_config_format() {
    // The projected schedule has to be a config someone can save, hand to
    // another machine, and re-parse -- not just an in-memory value.
    let discovery = discovery_config(r#"{ "type": "pos", "seed": 9 }"#);
    let (_, discovered, steps) = run(discovery.clone());

    let json = discovery
        .as_replay_with(steps)
        .to_json()
        .expect("serialize");
    let reparsed = ScenarioConfig::from_json(&json).expect("the projection must be a valid config");
    assert!(matches!(reparsed.mode, Mode::Replay { .. }));

    let (_, replayed, _) = run(reparsed);
    assert_eq!(replayed, discovered);
}

#[test]
fn replaying_a_projection_is_insensitive_to_the_seed_that_produced_it() {
    // Once projected, the schedule is the authority: nothing about the original
    // policy's randomness survives into replay.
    let a = discovery_config(r#"{ "type": "pos", "seed": 11 }"#);
    let (_, log_a, steps_a) = run(a.clone());
    let b = discovery_config(r#"{ "type": "pos", "seed": 12 }"#);

    let (_, replayed, _) = run(b.as_replay_with(steps_a));
    assert_eq!(replayed, log_a);
}

// ---------------------------------------------------------------------------
// Divergence
// ---------------------------------------------------------------------------

fn replay_config(steps: &str, on_divergence: DivergencePolicy) -> ScenarioConfig {
    let od = match on_divergence {
        DivergencePolicy::Block => "block",
        DivergencePolicy::Skip => "skip",
        DivergencePolicy::Abort => "abort",
    };
    ScenarioConfig::from_json(&format!(
        r#"{{
            "scenario_id": "toy-victim-racer",
            "cgroup": "{CGROUP}",
            "roles": [
                {{ "id": "victim", "comm": "runc" }},
                {{ "id": "racer", "comm": "racer", "cardinality": "pool" }}
            ],
            "checkpoints": [
                {{ "id": "chdir", "kind": "syscall", "target": "chdir" }},
                {{ "id": "openat", "kind": "syscall", "target": "openat" }},
                {{ "id": "mount", "kind": "syscall", "target": "mount" }},
                {{ "id": "symlink", "kind": "syscall", "target": "symlink" }},
                {{ "id": "rename", "kind": "syscall", "target": "rename" }},
                {{ "id": "never_happens", "kind": "syscall", "target": "mknod" }}
            ],
            "on_divergence": "{od}",
            "steps": {steps}
        }}"#
    ))
    .expect("replay config should parse")
}

#[test]
fn abort_on_divergence_ends_the_run_at_the_unsatisfiable_step() {
    let cfg = replay_config(
        r#"[
            { "role": "victim", "until": "chdir" },
            { "role": "victim", "until": "never_happens" }
        ]"#,
        DivergencePolicy::Abort,
    );
    let mut engine = Engine::new(cfg, scenario());
    let outcome = engine.run().expect("engine run");

    match outcome {
        RunOutcome::Diverged { step_idx, reason } => {
            assert_eq!(step_idx, 1, "the first step was enforced before diverging");
            assert!(reason.contains("never_happens"), "reason: {reason}");
        }
        other => panic!("expected a divergence, got {other:?}"),
    }
    assert_eq!(engine.canonical_log().len(), 1);
}

#[test]
fn skip_on_divergence_advances_past_the_unsatisfiable_step_and_carries_on() {
    let cfg = replay_config(
        r#"[
            { "role": "victim", "until": "chdir" },
            { "role": "victim", "until": "never_happens" },
            { "role": "racer#0", "until": "symlink" }
        ]"#,
        DivergencePolicy::Skip,
    );
    let mut engine = Engine::new(cfg, scenario());
    let outcome = engine.run().expect("engine run");

    assert_eq!(outcome, RunOutcome::Completed);
    let log = engine.canonical_log().render();
    assert!(log.contains("victim/t0\tchdir"), "log:\n{log}");
    assert!(log.contains("racer#0/t0\tsymlink"), "log:\n{log}");
    assert!(!log.contains("never_happens"));
}

#[test]
fn block_on_divergence_releases_nothing_rather_than_releasing_the_wrong_role() {
    // Step 0 names a checkpoint the victim can only reach after earlier
    // releases the schedule does not contain, so it is unsatisfiable. Under
    // `block` the engine must sit there -- and in particular must NOT release
    // the racer, which is sitting in the ready set the whole time.
    let cfg = replay_config(
        r#"[
            { "role": "victim", "until": "mount" }
        ]"#,
        DivergencePolicy::Block,
    );
    let mut engine = Engine::new(cfg, scenario());
    let outcome = engine.run().expect("engine run");

    assert!(engine.canonical_log().is_empty());
    assert!(
        engine.backend().released.is_empty(),
        "block released something: {:?}",
        engine.backend().released
    );
    // Nothing can ever move again: everyone is at rest and held.
    assert!(
        matches!(outcome, RunOutcome::Deadlocked { .. }),
        "got {outcome:?}"
    );
}

#[test]
fn a_step_must_name_every_release_not_only_the_interesting_ones() {
    // The consequence of reading a step as one release rather than a
    // run-until (see the header comment on `policy::FixedSchedule`): spelling
    // out the victim's intermediate checkpoints is what lets it reach `mount`.
    let cfg = replay_config(
        r#"[
            { "role": "victim", "until": "chdir" },
            { "role": "victim", "until": "openat" },
            { "role": "victim", "until": "mount" }
        ]"#,
        DivergencePolicy::Block,
    );
    let mut engine = Engine::new(cfg, scenario());
    assert_eq!(engine.run().expect("engine run"), RunOutcome::Completed);
    assert_eq!(
        engine.canonical_log().render(),
        "# scenario toy-victim-racer\n0\tvictim/t0\tchdir\n1\tvictim/t0\topenat\n2\tvictim/t0\tmount\n"
    );
}

#[test]
fn a_schedule_left_unfinished_by_the_scenario_does_not_report_completed() {
    let cfg = replay_config(
        r#"[
            { "role": "victim", "until": "chdir" },
            { "role": "victim", "until": "never_happens" }
        ]"#,
        DivergencePolicy::Block,
    );
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .hit(100, "chdir")
        .exit(100);
    let mut engine = Engine::new(cfg, backend);
    let outcome = engine.run().expect("engine run");
    assert!(
        matches!(outcome, RunOutcome::TimedOut { .. }),
        "got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Roles across fork/exec/threads, end to end
// ---------------------------------------------------------------------------

#[test]
fn a_role_keeps_its_identity_across_fork_exec_and_thread_creation() {
    // runc re-execs itself as `runc init` and, being a Go binary, spawns OS
    // threads whose parent pointer refers to the wrong process. Every one of
    // these must log as `victim`.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(101, 100, 9999, "runc")) // CLONE_THREAD sibling
        .task(task(150, 150, 100, "runc:[2:INIT]")) // fork + exec
        .hit(101, "chdir")
        .hit(150, "mount")
        .exit(101)
        .exit(150)
        .exit(100);

    let mut engine = Engine::new(victim_only_config(), backend);
    engine.run().expect("engine run");

    let log = engine.canonical_log().render();
    for line in log.lines().skip(1) {
        assert!(line.contains("\tvictim/"), "misattributed: {line}");
    }
    assert!(
        log.contains("mount"),
        "the re-exec'd child was never enforced"
    );
}

#[test]
fn pool_members_are_logged_with_their_member_index() {
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(200, 200, 1, "racer"))
        .task(task(201, 201, 1, "racer"))
        .hit(200, "symlink")
        .hit(201, "rename")
        .exit(100)
        .exit(200)
        .exit(201);

    let mut engine = Engine::new(
        discovery_config(r#"{ "type": "pos", "seed": 2 }"#),
        backend,
    );
    engine.run().expect("engine run");

    let log = engine.canonical_log().render();
    assert!(log.contains("racer#0"), "log:\n{log}");
    assert!(log.contains("racer#1"), "log:\n{log}");
}

#[test]
fn the_debug_log_carries_pids_that_the_canonical_log_does_not() {
    let mut engine = Engine::new(
        discovery_config(r#"{ "type": "pos", "seed": 1 }"#),
        scenario(),
    );
    engine.run().expect("engine run");

    assert!(engine.debug_log().render().contains("pid=100"));
    assert!(!engine.canonical_log().render().contains("100"));
}

// ---------------------------------------------------------------------------
// POS (plan Phases 1-4)
// ---------------------------------------------------------------------------

/// Both roles `one`, for POS tests that must finish.
fn pos_one_config(seed: u64) -> ScenarioConfig {
    config_with_roles(
        r#"{ "id": "victim", "comm": "runc" }, { "id": "racer", "comm": "racer" }"#,
        &format!(r#"{{ "type": "pos", "seed": {seed} }}"#),
    )
}

/// The same scripted scenario, with the two tasks registered in either order so
/// the stub backend emits their events in a different order.
fn pos_arrival_scenario(racer_first: bool) -> StubBackend {
    let mut b = StubBackend::new();
    if racer_first {
        b = b.task(task(200, 200, 1, "racer"));
        b = b.task(task(100, 100, 1, "runc"));
    } else {
        b = b.task(task(100, 100, 1, "runc"));
        b = b.task(task(200, 200, 1, "racer"));
    }
    b.hit(100, "chdir")
        .hit(100, "openat")
        .hit(100, "mount")
        .exit(100)
        .hit(200, "symlink")
        .hit(200, "rename")
        .exit(200)
}

#[test]
fn pos_runs_to_completion_and_records_every_release() {
    let (outcome, log, steps) = run(pos_one_config(1));
    assert_eq!(outcome, RunOutcome::Completed);
    assert_eq!(steps.len(), 5, "log:\n{log}");
}

#[test]
fn pos_with_the_same_seed_produces_the_same_canonical_log() {
    let (_, a, _) = run(pos_one_config(20261001));
    let (_, b, _) = run(pos_one_config(20261001));
    assert_eq!(a, b);
}

#[test]
fn pos_decisions_do_not_depend_on_task_arrival_order() {
    // Canonicalisation + the full readout make the first decision a function
    // of the ready *set*, and keyed priorities keep every later decision off
    // arrival order (plan Phase 2, section 14-A for POS).
    let run_with = |racer_first: bool| {
        let mut engine = Engine::new(pos_one_config(1234), pos_arrival_scenario(racer_first));
        assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
        (
            engine.canonical_log().render(),
            engine.decision_trace().to_vec(),
        )
    };
    assert_eq!(run_with(false), run_with(true));
}

#[test]
fn same_thread_group_hits_are_each_a_decision() {
    // Two threads of one thread group each reach a checkpoint. Seccomp holds
    // only the calling thread, so both are real ready entries and both are
    // recorded.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(101, 100, 1, "runc"))
        .hit(100, "chdir")
        .hit(101, "openat")
        .exit(101)
        .exit(100);
    let mut engine = Engine::new(victim_only_config(), backend);
    engine.run().expect("engine run");

    let log = engine.canonical_log().render();
    let victim_lines = log.lines().filter(|l| l.contains("\tvictim/")).count();
    assert_eq!(victim_lines, 2, "chdir + openat, log:\n{log}");
    assert!(
        log.contains("openat"),
        "the sibling hit was dropped:\n{log}"
    );
}

#[test]
fn occurrence_counts_increment_per_role_and_checkpoint() {
    use scx_crfuzz::checkpoint::CheckpointId;
    use scx_crfuzz::role::RoleId;
    use scx_crfuzz::role::RoleRef;

    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .hit(100, "chdir")
        .hit(100, "openat")
        .hit(100, "chdir")
        .exit(100);
    let mut engine = Engine::new(victim_only_config(), backend);
    engine.run().expect("engine run");

    let victim = RoleRef::one(RoleId(0));
    assert_eq!(
        engine.occurrence_count(victim, &CheckpointId::new("chdir")),
        2,
        "chdir was hit twice"
    );
    assert_eq!(
        engine.occurrence_count(victim, &CheckpointId::new("openat")),
        1
    );
}

// ---------------------------------------------------------------------------
// The full readout: decide only with every thread at rest
// ---------------------------------------------------------------------------

/// `role/thread\tcheckpoint` per recorded release, in order.
fn releases(engine: &Engine<StubBackend>) -> Vec<String> {
    engine
        .canonical_log()
        .render()
        .lines()
        .skip(1)
        .map(|l| l.split('\t').skip(1).collect::<Vec<_>>().join("\t"))
        .collect()
}

#[test]
fn pos_waits_for_the_released_thread_before_choosing_again() {
    // The victim works for a few polls between openat and mount, reaching no
    // checkpoint.
    // Whenever POS releases the victim's openat first, the next decision must
    // be made over a ready set that already holds the victim's mount:
    // choosing before it returns would release the racer while openat may
    // still be running. POS may still pick the racer -- from a full set.
    let mut exercised = 0;
    for seed in 0..32 {
        let backend = StubBackend::new()
            .task(task(100, 100, 1, "runc"))
            .task(task(200, 200, 1, "racer"))
            .hit(100, "openat")
            .state(100, ThreadStateKind::WakeStart, 0)
            .state(100, ThreadStateKind::WakeDone, 0)
            .hit(100, "mount")
            .exit(100)
            .hit(200, "rename")
            .exit(200);
        let mut engine = Engine::new(one_racer_config(seed), backend);
        engine.run().expect("run");
        if releases(&engine).first().map(String::as_str) == Some("victim/t0\topenat") {
            exercised += 1;
            let trace = engine.decision_trace();
            assert!(
                trace[1].contains("victim/t0@mount"),
                "seed {seed} chose again before the victim returned: {trace:?}"
            );
        }
    }
    assert!(exercised > 0, "no seed released the victim's openat first");
}

#[test]
fn no_decision_is_taken_while_a_thread_is_still_running() {
    // The racer runs (and is woken while running) for several polls after the
    // victim has parked. The first decision must wait for it.
    let backend = StubBackend::new()
        .spawn(200)
        .task(task(100, 100, 1, "runc"))
        .hit(100, "openat")
        .exit(100)
        .task(task(200, 200, 1, "racer"))
        .state(200, ThreadStateKind::WakeStart, 0)
        .state(200, ThreadStateKind::WakeDone, 0)
        .state(200, ThreadStateKind::WakeStart, 0)
        .state(200, ThreadStateKind::WakeDone, 0)
        .hit(200, "rename")
        .exit(200);
    let mut engine = Engine::new(one_racer_config(1), backend);
    assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
    assert_eq!(
        engine.decision_trace()[0],
        "victim/t0@openat,racer/t0@rename",
        "{:?}",
        engine.decision_trace()
    );
}

#[test]
fn no_decision_is_taken_between_an_early_wake_start_and_its_wake_done() {
    // The racer's wakeup starts before the sleep it ends is reported (the
    // early-`sched_waking` race): asleep, but not at rest.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .hit(100, "openat")
        .exit(100)
        .task(task(200, 200, 1, "racer"))
        .state(200, ThreadStateKind::WakeStart, 0)
        .state(200, ThreadStateKind::Asleep, 1)
        .state(200, ThreadStateKind::WakeDone, 0)
        .hit(200, "rename")
        .exit(200);
    let mut engine = Engine::new(one_racer_config(1), backend);
    assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
    assert_eq!(
        engine.decision_trace()[0],
        "victim/t0@openat,racer/t0@rename",
        "decided while the racer was mid-wakeup: {:?}",
        engine.decision_trace()
    );
}

#[test]
fn a_blocked_thread_does_not_hold_up_the_others_and_ends_deadlocked() {
    // The racer appears and then blocks somewhere invisible forever.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(200, 200, 1, "racer"))
        .hit(100, "openat")
        .exit(100)
        .state(200, ThreadStateKind::Asleep, 1);
    let mut engine = Engine::new(one_racer_config(1), backend);
    let outcome = engine.run().expect("run");
    assert_eq!(releases(&engine), ["victim/t0\topenat"]);
    let RunOutcome::Deadlocked { threads } = outcome else {
        panic!("expected Deadlocked, got {outcome:?}")
    };
    assert_eq!(threads.len(), 1, "{threads:?}");
    assert!(
        threads[0].starts_with("racer/t0 tid 200 (") && threads[0].contains("Blocked"),
        "{threads:?}"
    );
}

#[test]
fn decisions_beside_a_timed_sleeper_are_counted_and_it_is_waited_for() {
    // The racer sleeps with a timeout the whole run (a tid with no `/proc`
    // entry, so the closed backend finds it gone at the end).
    const RACER: i32 = 2_000_000_000;
    let script = || {
        StubBackend::new()
            .task(task(100, 100, 1, "runc"))
            .task(task(RACER, RACER, 1, "racer"))
            .state(RACER, ThreadStateKind::Asleep, 1)
            .hit(100, "openat")
            .hit(100, "mount")
            .exit(100)
    };
    let mut timed = Engine::new(one_racer_config(1), script().timed_sleeper(RACER));
    assert_eq!(timed.run().expect("run"), RunOutcome::Completed);
    assert_eq!(timed.decision_trace().len(), 2);
    assert_eq!(timed.timed_sleep_decisions(), 2);

    // Without the timeout the racer can never wake: once the victim is
    // done, nothing can change.
    let mut untimed = Engine::new(one_racer_config(1), script());
    let outcome = untimed.run().expect("run");
    assert!(matches!(outcome, RunOutcome::Deadlocked { .. }), "{outcome:?}");
    assert_eq!(untimed.decision_trace().len(), 2);
    assert_eq!(untimed.timed_sleep_decisions(), 0);
}

#[test]
fn a_sleeper_that_wakes_after_the_readout_defers_the_decision() {
    // The racer is in a timed sleep at the first readout, but its timer fires
    // after the last drain: it wakes and parks before the decision. The probe
    // sees its records, so the engine reads them and decides over both.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(200, 200, 1, "racer"))
        .state(200, ThreadStateKind::Asleep, 1)
        .state(200, ThreadStateKind::WakeStart, 0)
        .state(200, ThreadStateKind::WakeDone, 0)
        .hit(200, "openat")
        .exit(200)
        .late(200, 5)
        .hit(100, "openat")
        .exit(100)
        .timed_sleeper(200);
    let mut engine = Engine::new(one_racer_config(1), backend);
    assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
    let mut first: Vec<&str> = engine.decision_trace()[0].split(',').collect();
    first.sort_unstable();
    assert_eq!(first, ["racer/t0@openat", "victim/t0@openat"]);
    assert_eq!(engine.decision_trace().len(), 2);
    assert_eq!(engine.timed_sleep_decisions(), 0, "no decision had a sleeper");
}

#[test]
fn a_released_thread_s_exit_clears_the_wait() {
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .task(task(101, 100, 1, "runc"))
        .hit(101, "openat")
        .exit(101)
        .exit(100);
    let mut engine = Engine::new(victim_only_config(), backend);
    assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
}

#[test]
fn a_signal_interrupted_park_is_dropped_and_its_re_park_accepted() {
    // The victim parks, a signal wakes it out of the seccomp wait (its handle
    // is dead), and it parks again. The racer is still running throughout, so
    // no decision can see the dead handle.
    let backend = StubBackend::new()
        .task(task(100, 100, 1, "runc"))
        .hit(100, "openat")
        .parked(100, ThreadStateKind::WakeStart, 0)
        .parked(100, ThreadStateKind::WakeDone, 0)
        .hit(100, "openat")
        .exit(100)
        .task(task(200, 200, 1, "racer"))
        .state(200, ThreadStateKind::WakeStart, 0)
        .state(200, ThreadStateKind::WakeDone, 0)
        .state(200, ThreadStateKind::WakeStart, 0)
        .state(200, ThreadStateKind::WakeDone, 0)
        .hit(200, "rename")
        .exit(200);
    let mut engine = Engine::new(one_racer_config(1), backend);
    assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
    assert_eq!(engine.decision_trace()[0], "victim/t0@openat,racer/t0@rename");
    let released = &engine.backend().released;
    assert!(!released.contains(&NotifyHandle(0)), "the dead handle: {released:?}");
    assert!(released.contains(&NotifyHandle(1)), "the re-park: {released:?}");
}

/// A file conflict key for `name`; distinct names are distinct objects.
fn key(name: &str, dir: Direction) -> ConflictKey {
    let ino = name.bytes().map(u64::from).sum();
    ConflictKey::file(FileToken::leaf(10, ino, name, 10, ino), dir)
}

#[test]
fn an_event_whose_recaptured_keys_stop_conflicting_is_not_redrawn() {
    // The victim's openat parks conflicting with the racer's rename; by the
    // first decision its fresh keys name another file. Every decision must
    // then be the one taken when the two never conflicted at all.
    let script = |victim_keys: Vec<ConflictKey>, fresh: Option<Vec<ConflictKey>>| {
        let mut b = StubBackend::new()
            .task(task(100, 100, 1, "runc"))
            .task(task(200, 200, 1, "racer"))
            .hit_keys(100, "openat", None, victim_keys)
            .hit_keys(100, "mount", None, vec![key("other", Direction::Resolve)])
            .exit(100)
            .hit_keys(200, "rename", None, vec![key("target", Direction::Rebind)])
            .hit_keys(200, "rename", None, vec![key("target", Direction::Rebind)])
            .exit(200);
        if let Some(fresh) = fresh {
            b = b.recaptured(NotifyHandle(0), Some(fresh));
        }
        b
    };
    let trace = |seed, b| {
        let mut engine = Engine::new(one_racer_config(seed), b);
        assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
        engine.decision_trace().to_vec()
    };
    let target = vec![key("target", Direction::Resolve)];
    let other = vec![key("other", Direction::Resolve)];
    let mut sensitive = false;
    for seed in 0..64 {
        let independent = trace(seed, script(other.clone(), None));
        let recaptured = trace(seed, script(target.clone(), Some(other.clone())));
        assert_eq!(recaptured, independent, "seed {seed}");
        sensitive |= trace(seed, script(target.clone(), None)) != independent;
    }
    assert!(sensitive, "no seed's trace depends on the conflict at all");
}

#[test]
fn every_shipped_example_config_parses() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for entry in std::fs::read_dir(&dir).expect("examples dir") {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = std::fs::read_to_string(&path).unwrap();
            ScenarioConfig::from_json(&text)
                .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
        }
    }
}

#[test]
fn a_thread_that_exits_without_a_hit_does_not_shift_its_siblings_paths() {
    // 101 is a helper thread of the victim that dies before doing anything.
    let backend = StubBackend::new()
        .spawn(100)
        .created(100, 101, 100)
        .created(100, 102, 100)
        .task(task(100, 100, 1, "runc"))
        .task(task(102, 100, 1, "runc"))
        .task(task(200, 200, 1, "racer"))
        .exit(101)
        .hit(102, "openat")
        .hit(200, "rename")
        .exit(102)
        .exit(200)
        .exit(100);
    let mut engine = Engine::new(one_racer_config(1), backend);
    engine.run().expect("run");
    let trace = engine.decision_trace().join("\n");
    assert!(trace.contains("victim/t0.1@openat"), "{trace}");
}

/// Two roles of three threads each: the leader creates two threads, every
/// thread is woken once while running and walks its own checkpoints, with
/// conflicting and independent keys, plus a helper no role claims.
///
/// With `asleep_first`, each park's `Asleep` arrives ahead of its hit.
fn interleaved(shuffle: u64, asleep_first: bool) -> StubBackend {
    let target = |dir| vec![key("target", dir)];
    let own = |name: &str| vec![key(name, Direction::Rebind)];
    let mut b = StubBackend::new().spawn(100).spawn(200).spawn(900);
    if asleep_first {
        b = b.asleep_first();
    }
    for (leader, comm) in [(100, "runc"), (200, "racer")] {
        b = b
            .created(leader, leader + 1, leader)
            .created(leader, leader + 2, leader);
        for tid in leader..leader + 3 {
            b = b
                .task(task(tid, leader, 1, comm))
                .state(tid, ThreadStateKind::WakeStart, 0)
                .state(tid, ThreadStateKind::WakeDone, 0);
        }
    }
    b.hit_keys(100, "newfstatat", None, target(Direction::Resolve))
        .hit_keys(100, "openat", None, target(Direction::Resolve))
        .exit(100)
        .hit_keys(101, "openat", None, own("v1"))
        .hit_keys(101, "openat", None, target(Direction::Resolve))
        .exit(101)
        .hit_keys(102, "mount", None, own("v2"))
        .exit(102)
        .hit_keys(200, "rename", None, target(Direction::Rebind))
        .exit(200)
        .hit_keys(201, "rename", None, target(Direction::Rebind))
        .hit_keys(201, "rename", None, own("a1"))
        .exit(201)
        .hit_keys(202, "symlink", None, own("a2"))
        .hit_keys(202, "rename", None, target(Direction::Rebind))
        .exit(202)
        .task(task(900, 900, 1, "sshd"))
        .hit(900, "openat")
        .exit(900)
        .shuffle(shuffle)
}

#[test]
fn the_decisions_do_not_depend_on_cross_thread_record_order() {
    for seed in [1, 7, 20261005] {
        let run = |shuffle, asleep_first| {
            let mut engine =
                Engine::new(one_racer_config(seed), interleaved(shuffle, asleep_first));
            assert_eq!(engine.run().expect("run"), RunOutcome::Completed);
            (
                engine.decision_trace().to_vec(),
                engine.canonical_log().render(),
            )
        };
        let first = run(0, false);
        assert_eq!(
            first.0[0],
            "victim/t0@newfstatat,victim/t0.0@openat,victim/t0.1@mount,\
             racer/t0@rename,racer/t0.0@rename,racer/t0.1@symlink",
            "the first decision sees every thread"
        );
        for shuffle in 1..100 {
            for asleep_first in [false, true] {
                assert_eq!(
                    run(shuffle, asleep_first),
                    first,
                    "seed {seed}, interleaving {shuffle}, asleep first: {asleep_first}"
                );
            }
        }
    }
}

#[test]
fn a_stop_request_ends_the_run_with_an_error() {
    static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
    let mut engine = Engine::new(one_racer_config(1), scenario()).with_stop(&STOP);
    let err = engine.run().unwrap_err().to_string();
    assert!(err.contains("interrupted"), "{err}");
}
