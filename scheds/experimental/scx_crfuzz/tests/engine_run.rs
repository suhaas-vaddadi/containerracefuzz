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
//!   construction -- seccomp user-notify, `ops.dispatch` declining to place a
//!   task. `StubBackend` holds nothing, so nothing here says anything about it.
//! - **Section 14-A.** The stub scripts the order in which tasks reach their
//!   checkpoints, so the determinism tests below show only that `decide()` is a
//!   pure function of `(seed, ready-set-sequence)`. Whether the ready-set
//!   sequence is *itself* reproducible under real OS scheduling is a separate
//!   question these tests are structurally incapable of answering -- and one
//!   that has since been answered against real processes, in the negative:
//!   roughly one run in a few hundred diverges. See the crate docs, "Section
//!   14-A is no longer open". A green suite here is not evidence of end-to-end
//!   reproducibility and must not be cited as such.

use scx_crfuzz::backend::StubBackend;
use scx_crfuzz::config::DivergencePolicy;
use scx_crfuzz::config::ScenarioConfig;
use scx_crfuzz::engine::RunOutcome;
use scx_crfuzz::role::TaskInfo;
use scx_crfuzz::Engine;

const CGROUP: &str = "/sys/fs/cgroup/crfuzz";

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
        .hit(100, "stat")
        .hit(100, "openat")
        .hit(100, "mount")
        .exit(100)
        .hit(200, "symlink")
        .hit(200, "rename")
        .exit(200)
}

fn discovery_config(policy: &str) -> ScenarioConfig {
    ScenarioConfig::from_json(&format!(
        r#"{{
            "scenario_id": "toy-victim-racer",
            "cgroup": "{CGROUP}",
            "roles": [
                {{ "id": "victim", "comm": "runc" }},
                {{ "id": "racer", "comm": "racer", "cardinality": "pool" }}
            ],
            "policy": {policy}
        }}"#
    ))
    .expect("discovery config should parse")
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
    let (outcome, log, steps) = run(discovery_config(r#"{ "type": "random_walk", "seed": 1 }"#));
    assert_eq!(outcome, RunOutcome::Completed);
    // Five checkpoint hits plus two exits.
    assert_eq!(steps.len(), 7, "log:\n{log}");
    assert!(log.starts_with("# scenario toy-victim-racer\n"));
}

#[test]
fn nothing_is_released_before_the_barrier_completes() {
    // The victim reaches a checkpoint while the `one` role it is waiting on
    // has not appeared. It must be held, not released.
    let backend = StubBackend::new()
        .task(task(200, 200, 1, "racer"))
        .hit(200, "symlink");
    let config = discovery_config(r#"{ "type": "random_walk", "seed": 1 }"#);
    let mut engine = Engine::new(config, backend);
    let outcome = engine.run().expect("engine run");

    assert!(
        engine.canonical_log().is_empty(),
        "the barrier was never satisfied, so nothing may have been enforced"
    );
    assert!(matches!(outcome, RunOutcome::TimedOut { .. }));
}

#[test]
fn a_pool_role_alone_does_not_satisfy_the_barrier_but_does_not_block_it_either() {
    // Section 5: `all_roles_seen()` is evaluated over `one` roles only.
    // The full scenario completes even though no fixed number of pool members
    // was ever declared or waited for.
    let (outcome, _, steps) = run(discovery_config(r#"{ "type": "random_walk", "seed": 3 }"#));
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
        .hit(100, "stat")
        .exit(100)
        .exit(900);
    let mut engine = Engine::new(
        discovery_config(r#"{ "type": "random_walk", "seed": 1 }"#),
        backend,
    );
    engine.run().expect("engine run");

    let log = engine.canonical_log().render();
    assert!(!log.contains("sshd"));
    assert_eq!(
        engine.canonical_log().len(),
        2,
        "only the victim's stat and exit: got\n{log}"
    );
}

// ---------------------------------------------------------------------------
// Determinism (section 10.1)
// ---------------------------------------------------------------------------

#[test]
fn random_walk_with_the_same_seed_produces_a_byte_identical_canonical_log() {
    let cfg = r#"{ "type": "random_walk", "seed": 20260914 }"#;
    let (_, a, _) = run(discovery_config(cfg));
    let (_, b, _) = run(discovery_config(cfg));
    assert_eq!(a, b);
}

#[test]
fn pct_with_the_same_seed_produces_a_byte_identical_canonical_log() {
    let cfg = r#"{ "type": "pct", "seed": 77, "params": { "d": 3, "k": 7 } }"#;
    let (_, a, _) = run(discovery_config(cfg));
    let (_, b, _) = run(discovery_config(cfg));
    assert_eq!(a, b);
}

#[test]
fn different_seeds_explore_different_interleavings() {
    // Not a guarantee for any particular pair of seeds -- but if no seed ever
    // changed the interleaving, discovery mode would not be exploring anything.
    let logs: Vec<String> = (0..24)
        .map(|seed| {
            run(discovery_config(&format!(
                r#"{{ "type": "random_walk", "seed": {seed} }}"#
            )))
            .1
        })
        .collect();
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
    let discovery =
        discovery_config(r#"{ "type": "pct", "seed": 4242, "params": { "d": 3, "k": 7 } }"#);
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
    let discovery = discovery_config(r#"{ "type": "random_walk", "seed": 9 }"#);
    let (_, discovered, steps) = run(discovery.clone());

    let json = discovery
        .as_replay_with(steps)
        .to_json()
        .expect("serialize");
    let reparsed = ScenarioConfig::from_json(&json).expect("the projection must be a valid config");
    assert!(!reparsed.is_discovery());

    let (_, replayed, _) = run(reparsed);
    assert_eq!(replayed, discovered);
}

#[test]
fn replaying_a_projection_is_insensitive_to_the_seed_that_produced_it() {
    // Once projected, the schedule is the authority: nothing about the original
    // policy's randomness survives into replay.
    let a = discovery_config(r#"{ "type": "random_walk", "seed": 11 }"#);
    let (_, log_a, steps_a) = run(a.clone());
    let b = discovery_config(r#"{ "type": "random_walk", "seed": 12 }"#);

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
                {{ "id": "stat", "kind": "syscall", "target": "stat" }},
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
            { "role": "victim", "until": "stat" },
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
            { "role": "victim", "until": "stat" },
            { "role": "victim", "until": "never_happens" },
            { "role": "racer#0", "until": "symlink" }
        ]"#,
        DivergencePolicy::Skip,
    );
    let mut engine = Engine::new(cfg, scenario());
    let outcome = engine.run().expect("engine run");

    assert_eq!(outcome, RunOutcome::Completed);
    let log = engine.canonical_log().render();
    assert!(log.contains("victim\tstat"), "log:\n{log}");
    assert!(log.contains("racer#0\tsymlink"), "log:\n{log}");
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
            { "role": "victim", "until": "mount" },
            { "role": "victim", "until": "exit" }
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
    assert!(
        matches!(outcome, RunOutcome::TimedOut { .. }),
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
            { "role": "victim", "until": "stat" },
            { "role": "victim", "until": "openat" },
            { "role": "victim", "until": "mount" }
        ]"#,
        DivergencePolicy::Block,
    );
    let mut engine = Engine::new(cfg, scenario());
    assert_eq!(engine.run().expect("engine run"), RunOutcome::Completed);
    assert_eq!(
        engine.canonical_log().render(),
        "# scenario toy-victim-racer\n0\tvictim\tstat\n1\tvictim\topenat\n2\tvictim\tmount\n"
    );
}

#[test]
fn a_schedule_left_unfinished_by_the_scenario_does_not_report_completed() {
    let cfg = replay_config(
        r#"[
            { "role": "victim", "until": "stat" },
            { "role": "victim", "until": "never_happens" }
        ]"#,
        DivergencePolicy::Block,
    );
    let mut engine = Engine::new(cfg, scenario());
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
        .hit(101, "stat")
        .hit(150, "mount")
        .exit(150)
        .exit(100);

    let mut engine = Engine::new(
        discovery_config(r#"{ "type": "random_walk", "seed": 1 }"#),
        backend,
    );
    engine.run().expect("engine run");

    let log = engine.canonical_log().render();
    for line in log.lines().skip(1) {
        assert!(line.contains("\tvictim\t"), "misattributed: {line}");
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
        .exit(100);

    let mut engine = Engine::new(
        discovery_config(r#"{ "type": "random_walk", "seed": 2 }"#),
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
        discovery_config(r#"{ "type": "random_walk", "seed": 1 }"#),
        scenario(),
    );
    engine.run().expect("engine run");

    assert!(engine.debug_log().render().contains("pid=100"));
    assert!(!engine.canonical_log().render().contains("100"));
}
