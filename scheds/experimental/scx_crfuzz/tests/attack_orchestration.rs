// SPDX-License-Identifier: GPL-2.0
//
//! End-to-end runs of the attacker/oracle orchestration (`PolicyType::AutoAttack`)
//! against `StubBackend`.
//!
//! The depth-2, one-attacker/one-victim shape: at every use-shaped checkpoint
//! the single victim role hits, the engine runs the configured attacker on the
//! path the syscall resolved, releases the victim, and rules on the window with
//! the oracle at the victim's next hold or exit. `StubBackend` holds nothing
//! real, so these cover the *orchestration* -- ordering, per-window invocation,
//! path propagation, failure handling -- not the seccomp capture that produces
//! the path on a real target.

use scx_crfuzz::backend::StubBackend;
use scx_crfuzz::config::ScenarioConfig;
use scx_crfuzz::engine::RunOutcome;
use scx_crfuzz::role::TaskInfo;
use scx_crfuzz::Engine;
use std::io::Write;

const CGROUP: &str = "/sys/fs/cgroup/crfuzz";

fn task(pid: i32, comm: &str) -> TaskInfo {
    TaskInfo {
        pid,
        tgid: pid,
        parent_tgid: 1,
        comm: comm.to_string(),
        cgroup: format!("{CGROUP}/run0"),
    }
}

/// Write an attacker script that appends `<checkpoint> <path>` to `log_path`
/// for each invocation, and return its filesystem path. It reads the checkpoint
/// and path from the environment the engine sets (`CRFUZZ_CHECKPOINT`,
/// `CRFUZZ_TARGET_PATH`), so it also exercises that the engine exports them.
fn write_attacker(dir: &std::path::Path, log_path: &std::path::Path) -> std::path::PathBuf {
    let script = dir.join("attacker.sh");
    let mut f = std::fs::File::create(&script).unwrap();
    writeln!(
        f,
        "#!/bin/sh\nprintf '%s %s\\n' \"$CRFUZZ_CHECKPOINT\" \"$CRFUZZ_TARGET_PATH\" >> '{}'",
        log_path.display()
    )
    .unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script
}

fn auto_attack_config(attacker: &std::path::Path) -> ScenarioConfig {
    ScenarioConfig::from_json(&format!(
        r#"{{
            "scenario_id": "auto-attack-toy",
            "cgroup": "{CGROUP}",
            "roles": [{{ "id": "victim", "comm": "runc" }}],
            "policy": {{ "type": "auto_attack", "seed": 0 }},
            "attack": {{ "argv": ["{}"] }}
        }}"#,
        attacker.display()
    ))
    .expect("auto_attack config should parse")
}

#[test]
fn the_attacker_runs_once_before_every_use_on_that_use_s_path() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("attacks.log");
    let attacker = write_attacker(dir.path(), &log);

    // The victim hits two use-shaped checkpoints, each carrying the path the
    // syscall resolved, then exits.
    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "openat", Some("/victim/secret"))
        .hit_path(100, "mount", Some("/victim/rootfs"))
        .exit(100);

    let mut engine = Engine::new(auto_attack_config(&attacker), backend);
    let outcome = engine.run().expect("engine run");
    assert_eq!(outcome, RunOutcome::Completed);

    // The attacker ran once per use, in order, on that use's path.
    let recorded = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = recorded.lines().collect();
    assert_eq!(
        lines,
        vec!["openat /victim/secret", "mount /victim/rootfs"],
        "attacker should run once before each use, on that use's captured path"
    );
}

#[test]
fn the_oracle_rules_on_one_window_per_use() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("attacks.log");
    let attacker = write_attacker(dir.path(), &log);

    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "openat", Some("/a"))
        .hit_path(100, "chdir", Some("/b"))
        .hit_path(100, "mount", Some("/c"))
        .exit(100);

    let mut engine = Engine::new(auto_attack_config(&attacker), backend);
    engine.run().expect("engine run");

    // Three use-shaped checkpoints -> three observed windows. The paths are
    // fictional, so the oracle finds no pre-attack identity to diff and
    // none are violations.
    let verdicts = engine.oracle_verdicts();
    assert_eq!(verdicts.len(), 3, "one oracle observation per use window");
    assert!(
        verdicts.iter().all(|(_, v)| !v.is_violation()),
        "nothing was substituted, so the oracle must not fire"
    );
    // The observed windows are the recorded release steps, in order.
    let steps: Vec<u64> = verdicts.iter().map(|(idx, _)| *idx).collect();
    assert_eq!(steps, vec![0, 1, 2]);
}

#[test]
fn the_run_projects_to_a_replayable_schedule() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("attacks.log");
    let attacker = write_attacker(dir.path(), &log);

    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "openat", Some("/a"))
        .hit_path(100, "mount", Some("/b"))
        .exit(100);

    let mut engine = Engine::new(auto_attack_config(&attacker), backend);
    engine.run().expect("engine run");

    // Every release the orchestration made is on the canonical log, so the run
    // projects to a schedule that replays it.
    let steps = engine.canonical_log().project_to_steps();
    let rendered: Vec<String> = steps
        .iter()
        .map(|s| format!("{}@{}", s.role, s.until))
        .collect();
    assert_eq!(
        rendered,
        vec!["victim@openat", "victim@mount", "victim@exit"]
    );
}

#[test]
fn a_failing_attacker_primitive_does_not_derail_the_run() {
    // An attacker that cannot even be spawned is a setup failure (ACTION-FAILED),
    // never a lost race and never a finding: the victim is still released and
    // the run still completes.
    let cfg = ScenarioConfig::from_json(&format!(
        r#"{{
            "scenario_id": "auto-attack-toy",
            "cgroup": "{CGROUP}",
            "roles": [{{ "id": "victim", "comm": "runc" }}],
            "policy": {{ "type": "auto_attack", "seed": 0 }},
            "attack": {{ "argv": ["/nonexistent/attacker/binary", "{{path}}"] }}
        }}"#
    ))
    .unwrap();

    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "openat", Some("/a"))
        .exit(100);

    let mut engine = Engine::new(cfg, backend);
    let outcome = engine.run().expect("engine run");
    assert_eq!(outcome, RunOutcome::Completed);
    // The window was still observed.
    assert_eq!(engine.oracle_verdicts().len(), 1);
}

#[test]
fn the_oracle_fires_when_the_attacker_changes_the_path_type() {
    // The real oracle end to end: the engine snapshots a regular file before
    // the attacker runs, the attacker replaces it with a symlink, and the
    // oracle reports the type change when the window is observed at exit.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let secret = dir.path().join("secret");
    std::fs::write(&target, b"BENIGN").unwrap();
    std::fs::write(&secret, b"SECRET").unwrap();

    let attacker = dir.path().join("swap.sh");
    let mut f = std::fs::File::create(&attacker).unwrap();
    writeln!(
        f,
        "#!/bin/sh\nrm -f \"$CRFUZZ_TARGET_PATH\"\nln -s '{}' \"$CRFUZZ_TARGET_PATH\"",
        secret.display()
    )
    .unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&attacker, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "openat", Some(target.to_str().unwrap()))
        .exit(100);

    let mut engine = Engine::new(auto_attack_config(&attacker), backend);
    let outcome = engine.run().expect("engine run");
    assert_eq!(outcome, RunOutcome::Completed);

    let verdicts = engine.oracle_verdicts();
    assert_eq!(verdicts.len(), 1, "one window observed");
    assert!(
        verdicts[0].1.is_violation(),
        "a file -> symlink substitution must be a finding, got {:?}",
        verdicts[0].1
    );
}

#[test]
fn the_oracle_fires_on_a_same_type_directory_exchange() {
    // Directory -> directory: type is preserved, so only the identity can tell
    // it apart. This is the runc-rootfs case the type-only oracle missed.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("rootfs");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("marker"), b"original").unwrap();

    let attacker = dir.path().join("swap.sh");
    let mut f = std::fs::File::create(&attacker).unwrap();
    writeln!(
        f,
        "#!/bin/sh\nrm -rf \"$CRFUZZ_TARGET_PATH\"\nmkdir \"$CRFUZZ_TARGET_PATH\"",
    )
    .unwrap();
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&attacker, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "mount", Some(target.to_str().unwrap()))
        .exit(100);

    let mut engine = Engine::new(auto_attack_config(&attacker), backend);
    engine.run().expect("engine run");

    let verdicts = engine.oracle_verdicts();
    assert_eq!(verdicts.len(), 1, "one window observed");
    assert!(
        verdicts[0].1.is_violation(),
        "a directory exchange must be a finding, got {:?}",
        verdicts[0].1
    );
}
