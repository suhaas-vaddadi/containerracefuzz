// SPDX-License-Identifier: GPL-2.0
//
//! One run of the sweep against `StubBackend`: window keys, the single
//! attacked window, and the lightweight oracle -- an object diff of the paths
//! the victim's windows resolved. The stub holds nothing real, so these cover
//! the engine, not the seccomp capture that produces paths on a real target.

use scx_crfuzz::backend::StubBackend;
use scx_crfuzz::config::ScenarioConfig;
use scx_crfuzz::engine::RunOutcome;
use scx_crfuzz::role::TaskInfo;
use scx_crfuzz::Engine;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn task(pid: i32, comm: &str) -> TaskInfo {
    TaskInfo {
        pid,
        tgid: pid,
        parent_tgid: 1,
        comm: comm.to_string(),
        cgroup: "/crfuzz/run0".to_string(),
    }
}

/// An executable shell script at `dir/name` with body `body`.
fn script(dir: &Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.display().to_string()
}

/// An attacker that appends `<checkpoint> <path>` to `log` each time it runs.
fn logging_attacker(dir: &Path, log: &Path) -> String {
    script(
        dir,
        "attacker.sh",
        &format!(
            "printf '%s %s\\n' \"$CRFUZZ_CHECKPOINT\" \"$CRFUZZ_TARGET_PATH\" >> '{}'",
            log.display()
        ),
    )
}

fn config(attacker: &str, at: Option<&str>) -> ScenarioConfig {
    let at = at.map(|w| format!(r#", "at": "{w}""#)).unwrap_or_default();
    ScenarioConfig::from_json(&format!(
        r#"{{
            "cgroup": "/crfuzz",
            "victim": {{ "comm": "runc" }},
            "attack": {{ "argv": ["{attacker}"]{at} }}
        }}"#
    ))
    .unwrap()
}

/// runc hits openat, mount, openat; an unrelated `sh` hits openat in between.
fn backend() -> StubBackend {
    StubBackend::new()
        .task(task(100, "runc"))
        .task(task(200, "sh"))
        .hit_path(100, "openat", Some("/a"))
        .hit_path(200, "openat", Some("/not-the-victim"))
        .hit_path(100, "mount", Some("/m"))
        .hit_path(100, "openat", Some("/b"))
        .exit(100)
        .exit(200)
}

#[test]
fn a_dry_run_lists_every_victim_window_and_attacks_none() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("attacks.log");
    let attacker = logging_attacker(dir.path(), &log);

    let mut engine = Engine::new(config(&attacker, None), backend());
    assert_eq!(engine.run().unwrap(), RunOutcome::Completed);

    let keys: Vec<_> = engine.windows().iter().map(|w| w.key.as_str()).collect();
    assert_eq!(keys, ["openat#0", "mount#0", "openat#1"], "counted per checkpoint");
    assert_eq!(engine.windows()[2].path.as_deref(), Some(Path::new("/b")));
    assert!(!engine.attacked());
    assert!(!log.exists(), "a dry run never runs the attacker");
    assert!(engine.findings().is_empty(), "a dry run diffs nothing");
    assert_eq!(
        engine.backend().released.len(),
        4,
        "every hit, the bystander's included, is released"
    );
}

#[test]
fn only_the_selected_window_is_attacked_on_its_own_path() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("attacks.log");
    let attacker = logging_attacker(dir.path(), &log);

    let mut engine = Engine::new(config(&attacker, Some("openat#1")), backend());
    assert_eq!(engine.run().unwrap(), RunOutcome::Completed);

    assert!(engine.attacked());
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "openat /b\n");
}

#[test]
fn a_window_never_reached_is_reported_as_not_attacked() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("attacks.log");
    let attacker = logging_attacker(dir.path(), &log);

    let mut engine = Engine::new(config(&attacker, Some("mount#5")), backend());
    assert_eq!(engine.run().unwrap(), RunOutcome::Completed);
    assert!(!engine.attacked());
    assert!(!log.exists());
}

#[test]
fn a_failing_attacker_does_not_derail_the_run() {
    let mut engine = Engine::new(
        config("/nonexistent/attacker", Some("mount#0")),
        backend(),
    );
    assert_eq!(engine.run().unwrap(), RunOutcome::Completed);
    assert!(engine.attacked());
    assert!(engine.findings().is_empty(), "a failed primitive is not a finding");
    assert_eq!(engine.windows().len(), 3);
}

#[test]
fn the_oracle_reports_an_object_the_attacked_window_changed() {
    // The victim resolves `obj` at openat#0; the attacker at mount#0 rewrites
    // it. The oracle takes a token of `obj` immediately before and after the
    // attack and reports the change, attributed to the attacked window.
    let dir = tempfile::tempdir().unwrap();
    let obj = dir.path().join("obj");
    std::fs::write(&obj, b"BENIGN").unwrap();
    let attacker = script(
        dir.path(),
        "change.sh",
        &format!("printf CHANGED > '{}'", obj.display()),
    );
    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .hit_path(100, "openat", Some(obj.to_str().unwrap()))
        .hit_path(100, "mount", Some(obj.to_str().unwrap()))
        .exit(100);

    let mut engine = Engine::new(config(&attacker, Some("mount#0")), backend);
    assert_eq!(engine.run().unwrap(), RunOutcome::Completed);

    let findings = engine.findings();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].seen_at, "mount#0");
    assert!(findings[0].reason.contains("changed"), "{findings:?}");
}

#[test]
fn the_oracle_ignores_a_path_the_victim_never_resolved() {
    // `bystander` is resolved only by the non-victim `sh`; the engine never
    // watches it, so the attacker changing it is not a finding.
    let dir = tempfile::tempdir().unwrap();
    let bystander = dir.path().join("bystander");
    std::fs::write(&bystander, b"BENIGN").unwrap();
    let attacker = script(
        dir.path(),
        "change.sh",
        &format!("printf CHANGED > '{}'", bystander.display()),
    );
    let backend = StubBackend::new()
        .task(task(100, "runc"))
        .task(task(200, "sh"))
        .hit_path(200, "openat", Some(bystander.to_str().unwrap()))
        .hit_path(100, "openat", Some("/a"))
        .hit_path(100, "mount", Some("/m"))
        .exit(100)
        .exit(200);

    let mut engine = Engine::new(config(&attacker, Some("mount#0")), backend);
    engine.run().unwrap();
    assert!(engine.findings().is_empty(), "{:?}", engine.findings());
}
