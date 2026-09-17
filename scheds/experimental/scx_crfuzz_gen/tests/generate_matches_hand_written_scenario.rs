// SPDX-License-Identifier: GPL-2.0
//
// Closes the loop between scx_crfuzz_gen and the hand-written scenario it's
// meant to replace the boilerplate of: traces the same victim/racer pair
// scenarios/race_wins.json declares by hand, and checks the generator
// arrives at the same checkpoints.
#![cfg(target_os = "linux")]

use scx_crfuzz_gen::derive::build_config;
use scx_crfuzz_gen::derive::RoleTrace;
use scx_crfuzz_gen::tracer::derive_comm;
use scx_crfuzz_gen::tracer::ProcessTracer;
use scx_crfuzz_gen::tracer::StraceTracer;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

/// scheds/experimental/scx_crfuzz/scenarios/race_wins.json declares exactly
/// these three checkpoints by hand. This test's ground truth.
const EXPECTED_CHECKPOINTS: &[&str] = &["newfstatat", "openat", "renameat"];

#[test]
fn generated_checkpoints_match_the_hand_written_race_wins_scenario() {
    let scenarios_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scx_crfuzz/scenarios");
    let victim_bin = scenarios_dir.join("victim");
    let racer_bin = scenarios_dir.join("racer");
    assert!(
        victim_bin.exists() && racer_bin.exists(),
        "build the fixture first: `cd {} && make`",
        scenarios_dir.display()
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    let secret = dir.path().join("secret");
    let evil = dir.path().join("evil");
    std::fs::write(&target, "BENIGN\n").unwrap();
    std::fs::write(&secret, "SECRET\n").unwrap();
    symlink(&secret, &evil).unwrap();

    let victim_cmd = format!("{} {}", victim_bin.display(), target.display());
    let racer_cmd = format!(
        "{} {} {}",
        racer_bin.display(),
        evil.display(),
        target.display()
    );

    let tracer = StraceTracer;
    let traces = vec![
        RoleTrace {
            name: "victim".into(),
            comm: derive_comm(&victim_cmd).unwrap(),
            events: tracer.trace(&victim_cmd).expect("tracing victim"),
        },
        RoleTrace {
            name: "racer".into(),
            comm: derive_comm(&racer_cmd).unwrap(),
            events: tracer.trace(&racer_cmd).expect("tracing racer"),
        },
    ];

    let config = build_config("toctou-rename-swap", "/crfuzz", 42, &traces).unwrap();
    let mut ids: Vec<_> = config
        .checkpoints
        .iter()
        .map(|c| c.id.as_str().to_string())
        .collect();
    ids.sort();
    assert_eq!(ids, EXPECTED_CHECKPOINTS);
}
