//! Milestone 4 on the real backend. Needs root, a running scx_crfuzz_gated:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::trigger_file;

use scx_crfuzz::backend::GateBackend;
use scx_crfuzz::engine::{run, Decision};
use scx_crfuzz::pos::{EventId, Pos};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn once(seed: u64, a: &Path, b: &Path) -> Vec<Decision> {
    let script = format!("cat {} >/dev/null & cat {} >/dev/null & wait", a.display(), b.display());
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]);
    let mut be = GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut log = Vec::new();
    run(&mut be, &mut Pos::new(seed), None, None, None, None, Duration::from_millis(1), Duration::from_millis(200), deadline, &mut log).unwrap();
    assert!(be.child().wait().unwrap().success());
    log
}

/// Two racing `cat`s (forked: named by creation tree, D4): the engine decides
/// every openat on a complete frontier, a seed fixes the whole decision log,
/// and the seed is what picks which trigger opens first.
#[test]
#[ignore]
fn seed_fixes_trigger_order() {
    let (a, b) = (trigger_file("crfuzz_pos_a"), trigger_file("crfuzz_pos_b"));
    let mut firsts = Vec::new();
    for seed in 0..4 {
        let logs: Vec<Vec<EventId>> = (0..5)
            .map(|_| {
                let log = once(seed, &a, &b);
                // A partial decision is outside the claim (D2).
                assert!(log.iter().all(|d| !d.partial), "seed {seed}: partial decision");
                assert!(log.iter().all(|d| !d.id.thread.starts_with('?')), "seed {seed}: unnamed thread");
                log.into_iter().map(|d| d.id).collect()
            })
            .collect();
        let threads: BTreeSet<&str> = logs[0].iter().map(|id| id.thread.as_str()).collect();
        eprintln!("seed {seed}: {} decisions, threads {threads:?}", logs[0].len());
        assert!(logs.iter().all(|l| l == &logs[0]), "seed {seed}: decision logs differ");
        let trig: Vec<&Path> = logs[0].iter().filter_map(|id| id.path.as_deref()).filter(|&p| p == a || p == b).collect();
        assert_eq!(trig.len(), 2, "both triggers decided");
        firsts.push(if trig[0] == a { a.as_path() } else { b.as_path() });
    }
    eprintln!("first trigger per seed: {firsts:?}");
    assert!(firsts.contains(&a.as_path()) && firsts.contains(&b.as_path()), "the seed never changed the order");
}
