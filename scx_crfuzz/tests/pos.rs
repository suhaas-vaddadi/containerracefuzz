//! POS on the real backend: a seed fixes the decision log. Needs root, a
//! running `scx_crfuzz gated`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::trigger_file;

use scx_crfuzz::backend::GateBackend;
use scx_crfuzz::engine::{run, Decision};
use scx_crfuzz::name::EventId;
use scx_crfuzz::pos::Pos;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn once(seed: u64, a: &Path, b: &Path) -> Vec<Decision> {
    let script = format!("cat {} >/dev/null & cat {} >/dev/null & wait", a.display(), b.display());
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]);
    let mut be = GateBackend::spawn(cmd).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut log = Vec::new();
    run(&mut be, &mut Pos::new(seed), None, None, None, None, deadline, &mut log).unwrap();
    assert!(be.child().wait().unwrap().success());
    log
}

/// Two racing `cat`s (forked: named by creation tree): the engine decides
/// every path syscall on a complete frontier, a seed fixes the whole decision log,
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
                // A partial decision is outside the determinism claim.
                assert!(log.iter().all(|d| !d.partial), "seed {seed}: partial decision");
                assert!(log.iter().all(|d| !d.id.process.starts_with('?')), "seed {seed}: unnamed process");
                log.into_iter().map(|d| d.id).collect()
            })
            .collect();
        let procs: BTreeSet<&str> = logs[0].iter().map(|id| id.process.as_str()).collect();
        eprintln!("seed {seed}: {} decisions, processes {procs:?}", logs[0].len());
        let by = |p: &Path| logs[0].iter().find(|id| id.path.as_deref() == Some(p)).unwrap().process.clone();
        assert_eq!((by(&a), by(&b)), ("0/0".to_string(), "0/1".to_string()), "sh forks cat a first");
        assert!(logs.iter().all(|l| l == &logs[0]), "seed {seed}: decision logs differ");
        let trig: Vec<&Path> = logs[0].iter().filter_map(|id| id.path.as_deref()).filter(|&p| p == a || p == b).collect();
        assert_eq!(trig.len(), 2, "both triggers decided");
        firsts.push(if trig[0] == a { a.as_path() } else { b.as_path() });
    }
    eprintln!("first trigger per seed: {firsts:?}");
    assert!(firsts.contains(&a.as_path()) && firsts.contains(&b.as_path()), "the seed never changed the order");
}
