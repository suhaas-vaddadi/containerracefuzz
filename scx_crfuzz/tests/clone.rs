//! D4 on Go: clones are released without a POS decision, so holding them
//! doesn't stall stop-the-world (the runtime clones without handing off its
//! P), and every thread gets a creation-tree name. Needs root, a running
//! scx_crfuzz_gated, `go`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::{go_bin, trigger_file};

use scx_crfuzz::backend::GateBackend;
use scx_crfuzz::engine::run;
use scx_crfuzz::pos::Pos;
use std::collections::BTreeSet;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn go_clones_named_without_stall() {
    let bin = go_bin("go_clone");
    let trigger = trigger_file("crfuzz_clone_trigger");
    for seed in 0..10 {
        let mut cmd = Command::new(&bin);
        cmd.arg(&trigger);
        let mut be = GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap();
        let t = Instant::now();
        let deadline = t + Duration::from_secs(60);
        let log = run(&mut be, &mut Pos::new(seed), None, Duration::from_millis(1), Duration::from_millis(200), deadline)
            .unwrap_or_else(|e| panic!("seed {seed}: {e:#}"));
        assert!(be.child().wait().unwrap().success(), "seed {seed}: SUT failed");
        let threads: BTreeSet<&str> = log.iter().map(|d| d.id.thread.as_str()).collect();
        let partial = log.iter().filter(|d| d.partial).count();
        eprintln!("seed {seed}: {:?}, {} decisions, {partial} partial, threads {threads:?}", t.elapsed(), log.len());
        assert!(threads.iter().all(|t| !t.starts_with('?')), "seed {seed}: unnamed thread");
        assert!(threads.len() > 1, "seed {seed}: no thread but the root made a decision");
    }
}
