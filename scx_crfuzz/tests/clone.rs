//! Go's thread clones don't stall a run, and each process is named by its
//! place in the process creation tree, which the scheduler keeps from each fork.
//! Needs root, a running `scx_crfuzz gated`, `go`:
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
fn go_processes_named_thread_clones_pass() {
    let bin = go_bin("go_clone");
    let trigger = trigger_file("crfuzz_clone_trigger");
    for seed in 0..5 {
        let mut cmd = Command::new(&bin);
        cmd.arg(&trigger);
        let mut be = GateBackend::spawn(cmd).unwrap();
        let t = Instant::now();
        let deadline = t + Duration::from_secs(60);
        let mut log = Vec::new();
        run(&mut be, &mut Pos::new(seed), None, None, None, None, deadline, &mut log)
            .unwrap_or_else(|e| panic!("seed {seed}: {e:#}"));
        assert!(be.child().wait().unwrap().success(), "seed {seed}: SUT failed");
        let mut procs: BTreeSet<&str> = log.iter().map(|d| d.id.process.as_str()).collect();
        eprintln!("seed {seed}: {:?}, {} decisions, processes {procs:?}", t.elapsed(), log.len());
        // 0/0: os/exec's pidfd check clones a child that exits at once.
        procs.remove("0/0");
        assert_eq!(procs, BTreeSet::from(["0", "0/1", "0/2", "0/3", "0/4", "0/5"]), "seed {seed}");
    }
}
