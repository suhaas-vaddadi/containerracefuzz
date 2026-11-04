//! Milestone 2 acceptance. Needs root, a running scx_crfuzz_gated, and `go`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::{go_bin, trigger_file};

use scx_crfuzz::backend::{Event, GateBackend, Poll};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Spawn the SUT with stdout counted byte-by-byte.
fn spawn_counted(mut cmd: Command) -> (GateBackend, Arc<AtomicU64>) {
    cmd.stdout(Stdio::piped());
    let mut be = GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap();
    let mut out = be.child().stdout.take().unwrap();
    let bytes = Arc::new(AtomicU64::new(0));
    let b = bytes.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n @ 1..) = out.read(&mut buf) {
            b.fetch_add(n as u64, Ordering::Relaxed);
        }
    });
    (be, bytes)
}

/// Release every held syscall until one opens `trigger`; return that one, held.
fn next_trigger(be: &mut GateBackend, trigger: &Path) -> Event {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "trigger never trapped");
        match be.poll(ms(100)).unwrap() {
            Poll::Events(evs) => {
                let mut hit = None;
                for ev in evs {
                    if ev.path.as_deref() == Some(trigger) && hit.is_none() {
                        hit = Some(ev);
                    } else {
                        be.release(&ev).unwrap();
                    }
                }
                if let Some(ev) = hit {
                    return ev;
                }
            }
            Poll::Idle => {}
            Poll::Closed => panic!("SUT exited"),
        }
    }
}

fn bytes_over(bytes: &AtomicU64, d: Duration) -> u64 {
    let a = bytes.load(Ordering::Relaxed);
    sleep(d);
    bytes.load(Ordering::Relaxed) - a
}

/// Run free for `d`, releasing every held syscall; returns bytes written.
fn pump(be: &mut GateBackend, bytes: &AtomicU64, d: Duration) -> u64 {
    let a = bytes.load(Ordering::Relaxed);
    let end = Instant::now() + d;
    while Instant::now() < end {
        if let Poll::Events(evs) = be.poll(ms(10)).unwrap() {
            evs.iter().for_each(|ev| be.release(ev).unwrap());
        }
    }
    bytes.load(Ordering::Relaxed) - a
}

struct Hold {
    /// Bytes from notification receipt to tree gate + settle (the residual window).
    residual: u64,
    leak: u64,
    tree: usize,
}

/// Hold the trigger for 300 ms, with or without the tree gate, then release.
fn hold(be: &mut GateBackend, bytes: &AtomicU64, trigger: &Path, tree: bool) -> Hold {
    let ev = next_trigger(be, trigger);
    let at_recv = bytes.load(Ordering::Relaxed);
    if tree {
        be.gate_tree().unwrap();
    }
    sleep(ms(50));
    let residual = bytes.load(Ordering::Relaxed) - at_recv;
    let leak = bytes_over(bytes, ms(300));
    let tree_size = be.tree().len();
    be.release(&ev).unwrap();
    if tree {
        be.ungate_tree().unwrap();
    }
    Hold { residual, leak, tree: tree_size }
}

fn check(be: &mut GateBackend, bytes: &AtomicU64, trigger: &Path, label: &str) {
    pump(be, bytes, ms(300)); // past runtime / loader startup opens
    let free = pump(be, bytes, ms(300));
    let control = hold(be, bytes, trigger, false);
    let gated: Vec<Hold> = (0..5).map(|_| hold(be, bytes, trigger, true)).collect();
    let after = pump(be, bytes, ms(300));
    eprintln!(
        "{label}: bytes/300ms free {free}; seccomp-only hold leak {}; tree hold leaks {:?} \
         (residual window {:?}, tree sizes {:?}); after {after}",
        control.leak,
        gated.iter().map(|h| h.leak).collect::<Vec<_>>(),
        gated.iter().map(|h| h.residual).collect::<Vec<_>>(),
        gated.iter().map(|h| h.tree).collect::<Vec<_>>(),
    );
    assert!(control.leak > 0, "control: siblings should run under a seccomp-only hold");
    assert!(gated.iter().all(|h| h.leak == 0), "sibling bytes leaked during a tree hold");
    assert!(after > 0, "SUT did not resume after release");
}

/// Spec §4 milestone 2: zero sibling bytes during a hold on the Go fixture.
#[test]
#[ignore]
fn tree_hold_stops_go_siblings() {
    let trigger = trigger_file("crfuzz_go_trigger");
    let mut cmd = Command::new(go_bin("go_hold"));
    cmd.arg(&trigger);
    let (mut be, bytes) = spawn_counted(cmd);
    check(&mut be, &bytes, &trigger, "go");
}

/// The tree is every process in the run cgroup: here the trapping `cat` and a
/// forked subshell writing to stdout are different tgids. The subshell loop is
/// builtins only: an exec would trap on the loader's openat.
#[test]
#[ignore]
fn tree_hold_stops_sibling_processes() {
    let trigger = trigger_file("crfuzz_sh_trigger");
    let script = format!(
        "(while :; do printf x; done) & while :; do cat {} >/dev/null; sleep 0.1; done",
        trigger.display()
    );
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]);
    let (mut be, bytes) = spawn_counted(cmd);
    check(&mut be, &bytes, &trigger, "sh tree");
}

/// With execve watched, spawn returns (the SUT's own exec is let through) and
/// the SUT's next exec traps, held, with its path.
#[test]
#[ignore]
fn watched_execve_spawns_and_holds_next_exec() {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "exec /bin/true"]);
    let mut be = GateBackend::spawn(cmd, &[libc::SYS_execve]).unwrap();
    let ev = match be.poll(ms(1000)).unwrap() {
        Poll::Events(mut evs) => evs.remove(0),
        Poll::Idle => panic!("sh's exec never trapped"),
        Poll::Closed => panic!("SUT exited unheld"),
    };
    assert_eq!(ev.path.as_deref(), Some(Path::new("/bin/true")));
    sleep(ms(100));
    assert!(be.child().try_wait().unwrap().is_none(), "exec ran while held");
    be.release(&ev).unwrap();
    assert!(be.child().wait().unwrap().success());

    let bare = GateBackend::spawn(Command::new("sh"), &[libc::SYS_execve]);
    assert!(bare.is_err(), "bare program name accepted with execve watched");
}

/// runc moves `runc init` into the container cgroup, under ours (spec §3.4).
/// Here a subshell moves itself into a child cgroup and writes; the tree hold
/// must still stop it, and Drop must remove both cgroups.
#[test]
#[ignore]
fn tree_hold_stops_child_cgroup() {
    let trigger = trigger_file("crfuzz_cg_trigger");
    let script = format!(
        "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); mkdir $cg/ctr; \
         (echo 0 > $cg/ctr/cgroup.procs; while :; do printf x; done) & \
         while :; do cat {} >/dev/null; sleep 0.1; done",
        trigger.display()
    );
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]);
    let (mut be, bytes) = spawn_counted(cmd);
    let pid = be.child().id();
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    let run = PathBuf::from(format!("/sys/fs/cgroup{}", cg.trim().rsplit(':').next().unwrap()));
    check(&mut be, &bytes, &trigger, "child cgroup");
    assert!(run.join("ctr").exists(), "subshell never made its cgroup");
    drop(be);
    assert!(!run.exists(), "run cgroup left behind");
}
