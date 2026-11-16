//! The hold: seccomp parks a thread, the tree gate stops its siblings. Needs
//! root, a running `scx_crfuzz gated`, and `go`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::{go_bin, trigger_file};

use scx_crfuzz::backend::{Event, GateBackend, Poll};
use std::io::Read;
use std::path::Path;
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
    let mut be = GateBackend::spawn(cmd, &[]).unwrap();
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
    be.release(&ev).unwrap();
    if tree {
        be.ungate_tree().unwrap();
    }
    Hold { residual, leak }
}

fn check(be: &mut GateBackend, bytes: &AtomicU64, trigger: &Path, label: &str) {
    pump(be, bytes, ms(300)); // past runtime / loader startup opens
    let free = pump(be, bytes, ms(300));
    let control = hold(be, bytes, trigger, false);
    let gated: Vec<Hold> = (0..5).map(|_| hold(be, bytes, trigger, true)).collect();
    let after = pump(be, bytes, ms(300));
    eprintln!(
        "{label}: bytes/300ms free {free}; seccomp-only hold leak {}; tree hold leaks {:?} \
         (residual window {:?}); after {after}",
        control.leak,
        gated.iter().map(|h| h.leak).collect::<Vec<_>>(),
        gated.iter().map(|h| h.residual).collect::<Vec<_>>(),
    );
    assert!(control.leak > 0, "control: siblings should run under a seccomp-only hold");
    assert!(gated.iter().all(|h| h.leak == 0), "sibling bytes leaked during a tree hold");
    assert!(after > 0, "SUT did not resume after release");
}

/// Zero sibling bytes during a hold on the Go fixture.
#[test]
#[ignore]
fn tree_hold_stops_go_siblings() {
    let trigger = trigger_file("crfuzz_go_trigger");
    let mut cmd = Command::new(go_bin("go_hold"));
    cmd.arg(&trigger);
    let (mut be, bytes) = spawn_counted(cmd);
    check(&mut be, &bytes, &trigger, "go");
}

/// The tree is every process forked below the root: here the trapping `cat` and a
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

/// runc moves `runc init` into the container's cgroup, wherever the runtime
/// puts it. Here a subshell moves itself into another cgroup and writes; the
/// tree hold must still stop it, and Drop must kill it there.
#[test]
#[ignore]
fn tree_hold_follows_a_process_to_another_cgroup() {
    let trigger = trigger_file("crfuzz_cg_trigger");
    let cg = Path::new("/sys/fs/cgroup/crfuzz-test-moved");
    let _ = std::fs::create_dir(cg);
    let script = format!(
        "(echo 0 > {}/cgroup.procs; while :; do printf x; done) & while :; do cat {} >/dev/null; sleep 0.1; done",
        cg.display(),
        trigger.display()
    );
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]);
    let (mut be, bytes) = spawn_counted(cmd);
    check(&mut be, &bytes, &trigger, "moved cgroup");
    let procs = || std::fs::read_to_string(cg.join("cgroup.procs")).unwrap();
    assert!(!procs().is_empty(), "the subshell never moved");
    drop(be);
    assert!(procs().is_empty(), "Drop left a process of the tree alive: {}", procs());
    std::fs::remove_dir(cg).unwrap();
}

/// At startup the tree of a crfuzz that died (here by SIGKILL, so no Drop
/// ran) is killed; a live owner's (ours) is left alone.
#[test]
#[ignore]
fn sweep_kills_only_dead_owners_runs() {
    let d = Path::new("/tmp/crfuzz_sweep");
    let _ = std::fs::remove_dir_all(d);
    std::fs::create_dir(d).unwrap();
    let pidfile = d.join("pid");
    let script = format!("echo $$ > {}; exec sleep 60", pidfile.display());
    let mut owner = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz"))
        .args(["run", d.join("out").to_str().unwrap(), "--seeds", "1", "--attacker", "65534:65534", "--", "sh", "-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    let sut = loop {
        assert!(Instant::now() < end, "the SUT never started");
        if let Some(pid) = std::fs::read_to_string(&pidfile).ok().and_then(|s| s.trim().parse::<u32>().ok()) {
            break pid;
        }
        sleep(ms(50));
    };
    // Into its sleep: a syscall held when the listener closes fails, and
    // `sleep` would die of it on its own.
    sleep(ms(500));
    owner.kill().unwrap();
    owner.wait().unwrap();
    let alive = |pid: u32| Path::new(&format!("/proc/{pid}")).exists();
    assert!(alive(sut), "the SUT died with its owner: nothing to sweep");
    let mut cmd = Command::new("sleep");
    cmd.arg("60");
    let mut live = GateBackend::spawn(cmd, &[]).unwrap();
    scx_crfuzz::backend::sweep();
    assert!(!alive(sut), "a dead owner's SUT survived the sweep");
    assert!(live.child().try_wait().unwrap().is_none(), "a live owner's SUT was swept");
    for e in std::fs::read_dir("/var/lib/crfuzz").unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with(&format!("canary-{}-", owner.id())) {
            std::fs::remove_dir_all(e.path()).unwrap();
        }
    }
    std::fs::remove_dir_all(d).unwrap();
}
