// SPDX-License-Identifier: GPL-2.0
//
// The design doc's Background says a role denotes a thread group, and that
// "holding a role back means holding every thread of that thread group".
//
// This test measures whether a backend actually delivers that, by holding a
// deliberately multi-threaded role at a checkpoint and watching whether its
// sibling thread keeps making progress. It is the only test in this crate that
// distinguishes "held a thread" from "held a role".
//
// Requires root (the seccomp listener fd is privileged) and a Linux host, so
// it is gated and skipped elsewhere. Build the fixture first:
//
//     cd scheds/experimental/scx_crfuzz/scenarios && make
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_gate::GateBackend;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

/// How long to let the held role sit before re-measuring its sibling. The
/// fixture's sibling writes every 1ms, so a backend that does not hold the
/// thread group will grow the progress file by roughly this many bytes.
const OBSERVE: Duration = Duration::from_millis(300);

/// Give up waiting for the first checkpoint after this long.
const HIT_TIMEOUT: Duration = Duration::from_secs(10);

/// The tests here install a seccomp listener and gate a thread group, which
/// needs privilege. Skipping rather than failing keeps a plain `cargo test`
/// green for anyone; the VM runs them under sudo.
///
/// Returns true if the test should stop.

fn progress_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Drive a backend until one of its tasks is held at a checkpoint, then report
/// how much the sibling thread wrote while it was held.
///
/// Returns `(bytes_at_hit, bytes_after_observing)`.
fn sibling_progress_while_held<B: CheckpointBackend>(
    backend: &mut B,
    progress: &Path,
) -> (u64, u64) {
    let checkpoints = vec![CheckpointDecl::syscall("newfstatat")];
    backend.attach(&checkpoints).expect("attach");

    let deadline = Instant::now() + HIT_TIMEOUT;
    loop {
        assert!(
            Instant::now() < deadline,
            "no checkpoint hit within {HIT_TIMEOUT:?}; is the fixture built and running?"
        );
        match backend.poll().expect("poll") {
            Poll::Events(events) => {
                if events.iter().any(|e| {
                    matches!(e, BackendEvent::CheckpointHit { .. })
                }) {
                    // The main thread is now parked inside the kernel. Whatever
                    // the sibling writes from here on is a thread that the role
                    // contract says should be held.
                    let at_hit = progress_len(progress);
                    std::thread::sleep(OBSERVE);
                    return (at_hit, progress_len(progress));
                }
            }
            Poll::Idle => {}
            Poll::Closed => panic!("backend closed before any checkpoint was hit"),
        }
    }
}

#[test]
fn the_gate_holds_the_whole_thread_group() {
    if skip_unless_root("the_gate_holds_the_whole_thread_group") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }
    let fixture = scenarios_dir().join("02-multi-thread").join("threaded_victim");
    // Both fixture arguments are load-bearing: threaded_victim.c:49 exits via
    // VERDICT:usage when argc < 3, without ever creating the sibling thread,
    // which would make the assertion below vacuously true.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/gate-tgh")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    let mut backend = GateBackend::new(seccomp).unwrap();

    let (at_hit, after) = sibling_progress_while_held(&mut backend, &progress);
    assert_eq!(
        after,
        at_hit,
        "the sibling wrote {} bytes during a {:?} hold; the gate must hold the \
         whole thread group, not just the notifying thread",
        after - at_hit,
        OBSERVE
    );
}

#[test]
fn the_gate_holds_a_go_runtimes_thread_group() {
    if skip_unless_root("the_gate_holds_a_go_runtimes_thread_group") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }
    let fixture = scenarios_dir().join("fixtures").join("go_victim");
    // go_victim.go:71 has the same argc guard as threaded_victim -- see the note
    // on the row above.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/gate-go")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    let mut backend = GateBackend::new(seccomp).unwrap();

    let (at_hit, after) = sibling_progress_while_held(&mut backend, &progress);
    assert_eq!(
        after,
        at_hit,
        "the Go fixture's siblings wrote {} bytes during a {:?} hold; under seccomp \
         alone this is ~920 and under the gate it is 0",
        after - at_hit,
        OBSERVE
    );
}
