// SPDX-License-Identifier: GPL-2.0
//
// A poll with no timeout blocks in `epoll_wait` until something it watches is
// ready: a notification, a child's exit, or (under the gate) a thread-state
// record. Each of those has to wake it, and nothing else may make it spin.
//
// The spin is not hypothetical. When a held child exits, its seccomp notify fd
// reports a hangup, which is level-triggered and never clears: left in the
// set, every wait returns at once. An 11-thread Go child takes long enough to
// tear down that the window is easy to hit.
//
// Requires root (the seccomp listener fd is privileged) and Linux; the record
// half also needs `scx_crfuzz_gated`. Build the fixture first:
//
//     cd scheds/experimental/scx_crfuzz/scenarios && make
//
// Everything here lives in one test on purpose. `reap` calls `waitpid(-1)`,
// which is process-wide, so two backends running concurrently in one test
// binary would reap each other's children. The engine only ever constructs one
// backend, so this constrains the test rather than the code.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_gate::GateBackend;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

#[test]
fn a_blocking_poll_wakes_for_a_notification_an_exit_and_a_record() {
    if skip_unless_root("a_blocking_poll_wakes_for_a_notification_an_exit_and_a_record") {
        return;
    }
    abort_after(Duration::from_secs(60));

    // A notification, then the exit: drive a Go child to completion,
    // releasing every checkpoint, with no timeout on any poll.
    let dir = scenarios_dir();
    let tmp = tempfile::tempdir().expect("tmp");
    std::fs::write(tmp.path().join("target"), "BENIGN\n").expect("target");
    let spec = ProcessSpec::parse(&format!(
        "{}/fixtures/go_victim {}/target {}/progress",
        dir.display(),
        tmp.path().display(),
        tmp.path().display()
    ))
    .expect("spec");
    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/goexit");
    backend
        .attach(&[CheckpointDecl::syscall("newfstatat")])
        .expect("attach");

    let (mut hits, mut idle) = (0, 0);
    loop {
        match backend.poll(None).expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {
                idle += 1;
                assert!(idle < 100, "{idle} idle polls: the backend spins");
            }
            Poll::Events(events) => {
                for e in events {
                    if let BackendEvent::CheckpointHit { handle, .. } = e {
                        hits += 1;
                        backend.release(handle).expect("release");
                    }
                }
            }
        }
    }
    assert!(hits > 0, "the Go child never reached a checkpoint");
    drop(backend);

    // A record: under the gate, a child that raises no notification and has
    // not exited still wakes the poll, through the sensor's ringbuf.
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping the record half: scx_crfuzz_gated is not running");
        return;
    }
    let spec = ProcessSpec::parse("/bin/sleep 3").expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/recordwake").with_sched_ext(true);
    let mut backend = GateBackend::new(seccomp).expect("gate backend");
    backend
        .attach(&[CheckpointDecl::syscall("mount")])
        .expect("attach");
    let started = Instant::now();
    let Poll::Events(events) = backend.poll(None).expect("poll") else {
        panic!("the first poll reported nothing");
    };
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "woke only after {:?}, not for a record",
        started.elapsed()
    );
    assert!(
        events
            .iter()
            .all(|e| matches!(e, BackendEvent::ThreadState { .. })),
        "{events:?}"
    );
    while backend.poll(None).expect("poll") != Poll::Closed {}
}
