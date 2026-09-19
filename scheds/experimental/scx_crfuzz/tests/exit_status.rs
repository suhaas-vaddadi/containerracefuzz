// SPDX-License-Identifier: GPL-2.0
//
// Whether a spawned child's exit status survives the engine.
//
// The engine's own exit status answers "did the scheduling run complete", which
// is what a measurement shell loop wants. A *wrapper* wants the opposite: when
// `scx_crfuzz` stands in for `runc` behind `ctr --runc-binary`, containerd's
// shim reads the exit status to decide whether the container was created. An
// engine that reports its own verdict there tells the shim a container exists
// when it does not.
//
// One test per binary on purpose: `reap` calls `waitpid(None)`, which is
// process-wide, so two backends running concurrently in one test binary would
// reap each other's children. See tests/exit_observation.rs.
//
// Requires root (the seccomp listener fd is privileged) and Linux.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use std::time::Duration;
use std::time::Instant;

fn skip_unless_root(test: &str) -> bool {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } == 0 {
        return false;
    }
    eprintln!("skipping {test}: needs root (seccomp listener)");
    true
}

/// `/usr/bin/false` is the smallest thing that exits nonzero for a reason that
/// has nothing to do with the engine. Its exit code (1) is deliberately not the
/// engine's own failure code (2), so a passing assertion cannot be the engine
/// accidentally reporting itself.
#[test]
fn a_spawned_childs_exit_code_is_recorded() {
    if skip_unless_root("a_spawned_childs_exit_code_is_recorded") {
        return;
    }

    let spec = scx_crfuzz::backend_seccomp::ProcessSpec::parse("/usr/bin/false").expect("spec");
    let mut backend =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/exitstatus");
    backend
        .attach(&[CheckpointDecl {
            id: CheckpointId::new("openat"),
            kind: CheckpointKind::Syscall,
            target: "openat".into(),
            category: None,
        }])
        .expect("attach");

    assert_eq!(
        backend.child_exit_code(),
        None,
        "a child that has not exited has no exit code yet"
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match backend.poll().expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {}
            Poll::Events(events) => {
                for e in events {
                    if let scx_crfuzz::backend::BackendEvent::CheckpointHit { handle, .. } = e {
                        backend.release(handle).expect("release");
                    }
                }
            }
        }
    }

    assert_eq!(
        backend.child_exit_code(),
        Some(1),
        "/usr/bin/false exits 1; a wrapper standing in for runc has to be able to \
         report that rather than its own verdict"
    );
}
