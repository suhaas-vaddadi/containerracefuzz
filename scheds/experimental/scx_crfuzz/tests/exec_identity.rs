// SPDX-License-Identifier: GPL-2.0
//
// What a task is announced as, across `execve`, once `execve` is a checkpoint
// (design doc section 4.2).
//
// Two ways to get this wrong, both of which leave a role that never appears:
//
// 1. The backend loads its filter and *then* execs the target, so the launch
//    exec is the child's first notification. Reported, it would announce the
//    pid under this test binary's own `comm`.
// 2. A task that execs into a role binary from something that is not a role
//    (a shim exec'ing `runc`; here, `env` exec'ing `true`) is first announced
//    as the old program. Announced only once, it would never match.
//
// One test per binary on purpose: `reap` calls `waitpid(None)`, which is
// process-wide. See tests/exit_observation.rs.
//
// Requires root (the seccomp listener fd is privileged) and Linux.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
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

fn syscall(name: &str) -> CheckpointDecl {
    CheckpointDecl {
        id: CheckpointId::new(name),
        kind: CheckpointKind::Syscall,
        target: name.into(),
        category: None,
    }
}

#[test]
fn a_task_is_announced_as_the_program_it_became_and_never_as_the_engine() {
    if skip_unless_root("a_task_is_announced_as_the_program_it_became_and_never_as_the_engine") {
        return;
    }

    // Both binaries are dynamically linked, so each makes `openat` calls (the
    // loader's) after its exec -- that is what gets the pid announced again.
    let spec =
        scx_crfuzz::backend_seccomp::ProcessSpec::parse("/usr/bin/env /usr/bin/true").expect("spec");
    let mut backend =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/execidentity");
    backend
        .attach(&[syscall("execve"), syscall("openat")])
        .expect("attach");

    let mut announced: Vec<String> = Vec::new();
    let mut execs = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match backend.poll().expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {}
            Poll::Events(events) => {
                for e in events {
                    match e {
                        BackendEvent::TaskAppeared(t) => announced.push(t.comm),
                        BackendEvent::CheckpointHit {
                            checkpoint, handle, ..
                        } => {
                            if checkpoint.as_str() == "execve" {
                                execs += 1;
                            }
                            backend.release(handle).expect("release");
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    assert_eq!(
        execs, 1,
        "only env's exec of true is a checkpoint; the launch exec is the backend's own"
    );
    assert_eq!(
        announced,
        vec!["env".to_string(), "true".to_string()],
        "announced first as env, then again as true after the exec -- never as \
         this test binary, which is what the launch exec would have shown"
    );
}
