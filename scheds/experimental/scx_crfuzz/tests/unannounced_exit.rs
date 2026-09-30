// SPDX-License-Identifier: GPL-2.0
//
// A spawned child that never makes a watched syscall itself is never announced
// by a notification, so the engine has no role for it -- and a pid with no role
// has its exit dropped. `runc run` is the real case: every checkpoint it
// reaches is hit by the `runc init` it forks, so `until: exit` could never be
// satisfied and the attacker/oracle orchestration never observed its last
// window. The backend must therefore announce such a child just ahead of its
// exit, from /proc while it is still a zombie.
//
// Requires root (the seccomp listener fd is privileged) and Linux.
//
// One test in its own binary on purpose: `reap` peeks with `waitid(P_ALL)` and
// reaps with `waitpid`, which are process-wide, so a second backend in the same
// binary could consume this one's child.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::checkpoint::CheckpointDecl;
use std::time::Duration;
use std::time::Instant;

#[test]
fn a_child_that_hits_no_checkpoint_is_announced_before_its_exit() {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("skipping: needs root (seccomp listener)");
        return;
    }

    // `true` mounts nothing, so the only way it can be announced is at exit.
    let spec = scx_crfuzz::backend_seccomp::ProcessSpec::parse("/bin/true").expect("spec");
    let mut backend =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/unannounced");
    backend
        .attach(&[CheckpointDecl::syscall("mount")])
        .expect("attach");

    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match backend.poll().expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {}
            Poll::Events(events) => {
                for e in events {
                    match e {
                        BackendEvent::CheckpointHit { handle, .. } => {
                            backend.release(handle).expect("release")
                        }
                        other => seen.push(other),
                    }
                }
            }
        }
    }

    let exited = seen
        .iter()
        .position(|e| matches!(e, BackendEvent::TaskExited(_)))
        .expect("the child's exit was never reported");
    let BackendEvent::TaskExited(pid) = seen[exited] else {
        unreachable!()
    };
    let appeared = seen
        .iter()
        .position(|e| matches!(e, BackendEvent::TaskAppeared(t) if t.pid == pid))
        .expect("the child exited without ever being announced; the engine would drop its exit");
    assert!(appeared < exited, "announced after its exit: {seen:?}");

    let BackendEvent::TaskAppeared(task) = &seen[appeared] else {
        unreachable!()
    };
    // Read from the zombie: the program it exec'd, not the engine's own name,
    // and the scenario's cgroup, so role resolution can match it.
    assert_eq!(task.comm, "true");
    assert!(
        task.cgroup.starts_with("/crfuzz/unannounced"),
        "cgroup {:?}",
        task.cgroup
    );
}
