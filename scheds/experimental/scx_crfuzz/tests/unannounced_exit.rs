// SPDX-License-Identifier: GPL-2.0
//
// A spawned child that never makes a watched syscall -- `runc run`, whose
// checkpoints are all hit by the `runc init` it forks -- raises no
// notification at all. Its exit must still end a poll that waits with no
// timeout, or a run whose last process is such a child never closes.
//
// Requires root (the seccomp listener fd is privileged) and Linux.
//
// One test in its own binary on purpose: `reap` calls `waitpid(-1)`, which is
// process-wide, so a second backend in the same binary could consume this
// one's child.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::checkpoint::CheckpointDecl;

mod common;
use common::*;

#[test]
fn a_child_that_hits_no_checkpoint_still_wakes_a_blocking_poll_when_it_exits() {
    if skip_unless_root("a_child_that_hits_no_checkpoint_still_wakes_a_blocking_poll_when_it_exits")
    {
        return;
    }
    abort_after(std::time::Duration::from_secs(20));

    // `true` mounts nothing, so only its exit can wake the poll.
    let spec = scx_crfuzz::backend_seccomp::ProcessSpec::parse("/bin/true").expect("spec");
    let mut backend =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/unannounced");
    backend
        .attach(&[CheckpointDecl::syscall("mount")])
        .expect("attach");

    let mut polls = 0;
    while backend.poll(None).expect("poll") != Poll::Closed {
        polls += 1;
        assert!(polls < 100, "the poll spins instead of waiting");
    }
    assert_eq!(backend.child_exit_code_at(0), Some(0));
}
