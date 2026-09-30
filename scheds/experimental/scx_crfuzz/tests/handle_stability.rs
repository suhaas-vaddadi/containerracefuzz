// SPDX-License-Identifier: GPL-2.0
//
// The gate's soundness property: a held thread stays parked in its seccomp
// notification for the whole hold, so the notification id the engine was given
// stays valid and answerable. A thread-group hold must not disturb the syscall
// it holds -- a restarted syscall re-enters the filter and raises a *second*
// notification under a new id, which would corrupt the ready set and the
// canonical log.
//
// Driven through a raw `SeccompNotifyBackend` with `GateMap` applied by hand,
// not through `GateBackend`: this is the one place low enough to see what the
// mechanism actually does to the notification id underneath the trait that
// hides it. It needs `scx_crfuzz_gated` running and skips without it.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_gate::tgid_of;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::role::Pid;
use scx_crfuzz_gate::GateMap;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

/// Both tests here install a privileged seccomp listener; the gate test also
/// needs the scheduler attached. Skipping rather than failing keeps a plain
/// `cargo test` green for anyone; the VM runs these under sudo with
/// `scx_crfuzz_gated` already running.

fn skip_unless_scheduler(test: &str) -> bool {
    if !GateMap::scheduler_enabled() {
        eprintln!("skipping {test}: scx_crfuzz_gated is not running");
        return true;
    }
    false
}

/// A single narrowed checkpoint, NOT `default_discovery_checkpoints()`: the
/// full structural set holds the fixture at its progress-file `openat`, which
/// happens before the sibling thread is created. Matches the `newfstatat`
/// narrowing `thread_group_holding.rs` already uses for this fixture.
fn newfstatat_checkpoint() -> CheckpointDecl {
    CheckpointDecl::syscall("newfstatat")
}

/// Drive a raw backend until one of its tasks hits a checkpoint.
///
/// Returns `(pid, handle)` for the first hit.
fn first_hit(backend: &mut SeccompNotifyBackend, deadline: Instant) -> (Pid, NotifyHandle) {
    let mut first: Option<(Pid, NotifyHandle)> = None;
    while Instant::now() < deadline && first.is_none() {
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit { pid, handle, .. } = e {
                    first = Some((pid, handle));
                }
            }
        }
    }
    first.expect("the fixture never reached a checkpoint")
}

/// Ungate on the way out no matter how the test body exits, including a
/// panicking assertion mid-hold. Without this a failed assertion here leaves
/// the next run's tasks on a machine that will not schedule them -- the same
/// failure mode `GateBackend`'s own `Drop` exists to prevent.
struct GateGuard<'a> {
    map: &'a GateMap,
    tgid: Pid,
}

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.map.ungate(self.tgid) {
            eprintln!("cleanup: ungating tgid {}: {e:#}", self.tgid);
        }
        if let Err(e) = self.map.kick() {
            eprintln!("cleanup: kicking cpus: {e:#}");
        }
    }
}

#[test]
fn a_gated_notification_id_survives_the_hold() {
    if skip_unless_root("a_gated_notification_id_survives_the_hold") {
        return;
    }
    if skip_unless_scheduler("a_gated_notification_id_survives_the_hold") {
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("threaded_victim");
    // Both arguments required: threaded_victim.c:49 exits via VERDICT:usage
    // when argc < 3, without ever creating the sibling thread, which would
    // make everything below vacuously true. See Task 9 Step 1's note.
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

    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/handle-stability-gate")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    backend.attach(&[newfstatat_checkpoint()]).unwrap();

    let (pid, handle) = first_hit(&mut backend, Instant::now() + Duration::from_secs(10));
    let tgid = tgid_of(pid);

    let map = GateMap::open().expect("open gate map");
    map.gate(tgid).expect("gate");
    map.kick().expect("kick");
    // Guards cleanup for the panic path (the assert below); the success path
    // ungates explicitly, in order, before this guard's drop runs its
    // (then-redundant, and harmless per `GateMap::ungate`'s NotFound match)
    // second ungate.
    let _guard = GateGuard { map: &map, tgid };

    // Hold long enough that, if the gate perturbed the syscall at all, a
    // restart would certainly fall inside this window.
    let hold_start = Instant::now();
    while hold_start.elapsed() < Duration::from_millis(300) {
        // Polling during the hold is what would surface a replacement id: a
        // restarted syscall re-enters the filter and notifies again.
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit {
                    pid: p, handle: h, ..
                } = e
                {
                    if p == pid {
                        assert_eq!(
                            h, handle,
                            "a second notification arrived for the gated task: the hold \
                             let its syscall restart, which a thread-group hold must not do"
                        );
                    }
                }
            }
        }
    }

    // Ungate before answering -- order is load-bearing, matching
    // `GateBackend::release`'s own comment: a task released into a still-gated
    // thread group is parked again immediately on its way back to userspace.
    map.ungate(tgid).expect("ungate");
    map.kick().expect("kick");

    // The original id must still be answerable: nothing about the gate ever
    // touched the seccomp notification underneath it.
    backend
        .release(handle)
        .expect("the original notification id was still answerable after a 300ms gated hold");
}
