// SPDX-License-Identifier: GPL-2.0
//
// Task 9 Step 5 found that a soundness test driven through the
// `CheckpointBackend` trait cannot distinguish the gate from the freezer:
// `FreezerBackend` is deliberately built to look identical to `GateBackend` at
// that boundary. `poll()` swallows a freeze-induced restart's second
// notification outright (`backend_freezer.rs`'s `reported` set: "the engine
// keeps the one it has and never learns the difference"), and `release()`
// resolves a stale id through the `live` map and retries until it succeeds.
// Both are correct, intentional behavior for `FreezerBackend` as a working
// backend -- they are not a bug to catch, they are the trait contract doing
// its job. A test that calls `release()` on a `FreezerBackend` and expects it
// to fail is testing a promise the wrapper exists to keep.
//
// So this file does not go through either wrapper. It drives a raw
// `SeccompNotifyBackend` and applies each mechanism by hand -- `GateMap`
// directly for the gate, a manual `cgroup.freeze` write for the freezer --
// which is the one place low enough to see what each mechanism actually does
// to the notification id underneath the trait that hides it.
//
// Two tests, opposite assertions, same fixture and hold duration:
//
//   - a_gated_notification_id_survives_the_hold expects NO second
//     notification and a successful release of the ORIGINAL id. It needs
//     `scx_crfuzz_gated` running and skips without it.
//   - a_frozen_notification_id_does_not_survive_the_hold expects the
//     freezer's known failure to actually show up: a second notification for
//     the same task with a different id, or a release of the original id
//     that fails. (`backend_freezer.rs`'s own header: "old id
//     14407828070108571077 stopped being answerable the moment the cgroup
//     froze, and id ...078 appeared in its place".) It touches only a raw
//     seccomp backend and `cgroup.freeze` directly, so it runs -- and can
//     fail -- on plain root with no scheduler loaded at all; it must NOT be
//     gated on the scheduler being present, or an absent daemon silences
//     both halves of this file's discriminator at once instead of just the
//     half that actually needs it.
//
// The second test is what makes the first one mean anything. Without it,
// "the gate's id survives" is unfalsifiable -- nothing here would have caught
// Step 5's finding that the original single-test design couldn't fail either
// way. If a kernel or design change ever makes the freeze test start passing
// like the gate test, that is exactly the case this file exists to catch: the
// discriminator has stopped discriminating.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_freezer::is_frozen;
use scx_crfuzz::backend_gate::tgid_of;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use scx_crfuzz::role::Pid;
use scx_crfuzz_gate::GateMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Both tests here install a privileged seccomp listener; the gate test also
/// needs the scheduler attached. Skipping rather than failing keeps a plain
/// `cargo test` green for anyone; the VM runs these under sudo with
/// `scx_crfuzz_gated` already running.
fn skip_unless_root(test: &str) -> bool {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("skipping {test}: needs root (seccomp listener)");
        return true;
    }
    false
}

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
    CheckpointDecl {
        id: CheckpointId::new("newfstatat"),
        kind: CheckpointKind::Syscall,
        target: "newfstatat".into(),
        category: None,
    }
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

/// Poll `cgroup.events` until `frozen` reads `want`, matching
/// `backend_freezer.rs`'s own `wait_until_frozen` (not exported, so this is a
/// small independent copy rather than an import) -- reusing that module's
/// public `is_frozen` parser rather than re-parsing the file format by hand.
fn wait_for_frozen(cgroup: &Path, want: bool) {
    let events = cgroup.join("cgroup.events");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let raw = std::fs::read_to_string(&events).expect("reading cgroup.events");
        if is_frozen(&raw) == Some(want) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not reach frozen={want} within 5s",
            events.display()
        );
        std::thread::sleep(Duration::from_micros(200));
    }
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

/// As `GateGuard`, but for the freezer: thaw on the way out no matter what,
/// so a panicking assertion never leaves a cgroup frozen underneath whatever
/// runs next.
struct FreezeGuard {
    cgroup: PathBuf,
}

impl Drop for FreezeGuard {
    fn drop(&mut self) {
        let _ = std::fs::write(self.cgroup.join("cgroup.freeze"), "0");
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

    // Hold well past the freezer's ~350us convergence window, and past any
    // plausible restart latency, so a restart would certainly have happened
    // if the gate perturbed the syscall the way the freezer does.
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
                             let its syscall restart, which is the freezer's failure mode, \
                             not the gate's"
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

#[test]
fn a_frozen_notification_id_does_not_survive_the_hold() {
    if skip_unless_root("a_frozen_notification_id_does_not_survive_the_hold") {
        return;
    }
    // Deliberately no `skip_unless_scheduler` here: this test never touches
    // `GateMap` or `scx_crfuzz_gated` -- it holds by writing `cgroup.freeze`
    // directly. It is the falsification half of this file's pair, so it must
    // run (and be able to fail) on a plain root shell with no scheduler
    // loaded at all, independently of the gate test above. Coupling both
    // tests to the same precondition would let one absent daemon silence
    // both halves of the discriminator at once -- do not re-add this guard
    // for symmetry with the test above.

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("threaded_victim");
    // Both arguments required; see the note on the row above.
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

    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/handle-stability-freeze")
        .with_per_spawn_cgroups(true)
        .with_poll_timeout(Duration::from_millis(50));
    let cgroup =
        PathBuf::from("/sys/fs/cgroup").join(backend.spawn_cgroup(0).trim_start_matches('/'));
    backend.attach(&[newfstatat_checkpoint()]).unwrap();

    let (pid, handle) = first_hit(&mut backend, Instant::now() + Duration::from_secs(10));

    std::fs::write(cgroup.join("cgroup.freeze"), "1").expect("freeze");
    wait_for_frozen(&cgroup, true);
    // Guards the thaw for any panic path below; the normal path also thaws
    // explicitly before release, per the comment there.
    let _guard = FreezeGuard {
        cgroup: cgroup.clone(),
    };

    // Same hold duration as the gate test: long enough that, if a restart
    // happens at all, it certainly happens inside this window.
    let mut second_notification: Option<NotifyHandle> = None;
    let hold_start = Instant::now();
    while hold_start.elapsed() < Duration::from_millis(300) {
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit {
                    pid: p, handle: h, ..
                } = e
                {
                    if p == pid && h != handle {
                        second_notification = Some(h);
                    }
                }
            }
        }
    }

    // Thaw before answering, on this path unconditionally -- not just the
    // success path. backend_freezer.rs's `thaw` explains why: "answering a
    // seccomp notification for a task that has not finished leaving the
    // freezer fails the SEND ioctl outright ('system failure beyond the
    // control of libseccomp')". Skipping this on a failure path would make
    // `release` fail for the wrong reason and corrupt the evidence below.
    std::fs::write(cgroup.join("cgroup.freeze"), "0").expect("thaw");
    wait_for_frozen(&cgroup, false);

    let release_result = backend.release(handle);

    // The freezer's known failure, asserted positively: EITHER a second
    // notification arrived for this pid under a different id, OR the
    // original id was no longer answerable. Both are consequences of the
    // same restart; only one needs to have happened.
    assert!(
        second_notification.is_some() || release_result.is_err(),
        "expected the freezer's known failure (backend_freezer.rs's header: a frozen \
         cgroup wakes a task parked in a seccomp notification, which restarts the \
         syscall and replaces the id) but neither symptom appeared: second \
         notification for pid {pid} = {second_notification:?}, release({handle:?}) = \
         {release_result:?}. If this test starts passing, the freezer has stopped \
         perturbing the syscall it holds, which is the discriminator this file exists \
         to check.",
    );
}
