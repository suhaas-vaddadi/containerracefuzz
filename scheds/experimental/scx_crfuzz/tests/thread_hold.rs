// SPDX-License-Identifier: GPL-2.0
//
// Thread-level holds: holding and releasing one thread of a multithreaded role
// without holding or releasing its siblings.
//
// A role is a thread group, and the group gate (`gate_group`) is
// all-or-nothing for the group. The watchdog freezes a single thread that
// cannot reach a checkpoint, which needs a hold keyed on the thread
// (`freeze`/`thaw`). Both run against a fixture whose workers never park on
// their own, so every byte of frozen progress is attributable to the gate and
// not to seccomp.
//
// Requires root (the seccomp listener fd is privileged) and the `sched_ext`
// gate, so it is gated and skipped elsewhere. Build the fixtures first:
//
//     cd scheds/experimental/scx_crfuzz/scenarios && make
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_gate::GateBackend;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::role::Pid;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

/// How many worker threads the fixture runs. Three: one to hold, and enough
/// others that "the siblings kept running" is a meaningful statement.
const WORKERS: usize = 3;

/// How long to sample progress to decide whether a thread is running. Workers
/// write every 1ms, so this window is worth ~150 bytes if a thread is free.
const OBSERVE: Duration = Duration::from_millis(150);

/// Give up waiting for the fixture's first checkpoint after this long.
const HIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-thread progress file lengths, `<prefix>.<i>` for i in 0..WORKERS.
fn progress_snapshot(prefix: &Path) -> Vec<u64> {
    (0..WORKERS)
        .map(|i| {
            std::fs::metadata(format!("{}.{}", prefix.display(), i))
                .map(|m| m.len())
                .unwrap_or(0)
        })
        .collect()
}

/// How many worker threads advanced during `OBSERVE`.
fn growing(prefix: &Path) -> usize {
    let before = progress_snapshot(prefix);
    std::thread::sleep(OBSERVE);
    let after = progress_snapshot(prefix);
    before.iter().zip(after).filter(|(b, a)| a > b).count()
}

/// The tids in a thread group, from `/proc/<tgid>/task`.
fn threads_of(tgid: Pid) -> Vec<Pid> {
    let mut tids: Vec<Pid> = std::fs::read_dir(format!("/proc/{tgid}/task"))
        .expect("reading /proc/<tgid>/task")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
        .collect();
    tids.sort_unstable();
    tids
}

/// Drop the backend -- which clears its gates -- then kill the group, on the
/// way out of a test, including a panicking assertion mid-hold. A gated thread
/// must be ungated before SIGKILL can be delivered: it is
/// runnable-but-never-dispatched, so it never runs to act on the signal.
struct HoldGuard {
    backend: Option<GateBackend>,
    tgid: Pid,
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        drop(self.backend.take());
        // SAFETY: kill is always safe to call; tgid is a live thread group the
        // test started.
        unsafe {
            libc::kill(self.tgid, libc::SIGKILL);
        }
    }
}

/// Spawn mt_hold under a `GateBackend` and drive it until the fixture's main
/// thread parks at its first `newfstatat`. Returns the guard owning the
/// backend, the main tid, the hit's handle, and the progress-file prefix.
fn parked_mt_hold(tag: &str, tmp: &Path) -> (HoldGuard, Pid, NotifyHandle, PathBuf) {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scenarios/fixtures/mt_hold");
    let target = tmp.join("target");
    let prefix = tmp.join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {} {}",
        fixture.display(),
        target.display(),
        prefix.display(),
        WORKERS
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], format!("/crfuzz/thread-hold-{tag}"))
        .with_sched_ext(true);
    let mut backend = GateBackend::new(seccomp).expect("gate backend");
    backend
        .attach(&[CheckpointDecl::syscall("newfstatat")])
        .unwrap();
    let (main_tid, handle) = first_hit(&mut backend);
    let guard = HoldGuard {
        backend: Some(backend),
        tgid: tgid_of(main_tid),
    };
    (guard, main_tid, handle, prefix)
}

/// Drive a backend until the fixture's main thread parks at its first
/// checkpoint. Returns `(main_tid, handle)`.
fn first_hit(backend: &mut impl CheckpointBackend) -> (Pid, NotifyHandle) {
    let deadline = Instant::now() + HIT_TIMEOUT;
    while Instant::now() < deadline {
        if let Poll::Events(events) = backend.poll(Some(Duration::from_millis(50))).expect("poll") {
            for e in events {
                if let BackendEvent::CheckpointHit { pid, handle, .. } = e {
                    return (pid, handle);
                }
            }
        }
    }
    panic!("the fixture never reached a checkpoint within {HIT_TIMEOUT:?}");
}

#[test]
fn a_worker_thread_is_held_and_released_without_its_siblings() {
    if skip_unless_root("a_worker_thread_is_held_and_released_without_its_siblings") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut guard, main_tid, handle, prefix) = parked_mt_hold("thread", tmp.path());
    let backend = guard.backend.as_mut().unwrap();

    // The worker to hold: any thread of the group that is not the main thread.
    let worker = *threads_of(guard.tgid)
        .iter()
        .find(|t| **t != main_tid)
        .expect("the group has more than the main thread");

    // Sanity: with nothing gated, every worker is making progress. Without this
    // the "frozen" assertion below could pass vacuously.
    assert_eq!(
        growing(&prefix),
        WORKERS,
        "all {WORKERS} workers must be running before the hold"
    );

    // Hold exactly one worker thread.
    backend.freeze(worker).unwrap();
    assert_eq!(
        growing(&prefix),
        WORKERS - 1,
        "freezing tid {worker} must hold exactly one worker, not the group"
    );

    // Release the main thread's parked syscall. The held worker must stay held:
    // a per-thread hold is not undone by releasing a different thread.
    backend.release(handle).unwrap();
    assert_eq!(
        growing(&prefix),
        WORKERS - 1,
        "releasing the main thread must not release the held worker"
    );

    // Now release the worker.
    backend.thaw(worker).unwrap();
    assert_eq!(
        growing(&prefix),
        WORKERS,
        "thawing tid {worker} must let that worker run again"
    );
}

#[test]
fn gating_the_group_freezes_every_sibling_and_ungating_frees_them() {
    if skip_unless_root("gating_the_group_freezes_every_sibling_and_ungating_frees_them") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut guard, _, handle, prefix) = parked_mt_hold("group", tmp.path());
    let tgid = guard.tgid;
    let backend = guard.backend.as_mut().unwrap();

    assert_eq!(growing(&prefix), WORKERS, "a hit alone freezes no sibling");
    backend.gate_group(tgid).unwrap();
    assert_eq!(growing(&prefix), 0, "a gated group must freeze every sibling");
    backend.ungate_group(tgid).unwrap();
    backend.release(handle).unwrap();
    assert_eq!(growing(&prefix), WORKERS, "and ungating must free them");
}

#[test]
fn nothing_a_parked_thread_did_before_its_hit_arrives_after_it() {
    // mt_hold's main thread and every worker call `nanosleep`; with it the
    // checkpoint and nothing released, all of them park on the one listener
    // fd, often several at once. The gate's poll reads notifications before
    // it drains records, so the wakeups that let a thread reach its syscall
    // are delivered ahead of its hit, and the thread's last record is the
    // `Asleep` of its park (which may come before or after the hit).
    if skip_unless_root("nothing_a_parked_thread_did_before_its_hit_arrives_after_it") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }
    use scx_crfuzz::backend::ThreadStateKind;

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scenarios/fixtures/mt_hold");
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {} {}",
        fixture.display(),
        target.display(),
        tmp.path().join("progress").display(),
        WORKERS
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/thread-hold-asleep")
        .with_sched_ext(true);
    let mut backend = GateBackend::new(seccomp).expect("gate backend");
    backend
        .attach(&[CheckpointDecl::syscall("clock_nanosleep")])
        .unwrap();

    let mut seen = Vec::new();
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        if let Poll::Events(events) = backend.poll(Some(Duration::from_millis(50))).unwrap() {
            seen.extend(events);
        }
    }
    let hits: Vec<(usize, Pid)> = seen
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            BackendEvent::CheckpointHit { pid, .. } => Some((i, *pid)),
            _ => None,
        })
        .collect();
    let tgid = tgid_of(hits.first().expect("nothing parked").1);
    let _guard = HoldGuard {
        backend: Some(backend),
        tgid,
    };
    assert_eq!(hits.len(), WORKERS + 1, "every thread parks once: {hits:?}");
    for (at, tid) in hits {
        let own: Vec<(usize, ThreadStateKind)> = seen
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                BackendEvent::ThreadState { tid: t, kind, .. } if *t == tid => Some((i, *kind)),
                _ => None,
            })
            .collect();
        // Nothing is released, so nothing wakes it after it parks.
        let woken = own.iter().find(|(i, k)| {
            *i > at && matches!(k, ThreadStateKind::WakeStart | ThreadStateKind::WakeDone)
        });
        assert!(woken.is_none(), "tid {tid}: {woken:?} after its hit at {at}");
        assert_eq!(
            own.last().map(|(_, k)| *k),
            Some(ThreadStateKind::Asleep),
            "tid {tid} ends asleep in its park"
        );
    }
}
