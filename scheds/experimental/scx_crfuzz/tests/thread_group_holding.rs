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
use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use scx_crfuzz::role::Pid;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// How long to let the held role sit before re-measuring its sibling. The
/// fixture's sibling writes every 1ms, so a backend that does not hold the
/// thread group will grow the progress file by roughly this many bytes.
const OBSERVE: Duration = Duration::from_millis(300);

/// Give up waiting for the first checkpoint after this long.
const HIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Both tests here install a seccomp listener and write to `cgroup.freeze`,
/// which need privilege. Skipping rather than failing keeps a plain
/// `cargo test` green for anyone; the VM runs them under sudo.
///
/// Returns true if the test should stop.
fn skip_unless_root(test: &str) -> bool {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } == 0 {
        return false;
    }
    eprintln!("skipping {test}: needs root (seccomp listener + cgroup.freeze)");
    true
}

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scenarios")
}

fn progress_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// How many OS threads a thread group currently has.
fn thread_count(pid: Pid) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|d| d.count())
        .unwrap_or(0)
}

/// Which `--spawn` a pid belongs to, read back from the `spawn<N>` cgroup
/// `with_per_spawn_cgroups` placed it in.
fn spawn_index(pid: Pid) -> Option<usize> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = raw.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    path.rsplit('/').next()?.strip_prefix("spawn")?.parse().ok()
}

/// Drive a backend until one of its tasks is held at a checkpoint, then report
/// how much the sibling thread wrote while it was held.
///
/// Returns `(bytes_at_hit, bytes_after_observing)`.
fn sibling_progress_while_held<B: CheckpointBackend>(
    backend: &mut B,
    progress: &Path,
) -> (u64, u64) {
    let (a, b, _) = sibling_progress_and_pid_while_held(backend, progress);
    (a, b)
}

/// As `sibling_progress_while_held`, plus the pid that was held -- needed when
/// a test wants to say something about the thread group itself.
///
/// Returns `(bytes_at_hit, bytes_after_observing, held_pid)`.
fn sibling_progress_and_pid_while_held<B: CheckpointBackend>(
    backend: &mut B,
    progress: &Path,
) -> (u64, u64, Pid) {
    let checkpoints = vec![CheckpointDecl {
        id: CheckpointId::new("newfstatat"),
        kind: CheckpointKind::Syscall,
        target: "newfstatat".into(),
        category: None,
    }];
    backend.attach(&checkpoints).expect("attach");

    let deadline = Instant::now() + HIT_TIMEOUT;
    loop {
        assert!(
            Instant::now() < deadline,
            "no checkpoint hit within {HIT_TIMEOUT:?}; is the fixture built and running?"
        );
        match backend.poll().expect("poll") {
            Poll::Events(events) => {
                if let Some(pid) = events.iter().find_map(|e| match e {
                    BackendEvent::CheckpointHit { pid, .. } => Some(*pid),
                    _ => None,
                }) {
                    // The main thread is now parked inside the kernel. Whatever
                    // the sibling writes from here on is a thread that the role
                    // contract says should be held.
                    let at_hit = progress_len(progress);
                    std::thread::sleep(OBSERVE);
                    return (at_hit, progress_len(progress), pid);
                }
            }
            Poll::Idle => {}
            Poll::Closed => panic!("backend closed before any checkpoint was hit"),
        }
    }
}

#[test]
fn holding_a_role_holds_every_thread_in_its_thread_group() {
    if skip_unless_root("holding_a_role_holds_every_thread_in_its_thread_group") {
        return;
    }
    let dir = scenarios_dir();
    let fixture = dir.join("threaded_victim");
    assert!(
        fixture.exists(),
        "build the fixture first: `cd {} && make`",
        dir.display()
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();

    let spec = scx_crfuzz::backend_seccomp::ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");

    let seccomp =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/threadgroup");
    let mut backend = scx_crfuzz::backend_freezer::FreezerBackend::new(seccomp);

    let (at_hit, after) = sibling_progress_while_held(&mut backend, &progress);

    assert_eq!(
        after,
        at_hit,
        "sibling thread wrote {} bytes while its thread group was supposed to be held \
         (design doc Background: \"holding a role back means holding every thread of that \
         thread group\")",
        after - at_hit
    );
}

/// Releasing one role must not release another.
///
/// The freezer works on whatever cgroup the held task is in, so if every role
/// shares one cgroup, thawing to release role A thaws role B along with it --
/// and `Enforcing` ("hold every role back except the one named by the current
/// step") silently stops holding anything. This is what
/// `with_per_spawn_cgroups` exists to prevent.
#[test]
fn releasing_one_role_leaves_the_other_role_held() {
    if skip_unless_root("releasing_one_role_leaves_the_other_role_held") {
        return;
    }
    let dir = scenarios_dir();
    let fixture = dir.join("threaded_victim");
    assert!(
        fixture.exists(),
        "build the fixture first: `cd {} && make`",
        dir.display()
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    std::fs::write(&target, "BENIGN\n").unwrap();

    let progress: Vec<PathBuf> = (0..2).map(|i| tmp.path().join(format!("p{i}"))).collect();
    let specs = progress
        .iter()
        .map(|p| {
            scx_crfuzz::backend_seccomp::ProcessSpec::parse(&format!(
                "{} {} {}",
                fixture.display(),
                target.display(),
                p.display()
            ))
            .expect("spec")
        })
        .collect();

    let seccomp = scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(specs, "/crfuzz/tworoles")
        .with_per_spawn_cgroups(true);
    let mut backend = scx_crfuzz::backend_freezer::FreezerBackend::new(seccomp);

    backend
        .attach(&[CheckpointDecl {
            id: CheckpointId::new("newfstatat"),
            kind: CheckpointKind::Syscall,
            target: "newfstatat".into(),
            category: None,
        }])
        .expect("attach");

    // Collect one hit per role, so both thread groups are frozen before any
    // release happens.
    let mut hits: Vec<(Pid, NotifyHandle)> = Vec::new();
    let deadline = Instant::now() + HIT_TIMEOUT;
    while hits.len() < 2 {
        assert!(
            Instant::now() < deadline,
            "only {} of 2 roles reached a checkpoint within {HIT_TIMEOUT:?}",
            hits.len()
        );
        if let Poll::Events(events) = backend.poll().expect("poll") {
            for e in &events {
                if let BackendEvent::CheckpointHit { pid, handle, .. } = e {
                    if !hits.iter().any(|(p, _)| p == pid) {
                        hits.push((*pid, *handle));
                    }
                }
            }
        }
    }

    // Release one role; the OTHER must stay exactly where it is.
    //
    // Which role reached its checkpoint first is not fixed -- that is the
    // crate's own section 14-A nondeterminism, and it bit this test before it
    // keyed the progress file off the pid instead of the hit order.
    let released_spawn = spawn_index(hits[0].0).expect("released role's spawn index");
    let still_held = progress[1 - released_spawn].clone();
    let before = progress_len(&still_held);
    backend.release(hits[0].1).expect("release");
    std::thread::sleep(OBSERVE);
    let after = progress_len(&still_held);

    assert_eq!(
        after,
        before,
        "releasing one role let the other role's sibling thread write {} bytes; the two \
         roles are sharing a freezer",
        after - before
    );
}

/// The same property as the pthreads test, against the runtime that makes it
/// matter.
///
/// Go multiplexes goroutines onto OS threads, and `sysmon` responds to a thread
/// blocked in a syscall by handing its work to another M -- so holding one
/// thread in a seccomp notification is the very thing that provokes the runtime
/// into running more threads. runc and containerd are Go; this is the shape of
/// the real target, minus 50k lines.
#[test]
fn holding_a_go_role_holds_every_thread_the_runtime_is_using() {
    if skip_unless_root("holding_a_go_role_holds_every_thread_the_runtime_is_using") {
        return;
    }
    let dir = scenarios_dir();
    let fixture = dir.join("go_victim");
    assert!(
        fixture.exists(),
        "build the fixture first: `cd {} && make`",
        dir.display()
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();

    let spec = scx_crfuzz::backend_seccomp::ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");

    let seccomp =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/goroutines")
            .with_per_spawn_cgroups(true);
    let mut backend = scx_crfuzz::backend_freezer::FreezerBackend::new(seccomp);

    let (at_hit, after, pid) = sibling_progress_and_pid_while_held(&mut backend, &progress);

    // The fixture pins one M per sibling plus the main goroutine, so a hold
    // that only caught the checkpointed thread would be leaving several
    // runnable. Stated as a number so the test fails loudly if a future
    // runtime or GOMAXPROCS change makes it vacuous.
    let threads = thread_count(pid);
    assert!(
        threads >= 5,
        "expected the Go runtime to be using at least 5 OS threads (1 main + 4 pinned \
         siblings), saw {threads}; this test proves nothing if the group is single-threaded"
    );

    assert_eq!(
        after,
        at_hit,
        "{} of the Go thread group's {threads} OS threads kept running while the role was \
         held: the sibling goroutines wrote {} bytes",
        "some",
        after - at_hit
    );
}
