// SPDX-License-Identifier: GPL-2.0
//
// A spawned target must land in SCHED_EXT, and so must every thread and child
// it goes on to create -- scheduling policy is inherited across fork and
// CLONE_THREAD, which is what lets one call before exec enroll a whole tree
// without the engine chasing descendants.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Scheduling policy of a task, from field 41 of /proc/<pid>/stat.
///
/// Read from `stat` rather than `sched_getscheduler` so the assertion covers
/// threads this process never spawned.
fn policy(pid: i32) -> Option<i64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &raw[raw.rfind(')')? + 2..];
    tail.split_whitespace().nth(38)?.parse().ok()
}

#[test]
fn a_spawned_target_and_its_threads_are_in_sched_ext() {
    if unsafe { libc::getuid() } != 0 {
        eprintln!("skipping: needs root (seccomp listener)");
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("threaded_victim");
    assert!(
        fixture.exists(),
        "build the fixture first: `cd {} && make`",
        fixture.parent().unwrap().display()
    );

    // threaded_victim requires <path> <progress_path>; without them it prints
    // usage and exits before ever creating its sibling thread, which would
    // make the multi-thread assertion below vacuous.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();

    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .unwrap();
    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/enroll")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    // Only fstatat: the fixture's own progress-file open() is also a
    // structural syscall (openat), and it runs before the sibling thread is
    // created. Attaching the full discovery set would hold the target there
    // instead of at its intended CHECK point, making the multi-thread
    // assertion below vacuous. thread_group_holding.rs uses this same narrow
    // set for the same fixture and the same reason.
    backend
        .attach(&[CheckpointDecl {
            id: CheckpointId::new("fstatat"),
            kind: CheckpointKind::Syscall,
            target: "fstatat".into(),
            category: None,
        }])
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut held = None;
    while Instant::now() < deadline && held.is_none() {
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit { pid, .. } = e {
                    held = Some(pid);
                }
            }
        }
    }
    let pid = held.expect("the fixture never reached a checkpoint");

    const SCHED_EXT: i64 = 7;
    assert_eq!(
        policy(pid),
        Some(SCHED_EXT),
        "the held task is in SCHED_EXT"
    );

    let tgid_dir = format!("/proc/{pid}/task");
    let threads: Vec<i32> = std::fs::read_dir(&tgid_dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    assert!(
        threads.len() >= 2,
        "the fixture is multi-threaded: {threads:?}"
    );
    for t in threads {
        assert_eq!(policy(t), Some(SCHED_EXT), "thread {t} inherited SCHED_EXT");
    }
}
