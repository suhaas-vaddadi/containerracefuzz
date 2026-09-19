// SPDX-License-Identifier: GPL-2.0
//
// The engine decides a run has stalled after `MAX_IDLE_ROUNDS` consecutive
// idle polls. That budget is only meaningful if an idle poll actually *waits*:
// the count is a proxy for elapsed time, and nothing else in the engine
// measures wall-clock progress.
//
// A backend that can return `Poll::Idle` without blocking therefore does not
// merely waste CPU -- it silently converts the engine's multi-second stall
// timeout into a microsecond one, and the run is declared dead while its
// processes are still alive and making progress.
//
// That is not hypothetical. When a held child exits, its seccomp notify fd
// reports POLLHUP rather than POLLIN. POLLHUP is level-triggered and never
// clears, so `poll(2)` returns *immediately* and keeps returning immediately
// for as long as the fd stays in the set. Between the moment a child exits and
// the moment `waitpid` can reap it there is a window, and in that window the
// backend spins. A single-threaded C child tears down fast enough to be reaped
// inside the budget; an 11-thread Go child does not, so its exit is never
// reported and the engine waits forever for a role that has already gone.
//
// Requires root (the seccomp listener fd is privileged) and Linux. Build the
// fixture first:
//
//     cd scheds/experimental/scx_crfuzz/scenarios && make
//
// Everything here lives in one test on purpose. `reap` calls `waitpid(None)`,
// which is process-wide, so two backends running concurrently in one test
// binary would reap each other's children and neither would see its own exit.
// The engine only ever constructs one backend, so this constrains the test
// rather than the code.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Mirrors `engine::MAX_IDLE_ROUNDS`. Not imported, because the point of the
/// test is that the engine's constant means what the engine thinks it means.
const MAX_IDLE_ROUNDS: usize = 64;

/// The backend's default poll timeout, and so the floor on what one idle poll
/// should cost.
const POLL_TIMEOUT: Duration = Duration::from_millis(50);

/// Well under `MAX_IDLE_ROUNDS * POLL_TIMEOUT` (3.2s), and far above anything a
/// spin could reach. Loose on purpose: this is asserting that idle polls wait
/// at all, not that they wait precisely.
const MIN_BUDGET: Duration = Duration::from_millis(500);

fn skip_unless_root(test: &str) -> bool {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } == 0 {
        return false;
    }
    eprintln!("skipping {test}: needs root (seccomp listener)");
    true
}

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scenarios")
}

/// Drive a multi-threaded child to completion, releasing every checkpoint
/// immediately, and report `(longest run of consecutive idle polls, how long
/// that run took, whether the exit was ever seen)`.
fn drive_to_exit(tag: &str) -> (usize, Duration, bool) {
    let dir = scenarios_dir();
    let tmp = std::env::temp_dir().join(format!("crfuzz-{tag}"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("tmp");
    std::fs::write(tmp.join("target"), "BENIGN\n").expect("target");

    let spec = scx_crfuzz::backend_seccomp::ProcessSpec::parse(&format!(
        "{}/go_victim {}/target {}/progress",
        dir.display(),
        tmp.display(),
        tmp.display()
    ))
    .expect("spec");

    let mut backend = scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(
        vec![spec],
        &format!("/crfuzz/{tag}"),
    );
    backend
        .attach(&[CheckpointDecl {
            id: CheckpointId::new("newfstatat"),
            kind: CheckpointKind::Syscall,
            target: "newfstatat".into(),
            category: None,
        }])
        .expect("attach");

    let mut saw_exit = false;
    let mut idle_run = 0usize;
    let mut idle_since = Instant::now();
    let mut worst = (0usize, Duration::ZERO);
    let deadline = Instant::now() + Duration::from_secs(30);

    while Instant::now() < deadline {
        match backend.poll().expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {
                if idle_run == 0 {
                    idle_since = Instant::now();
                }
                idle_run += 1;
                if idle_run > worst.0 {
                    worst = (idle_run, idle_since.elapsed());
                }
                // The engine gives up here, so the test must too -- otherwise
                // it would wait out a stall the engine would never survive.
                if idle_run >= MAX_IDLE_ROUNDS {
                    break;
                }
            }
            Poll::Events(events) => {
                idle_run = 0;
                for e in events {
                    match e {
                        BackendEvent::CheckpointHit { handle, .. } => {
                            backend.release(handle).expect("release");
                        }
                        BackendEvent::TaskExited(_) => saw_exit = true,
                        BackendEvent::TaskAppeared(_) => {}
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    (worst.0, worst.1, saw_exit)
}

/// Both halves of the same drive: idle polls must cost real time, and a
/// multi-threaded child's exit must be reported while the engine is still
/// listening.
#[test]
fn a_multi_threaded_child_exit_is_reported_before_the_stall_budget_runs_out() {
    if skip_unless_root("a_multi_threaded_child_exit_is_reported_before_the_stall_budget_runs_out")
    {
        return;
    }
    let (longest, took, saw_exit) = drive_to_exit("goexit");

    // The root cause. A run of idle polls that costs nothing turns the engine's
    // multi-second stall timeout into a microsecond one.
    if longest >= MAX_IDLE_ROUNDS {
        assert!(
            took >= MIN_BUDGET,
            "{longest} consecutive idle polls took only {took:?}; the engine treats \
             {MAX_IDLE_ROUNDS} idle polls as a stall and expects that to mean at least \
             {MIN_BUDGET:?} of real time (poll timeout {POLL_TIMEOUT:?}). The backend is spinning.",
        );
    }

    // The symptom it causes: `until: exit` can never be satisfied for a Go role.
    assert!(
        saw_exit,
        "the Go child ran to completion but its exit was never reported; a role \
         waiting on `until: exit` would wait forever (longest idle run {longest} \
         polls over {took:?})"
    );
}
