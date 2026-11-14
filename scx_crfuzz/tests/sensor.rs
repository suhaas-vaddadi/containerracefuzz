//! The readout sensor: the scheduler's count of the tree's runnable tasks. Needs root, a running
//! `scx_crfuzz gated`, `cc` and `go`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::{go_bin, trigger_file};

use scx_crfuzz::backend::{Event, GateBackend};
use scx_crfuzz::sensor::{wait_frontier, Frontier};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn c_bin() -> PathBuf {
    let out = std::env::temp_dir().join("crfuzz_sensor");
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sensor.c");
    let ok = Command::new("cc").args(["-O2", "-pthread", "-o"]).arg(&out).arg(src).status().unwrap().success();
    assert!(ok, "cc failed");
    out
}

fn spawn_c(mode: &str, trigger: &Path, arg: &str) -> GateBackend {
    let mut cmd = Command::new(c_bin());
    cmd.arg(mode).arg(trigger).arg(arg);
    GateBackend::spawn(cmd, &[]).unwrap()
}

struct Reach {
    /// How the deciding wait_frontier call ended.
    end: Frontier,
    /// Its wall time (the decision latency).
    last: Duration,
    held: Vec<Event>,
}

impl Reach {
    fn trigger_held(&self, trigger: &Path) -> bool {
        self.held.iter().any(|e| e.path.as_deref() == Some(trigger))
    }
}

/// Decide-and-release every frontier until one holds `trigger` (or the deadline).
fn reach(be: &mut GateBackend, trigger: &Path, deadline: Duration) -> Reach {
    let deadline = Instant::now() + deadline;
    let (mut held, mut idle) = (Vec::new(), false);
    loop {
        let t = Instant::now();
        let end = wait_frontier(be, &mut held, deadline, idle).unwrap();
        let r = Reach { end, last: t.elapsed(), held: std::mem::take(&mut held) };
        if r.end != Frontier::Complete || r.trigger_held(trigger) {
            return r;
        }
        idle = r.held.is_empty();
        r.held.iter().for_each(|e| be.release(e).unwrap());
    }
}

/// A thread blocked on a futex doesn't stall the readout.
#[test]
#[ignore]
fn futex_blocked_thread_reaches_decision() {
    let trigger = trigger_file("crfuzz_sensor_block");
    let mut be = spawn_c("block", &trigger, "");
    let r = reach(&mut be, &trigger, Duration::from_secs(2));
    eprintln!("block: {:?} in {:?}", r.end, r.last);
    assert_eq!(r.end, Frontier::Complete, "stalled with a futex-blocked thread");
    assert!(r.trigger_held(&trigger));
}

/// A spinning thread is runnable forever: never complete, even with the trigger held.
#[test]
#[ignore]
fn spinning_thread_never_decides() {
    let trigger = trigger_file("crfuzz_sensor_spin");
    let mut be = spawn_c("spin", &trigger, "");
    let r = reach(&mut be, &trigger, Duration::from_secs(1));
    assert_eq!(r.end, Frontier::Partial, "complete while a thread was spinning");
    assert!(r.trigger_held(&trigger), "trigger never trapped");
}

/// Two threads handing a byte back and forth: one is always running or being
/// woken, and the count never misses the handoff (a wakeup in flight to
/// another CPU is counted from `sched_waking`).
#[test]
#[ignore]
fn pingpong_never_quiet() {
    let trigger = trigger_file("crfuzz_sensor_pingpong");
    let mut be = spawn_c("pingpong", &trigger, "");
    let r = reach(&mut be, &trigger, Duration::from_secs(1));
    assert_eq!(r.end, Frontier::Partial, "complete during ping-pong");
    let n = 20_000;
    let quiet = (0..n).filter(|_| be.quiet().unwrap()).count();
    assert_eq!(quiet, 0, "the tree read quiet in {quiet} of {n} reads during ping-pong");
}

/// A thread waking on a timer: it is asleep between ticks, so a frontier is
/// complete then (the determinism claim leaves timed sleepers out).
#[test]
#[ignore]
fn periodic_ticker_settle() {
    for us in ["50", "200", "1000", "10000"] {
        let trigger = trigger_file("crfuzz_sensor_tick");
        let mut be = spawn_c("tick", &trigger, us);
        let r = reach(&mut be, &trigger, Duration::from_secs(2));
        assert!(r.trigger_held(&trigger));
        // Mid-sleep nearly always; only the long tick is sure to be.
        if us == "10000" {
            assert_eq!(be.sleepers(&r.held), 1, "the ticker is a timed sleeper");
        }
        let mut held = r.held;
        // Re-decide 20 times with the trigger still parked; the ticker keeps ticking.
        let samples: Vec<_> = (0..20)
            .map(|_| {
                let t = Instant::now();
                let deadline = Instant::now() + Duration::from_secs(1);
                (wait_frontier(&mut be, &mut held, deadline, false).unwrap(), t.elapsed().as_micros())
            })
            .collect();
        eprintln!("tick {us}us: 20 decisions (frontier, µs) {samples:?}");
    }
}

/// Go: one goroutine parked at openat, main blocked on a channel, runtime
/// threads (sysmon, idle Ms) left alone. Must settle, repeatedly.
#[test]
#[ignore]
fn go_channel_blocked_reaches_decision() {
    let bin = go_bin("go_chan");
    let mut lat = Vec::new();
    for i in 0..20 {
        let trigger = trigger_file("crfuzz_sensor_go");
        let mut cmd = Command::new(&bin);
        cmd.arg(&trigger);
        let mut be = GateBackend::spawn(cmd, &[]).unwrap();
        let r = reach(&mut be, &trigger, Duration::from_secs(2));
        assert_eq!(r.end, Frontier::Complete, "run {i}: Go stalled the readout");
        assert!(r.trigger_held(&trigger));
        lat.push(r.last.as_micros());
    }
    lat.sort();
    eprintln!("go: 20 runs, µs sorted {lat:?}");
}

/// Under a tree hold a spinning thread stays runnable (it waits on the hold
/// queue), so the tree is not quiet; a futex-blocked one is asleep, so the
/// frontier reads complete during the hold (the engine never decides there).
#[test]
#[ignore]
fn gated_threads_under_tree_hold() {
    for (mode, want) in [("spin", Frontier::Partial), ("block", Frontier::Complete)] {
        let trigger = trigger_file("crfuzz_sensor_gated");
        let mut be = spawn_c(mode, &trigger, "");
        let r = reach(&mut be, &trigger, Duration::from_secs(1));
        assert!(r.trigger_held(&trigger));
        be.gate_tree().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut held = r.held;
        let decided = wait_frontier(&mut be, &mut held, Instant::now() + Duration::from_millis(300), false).unwrap();
        be.ungate_tree().unwrap();
        assert_eq!(decided, want, "{mode} under a tree hold");
    }
}
