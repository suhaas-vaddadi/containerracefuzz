//! Milestone 3 spike: the `/proc` double-snapshot sensor. Needs root, a running
//! scx_crfuzz_gated, `cc` and `go`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

mod common;
use common::{go_bin, trigger_file};

use scx_crfuzz::backend::{Event, GateBackend};
use scx_crfuzz::sensor::{quiescent, snapshot, wait_frontier};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_millis(1);

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
    GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap()
}

struct Reach {
    /// Rounds of the deciding wait_frontier call; None = deadline hit.
    rounds: Option<u32>,
    /// Wall time of the last wait_frontier call (the decision latency).
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
    let mut held = Vec::new();
    loop {
        let t = Instant::now();
        let rounds = wait_frontier(be, &mut held, INTERVAL, deadline).unwrap();
        let r = Reach { rounds, last: t.elapsed(), held: std::mem::take(&mut held) };
        if rounds.is_none() || r.trigger_held(trigger) {
            return r;
        }
        r.held.iter().for_each(|e| be.release(e).unwrap());
    }
}

fn parked(r: &Reach) -> BTreeSet<u32> {
    r.held.iter().map(|e| e.tid).collect()
}

/// Spec §4 milestone 3: a thread blocked on a futex doesn't stall the readout.
#[test]
#[ignore]
fn futex_blocked_thread_reaches_decision() {
    let trigger = trigger_file("crfuzz_sensor_block");
    let mut be = spawn_c("block", &trigger, "");
    let r = reach(&mut be, &trigger, Duration::from_secs(2));
    let (snap, p) = (snapshot(be.cgroup()), parked(&r));
    let states: Vec<(char, bool)> = snap.iter().map(|(t, &(s, _))| (s as char, p.contains(t))).collect();
    eprintln!("block: rounds {:?} in {:?}; (state, parked) per thread {states:?}", r.rounds, r.last);
    assert!(r.rounds.is_some(), "stalled with a futex-blocked thread");
    assert!(r.trigger_held(&trigger));
}

/// A spinning thread is Running forever: never decide, even with the trigger held.
#[test]
#[ignore]
fn spinning_thread_never_decides() {
    let trigger = trigger_file("crfuzz_sensor_spin");
    let mut be = spawn_c("spin", &trigger, "");
    let r = reach(&mut be, &trigger, Duration::from_secs(1));
    eprintln!("spin: rounds {:?}, trigger held {}", r.rounds, r.trigger_held(&trigger));
    assert!(r.rounds.is_none(), "decided while a thread was spinning");
    assert!(r.trigger_held(&trigger), "trigger never trapped");
}

/// Two threads handing a byte back and forth: one is always running or about
/// to. Compares a naive single snapshot ("nobody R") with the double snapshot.
#[test]
#[ignore]
fn pingpong_never_quiescent() {
    let trigger = trigger_file("crfuzz_sensor_pingpong");
    let mut be = spawn_c("pingpong", &trigger, "");
    let r = reach(&mut be, &trigger, Duration::from_secs(1));
    assert!(r.rounds.is_none(), "decided during ping-pong");
    let p = parked(&r);
    let n = 20_000;
    let mut prev = snapshot(be.cgroup());
    let (mut single, mut double) = (0, 0);
    for _ in 0..n {
        let now = snapshot(be.cgroup());
        single += now.iter().all(|(t, &(s, _))| p.contains(t) || s != b'R') as u32;
        double += quiescent(&prev, &now, &p) as u32;
        prev = now;
    }
    eprintln!("pingpong: false 'quiescent' in {n} back-to-back snapshots: single {single}, double {double}");
    assert_eq!(double, 0, "double snapshot reported quiescence during ping-pong");
}

/// A thread waking on a timer: it is Blocked between ticks, so deciding is
/// allowed, but B has to find a quiet window spanning two snapshots.
#[test]
#[ignore]
fn periodic_ticker_settle() {
    for us in ["50", "200", "1000", "10000"] {
        let trigger = trigger_file("crfuzz_sensor_tick");
        let mut be = spawn_c("tick", &trigger, us);
        let mut held = reach(&mut be, &trigger, Duration::from_secs(2)).held;
        // Re-decide 20 times with the trigger still parked; the ticker keeps ticking.
        let samples: Vec<_> = (0..20)
            .map(|_| {
                let t = Instant::now();
                let deadline = Instant::now() + Duration::from_secs(1);
                (wait_frontier(&mut be, &mut held, INTERVAL, deadline).unwrap(), t.elapsed().as_micros())
            })
            .collect();
        eprintln!("tick {us}us: 20 decisions (rounds, µs) {samples:?}");
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
        let mut be = GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap();
        let r = reach(&mut be, &trigger, Duration::from_secs(2));
        assert!(r.rounds.is_some(), "run {i}: Go stalled the readout");
        assert!(r.trigger_held(&trigger));
        let snap = snapshot(be.cgroup());
        if i == 0 {
            let states: String = snap.values().map(|&(s, _)| s as char).collect();
            let t = Instant::now();
            for _ in 0..1000 {
                snapshot(be.cgroup());
            }
            eprintln!("go: {} threads, states {states}; snapshot cost {:?}", snap.len(), t.elapsed() / 1000);
        }
        lat.push((r.rounds.unwrap(), r.last.as_micros()));
    }
    lat.sort_by_key(|l| l.1);
    eprintln!("go: 20 runs (rounds, µs) sorted {lat:?}");
}

/// What a gated runnable thread looks like: the spec says a tree-gated thread
/// reads Running. A spinning thread under a tree hold should be `R` with frozen
/// cpu time; a futex-blocked one stays `S`, so the frontier can look complete
/// during a tree hold.
#[test]
#[ignore]
fn gated_threads_under_tree_hold() {
    for mode in ["spin", "block"] {
        let trigger = trigger_file("crfuzz_sensor_gated");
        let mut be = spawn_c(mode, &trigger, "");
        let r = reach(&mut be, &trigger, Duration::from_secs(1));
        assert!(r.trigger_held(&trigger));
        be.gate_tree().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let a = snapshot(be.cgroup());
        std::thread::sleep(Duration::from_millis(50));
        let b = snapshot(be.cgroup());
        let mut held = r.held;
        let decided = wait_frontier(&mut be, &mut held, INTERVAL, Instant::now() + Duration::from_millis(300)).unwrap();
        eprintln!("{mode} under tree hold: {a:?} -> {b:?}; wait_frontier {decided:?}");
        be.ungate_tree().unwrap();
    }
}
