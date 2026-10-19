//! Readout sensor (spec §3.4), `/proc` double-snapshot variant (M3 spike).
//!
//! Two snapshots of the run cgroup's threads with the same tid set, no thread
//! `R`, and unchanged on-CPU time mean every thread slept through the gap
//! between them: a moment when no SUT thread ran. Threads we hold are exempt. Per thread, state is read
//! before cpu time, so a wakeup after the state read shows as `R` or moved time
//! in the next snapshot.

use crate::backend::{cgroup_dirs, Event, GateBackend, Poll};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// tid -> (state char from /proc/<tid>/stat, ns on CPU from schedstat).
pub type Snap = BTreeMap<u32, (u8, u64)>;

pub fn snapshot(cgroup: &Path) -> Snap {
    let mut snap = Snap::new();
    for dir in cgroup_dirs(cgroup) {
        let Ok(tids) = fs::read_to_string(dir.join("cgroup.threads")) else { continue };
        for tid in tids.lines().filter_map(|l| l.parse().ok()) {
            if let Some(t) = read_thread(tid) {
                snap.insert(tid, t);
            }
        }
    }
    snap
}

/// None: the thread is gone (Exited).
fn read_thread(tid: u32) -> Option<(u8, u64)> {
    let stat = fs::read_to_string(format!("/proc/{tid}/stat")).ok()?;
    // comm may hold spaces and parens; state follows the last ')'.
    let state = *stat.get(stat.rfind(')')? + 2..)?.as_bytes().first()?;
    let sched = fs::read_to_string(format!("/proc/{tid}/schedstat")).ok()?;
    Some((state, sched.split_whitespace().next()?.parse().ok()?))
}

/// No SUT thread ran between `a` and `b`. `parked` threads (held by us) count
/// as stopped whatever their state.
pub fn quiescent(a: &Snap, b: &Snap, parked: &BTreeSet<u32>) -> bool {
    a.keys().eq(b.keys())
        && b.iter().all(|(tid, &(st, ns))| parked.contains(tid) || (st != b'R' && a[tid] == (st, ns)))
}

/// The SUT tree is gone: there is no frontier to decide on. Not a stall; a run
/// ends this way. Check with `err.is::<Exited>()`.
#[derive(Debug)]
pub struct Exited;

impl std::fmt::Display for Exited {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("SUT exited")
    }
}

impl std::error::Error for Exited {}

/// Wait until no SUT thread is running, adding every syscall held meanwhile to
/// `held` (the frontier). Returns the snapshot rounds it took, None at
/// `deadline`, or `Exited` once the SUT has no threads left (an empty snapshot
/// is vacuously quiescent). Only syscalls received before a snapshot may
/// exempt a thread in it: one received after was running during the snapshot.
pub fn wait_frontier(
    be: &mut GateBackend,
    held: &mut Vec<Event>,
    interval: Duration,
    deadline: Instant,
) -> Result<Option<u32>> {
    let mut prev = snapshot(be.cgroup());
    for round in 1.. {
        match be.poll(interval)? {
            Poll::Events(evs) => held.extend(evs),
            Poll::Closed => return Err(Exited.into()),
            Poll::Idle => {}
        }
        let now = snapshot(be.cgroup());
        // Last thread gone before the notify fd reports POLLHUP.
        if now.is_empty() {
            return Err(Exited.into());
        }
        if quiescent(&prev, &now, &held.iter().map(|e| e.tid).collect()) {
            return Ok(Some(round));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        prev = now;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(ts: &[(u32, u8, u64)]) -> Snap {
        ts.iter().map(|&(t, s, n)| (t, (s, n))).collect()
    }

    #[test]
    fn quiescent_rules() {
        let none = BTreeSet::new();
        let a = snap(&[(1, b'S', 10), (2, b'D', 5)]);
        assert!(quiescent(&a, &a, &none));
        assert!(!quiescent(&a, &snap(&[(1, b'S', 11), (2, b'D', 5)]), &none), "ran between");
        assert!(!quiescent(&a, &snap(&[(1, b'R', 10), (2, b'D', 5)]), &none), "runnable");
        assert!(!quiescent(&a, &snap(&[(1, b'S', 10)]), &none), "exited between");
        assert!(!quiescent(&a, &snap(&[(1, b'S', 10), (2, b'D', 5), (3, b'S', 0)]), &none), "cloned");
        let moving = snap(&[(1, b'R', 99), (2, b'D', 5)]);
        assert!(quiescent(&a, &moving, &BTreeSet::from([1])), "parked overrides");
    }

    #[test]
    fn reads_own_thread() {
        let tid = unsafe { libc::gettid() } as u32;
        let (st, ns) = read_thread(tid).unwrap();
        assert_eq!(st, b'R');
        assert!(ns > 0);
    }
}
