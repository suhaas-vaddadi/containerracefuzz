//! Readout sensor: is no SUT thread running? The gate scheduler counts the
//! tree's tasks that are runnable or being woken (`GateMap::quiet`), so the
//! answer is one map read, exact as of the read.

use crate::backend::{Event, GateBackend, Poll};
use anyhow::Result;
use std::time::{Duration, Instant};

/// How long to wait for a syscall to trap while the tree is running, or
/// while there is nothing to decide on.
const INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug, PartialEq, Eq)]
pub enum Frontier {
    /// No SUT thread can run: everything it will do without us is held.
    Complete,
    /// Some still could at the deadline.
    Partial,
    /// The SUT tree is gone: there is no frontier to decide on. Not a stall;
    /// a run ends this way.
    Exited,
}

/// Wait until no SUT thread can run, adding every syscall held meanwhile to
/// `held` (the frontier), up to `deadline`. `idle`: the last frontier was
/// left as it was, so wait for a trap or a tick before reading again.
///
/// Complete means the tree read quiet, then the listener was drained, then
/// it read quiet again. Quiet first: a thread parks only after its
/// notification is queued, so everything trapped by then is in the drain.
/// Quiet after: the drain lets syscalls out of scope run on, and a release
/// counts its thread busy before it returns.
pub fn wait_frontier(be: &mut GateBackend, held: &mut Vec<Event>, deadline: Instant, mut idle: bool) -> Result<Frontier> {
    loop {
        let quiet = be.quiet()?;
        match be.poll(if quiet && !idle { Duration::ZERO } else { INTERVAL })? {
            Poll::Events(evs) => held.extend(evs),
            Poll::Closed => return Ok(Frontier::Exited),
            Poll::Idle => {}
        }
        if quiet && be.quiet()? {
            return Ok(Frontier::Complete);
        }
        if Instant::now() >= deadline {
            return Ok(Frontier::Partial);
        }
        idle = false;
    }
}
