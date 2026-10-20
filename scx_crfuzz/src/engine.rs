//! Discovery loop: wait for a complete frontier (D1) up to a limit (D2), let
//! POS pick, release, repeat until the SUT exits.

use crate::backend::{Event, GateBackend};
use crate::pos::{EventId, Pos};
use crate::sensor::{wait_frontier, Exited};
use anyhow::{bail, Result};
use std::time::{Duration, Instant};

/// One POS decision, as the canonical log records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub id: EventId,
    /// Decided at the limit over an incomplete frontier (D2); replay and the
    /// determinism claim cover complete decisions only.
    pub partial: bool,
}

/// Run the SUT under POS until it exits; returns the decision log. Fails at
/// `deadline` (a hung or deadlocked SUT).
pub fn run(
    be: &mut GateBackend,
    pos: &mut Pos,
    interval: Duration,
    limit: Duration,
    deadline: Instant,
) -> Result<Vec<Decision>> {
    let mut held: Vec<Event> = Vec::new();
    let mut ids: Vec<EventId> = Vec::new();
    let mut log = Vec::new();
    loop {
        if Instant::now() >= deadline {
            bail!("SUT still running at the deadline after {} decisions", log.len());
        }
        let complete = match wait_frontier(be, &mut held, interval, deadline.min(Instant::now() + limit)) {
            Ok(r) => r.is_some(),
            Err(e) if e.is::<Exited>() => return Ok(log),
            Err(e) => return Err(e),
        };
        // Name events once, as they arrive: occurrence counts history.
        ids.extend(held[ids.len()..].iter().map(|e| pos.id(&e.thread, e.nr, e.path.clone())));
        // D1: a tree-gated thread already blocked reads `S`, so the readout
        // can look complete when it isn't.
        if !be.tree().is_empty() {
            bail!("POS decision under a tree hold");
        }
        let ready: Vec<_> = ids.iter().zip(&held).map(|(id, e)| (id, &e.keys)).collect();
        // Nothing held: every thread blocked or running free.
        let Some(i) = pos.pick(&ready) else { continue };
        be.release(&held.remove(i))?;
        log.push(Decision { id: ids.remove(i), partial: !complete });
    }
}
