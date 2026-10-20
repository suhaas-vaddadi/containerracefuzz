//! Discovery loop: wait for a complete frontier (D1) up to a limit (D2), let
//! POS pick, fire the mutator (D6), release, repeat until the SUT exits.

use crate::backend::{Event, GateBackend};
use crate::pos::{EventId, Pos};
use crate::sensor::{wait_frontier, Exited};
use anyhow::{bail, Result};
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

/// A mutator still running then is killed: a tree hold must end well before
/// sched_ext's 30 s watchdog ejects the scheduler (L:Gate).
const MUTATOR_TIMEOUT: Duration = Duration::from_secs(15);

/// One POS decision, as the canonical log records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub id: EventId,
    /// Decided at the limit over an incomplete frontier (D2); replay and the
    /// determinism claim cover complete decisions only.
    pub partial: bool,
    /// The mutator fired at this hold: its exit status, or why it has none
    /// (a primitive failure, never a finding: §3.6).
    pub mutation: Option<Result<ExitStatus, String>>,
}

/// Run the SUT under POS until it exits; returns the decision log. With a
/// `mutator`, fire it at every hold whose event has a known path. Fails at
/// `deadline` (a hung or deadlocked SUT).
pub fn run(
    be: &mut GateBackend,
    pos: &mut Pos,
    mutator: Option<&Path>,
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
        let (ev, id) = (held.remove(i), ids.remove(i));
        // The whole tree stays put while the mutator runs (§3.3); answer
        // before ungating (L:Gate).
        let mutation = match mutator {
            Some(prog) if ev.path.is_some() && !ev.keys.all => {
                be.gate_tree()?;
                Some(be.mutate(&ev, prog, pos.event_seed(&id), MUTATOR_TIMEOUT).map_err(|e| format!("{e:#}")))
            }
            _ => None,
        };
        let released = be.release(&ev);
        if mutation.is_some() {
            be.ungate_tree()?;
        }
        released?;
        log.push(Decision { id, partial: !complete, mutation });
    }
}
