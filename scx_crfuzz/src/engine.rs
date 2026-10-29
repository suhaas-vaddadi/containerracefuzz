//! Discovery loop: wait for a complete frontier (D1) up to a limit (D2), let
//! POS pick, fire the mutator (D6), release, repeat until the SUT exits. With
//! a judge, probe as alice at the final hold (§5). Replaying (§3.8), the
//! recorded step is released instead of POS's pick.

use crate::backend::{Event, GateBackend, SelfCheckFailed};
use crate::oracle::{Alice, Canary, Finding};
use crate::pos::{EventId, Keys, Pos};
use crate::schedule::{self, Divergence, Fixed, Step};
use crate::sensor::{wait_frontier, Exited};
use anyhow::{bail, Result};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

/// A mutator still running then is killed: a tree hold must end well before
/// sched_ext's 30 s watchdog ejects the scheduler (L:Gate).
const MUTATOR_TIMEOUT: Duration = Duration::from_secs(15);

/// One POS decision, as the canonical log records it.
#[derive(Clone, PartialEq, Eq)]
pub struct Decision {
    pub id: EventId,
    /// The event's conflict keys (D3), for its partial order (M8). Inode
    /// numbers: this run only.
    pub keys: Keys,
    /// Decided at the limit over an incomplete frontier (D2); replay and the
    /// determinism claim cover complete decisions only.
    pub partial: bool,
    /// The mutator fired at this hold: its exit status, or why it has none
    /// (a primitive failure, never a finding: §3.6).
    pub mutation: Option<Result<ExitStatus, String>>,
}

/// Without `keys`: one line per decision in the printed log.
impl std::fmt::Debug for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Decision").field("id", &self.id).field("partial", &self.partial).field("mutation", &self.mutation).finish()
    }
}

/// The canonical log as a schedule (§3.8): every decision, partial ones
/// included, in order.
pub fn project(log: &[Decision]) -> Vec<Step> {
    log.iter().map(|d| Step { id: d.id.clone(), mutate: d.mutation.is_some() }).collect()
}

/// Replay a schedule (§3.8): POS still names events and seeds the mutator (D6).
pub struct Replay<'a> {
    pub fixed: Fixed<'a>,
    /// Minimization: fire the mutator at this step alone, and on a divergence
    /// past it go on under POS, unmutated. None (confirmation): fire at every
    /// recorded mutation, and any divergence fails the run.
    pub only: Option<usize>,
    /// Minimization: where the run left the schedule, past `only`.
    pub diverged: Option<Divergence>,
}

impl Replay<'_> {
    /// Past the one enabled hold: keep it and go on; otherwise fail the run.
    fn left(&mut self, d: Divergence) -> Result<()> {
        if schedule::tolerated(self.only, &d) {
            self.diverged = Some(d);
            return Ok(());
        }
        Err(d.into())
    }
}

/// The oracle's side of one run (§5).
pub struct Judge<'a> {
    pub canary: &'a Canary,
    /// The attacker (§1): an input, never inferred.
    pub alice: Alice,
    /// What the probe found. None: no final hold (the SUT died by a signal).
    pub reached: Option<Vec<Finding>>,
    /// The probed task: `(tid, tgid, thread)`, to normalize its handles.
    pub task: Option<(u32, u32, String)>,
}

/// The SUT was still running at the deadline: `RuntimeError` (§6), not an
/// invalid run. Check with `err.is::<Deadline>()`.
#[derive(Debug)]
pub struct Deadline;

impl std::fmt::Display for Deadline {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("SUT still running at the deadline")
    }
}

impl std::error::Error for Deadline {}

/// Run the SUT under POS until it exits, appending each decision to `log`
/// (caller-owned, so it survives every ending). With a `mutator`, fire it at
/// the `target` event's hold alone (None: every hold whose event has a known
/// path); a replay fires where its schedule says instead. With a `judge`, the
/// mutator runs as alice, self-checked against the canary (§4, §10.1), and
/// the root process's `exit_group` is probed (§5). Fails with `Deadline` at
/// `deadline` (a hung or deadlocked SUT), with `SelfCheckFailed` if alice gets
/// past the gate, with `Divergence` if a `replay` leaves its schedule.
pub fn run(
    be: &mut GateBackend,
    pos: &mut Pos,
    mutator: Option<&Path>,
    target: Option<&EventId>,
    mut replay: Option<&mut Replay>,
    mut judge: Option<&mut Judge>,
    interval: Duration,
    limit: Duration,
    deadline: Instant,
    log: &mut Vec<Decision>,
) -> Result<()> {
    let root = be.child().id();
    let mut footprint = BTreeSet::new();
    let mut held: Vec<Event> = Vec::new();
    let mut ids: Vec<EventId> = Vec::new();
    loop {
        let complete = match wait_frontier(be, &mut held, interval, deadline.min(Instant::now() + limit)) {
            Ok(r) => r.is_some(),
            Err(e) if e.is::<Exited>() => {
                return match replay.filter(|r| r.diverged.is_none()) {
                    Some(r) => r.fixed.finish().or_else(|d| r.left(d)),
                    None => Ok(()),
                }
            }
            Err(e) => return Err(e),
        };
        // Checked after the wait, not before: a frontier cut short by the
        // deadline is never picked from (a replay would read it as Divergence).
        if Instant::now() >= deadline {
            return Err(anyhow::Error::new(Deadline).context(format!("after {} decisions", log.len())));
        }
        // Name events once, as they arrive: occurrence counts history. The
        // canary directory differs every run (§3.8).
        let canary = judge.as_deref().map(|j| j.canary.dir.as_path());
        ids.extend(held[ids.len()..].iter().map(|e| {
            let path = e.path.as_deref().map(|p| canary.and_then(|c| schedule::uncanary(p, c)).unwrap_or_else(|| p.into()));
            pos.id(&e.thread, e.nr, path)
        }));
        // D1: a tree-gated thread already blocked reads `S`, so the readout
        // can look complete when it isn't.
        if !be.tree().is_empty() {
            bail!("POS decision under a tree hold");
        }
        let ready: Vec<_> = ids.iter().zip(&held).map(|(id, e)| (id, &e.keys)).collect();
        // Replaying, the recorded step, and only its mutation (Some).
        let (mut pick, mut fire) = (None, None);
        if let Some(r) = replay.as_deref_mut() {
            if r.diverged.is_none() {
                match r.fixed.pick(&ready) {
                    Ok(p) => {
                        fire = p.map(|_| {
                            let s = r.fixed.next - 1;
                            r.fixed.steps[s].mutate && r.only.map_or(true, |k| k == s)
                        });
                        pick = Some(p);
                    }
                    Err(d) => r.left(d)?,
                }
            }
            if r.diverged.is_some() {
                fire = Some(false);
            }
        }
        let pick = pick.unwrap_or_else(|| pos.pick(&ready));
        // Nothing held: every thread blocked or running free.
        let Some(i) = pick else { continue };
        let (ev, id) = (held.remove(i), ids.remove(i));
        let seed = pos.event_seed(&id);
        let hit = !ev.keys.all && target.map_or(true, |t| *t == id);
        // Logged at once: every ending from here keeps it (§10.3).
        log.push(Decision { id, keys: ev.keys.clone(), partial: !complete, mutation: None });
        // The whole tree stays put while the mutator runs (§3.3); answer
        // before ungating (L:Gate).
        if let Some(p) = &ev.path {
            // Dirfd-relative: the fd number means nothing at the final hold.
            if p.is_absolute() || ev.dirfd.is_none() {
                footprint.insert(p.clone());
            }
        }
        let judged = judge.as_deref().map(|j| (&j.alice, j.canary));
        let mutation = match mutator {
            Some(prog) if ev.path.is_some() && fire.unwrap_or(hit) => {
                be.gate_tree()?;
                match be.mutate(&ev, prog, judged, seed, MUTATOR_TIMEOUT) {
                    // §4: the run ends here (main judges whether the SUT opened
                    // the gate). Anything else (alice unmapped in the task's
                    // namespace) is a primitive failure.
                    Err(e) if e.is::<SelfCheckFailed>() => {
                        log.last_mut().expect("pushed above").mutation = Some(Err(format!("{e:#}")));
                        return Err(e);
                    }
                    r => Some(r.map_err(|e| format!("{e:#}"))),
                }
            }
            _ => None,
        };
        let mutated = mutation.is_some();
        log.last_mut().expect("pushed above").mutation = mutation;
        // §5: the final hold. exit_group has no path, so it is never also mutated.
        let probe = match judge.as_deref_mut() {
            Some(j) if ev.nr == libc::SYS_exit_group && ev.tgid == root => {
                be.gate_tree()?;
                j.task = Some((ev.tid, ev.tgid, ev.thread.clone()));
                Some(be.probe(&ev, &j.alice, j.canary, &footprint, MUTATOR_TIMEOUT).map(|f| j.reached = Some(f)))
            }
            _ => None,
        };
        let released = be.release(&ev);
        if mutated || probe.is_some() {
            be.ungate_tree()?;
        }
        released?;
        // SelfCheckFailed or a failed probe: the run is invalid.
        probe.transpose()?;
    }
}
