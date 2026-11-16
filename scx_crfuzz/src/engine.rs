//! Discovery loop: wait for a complete frontier (no SUT thread can run) up to
//! a limit, let POS pick, fire the mutator, release, repeat until the SUT
//! exits. With a judge, probe as alice at the final hold. Replaying, the
//! recorded step is released instead of POS's pick.

use crate::backend::{Event, GateBackend};
use crate::name::{self, EventId};
use crate::oracle::{Alice, Canary, Finding};
use crate::pos::{Keys, Pos};
use crate::schedule::{self, Divergence, Fixed, Step};
use crate::sensor::{wait_frontier, Frontier};
use anyhow::{bail, Result};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A mutator still running then is killed: a tree hold must end well before
/// sched_ext's 30 s watchdog ejects the scheduler.
const MUTATOR_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a frontier may stay incomplete before POS decides anyway: a
/// spinning thread or a fast ticker would otherwise stall the run.
const LIMIT: Duration = Duration::from_millis(200);

/// One POS decision, as the canonical log records it.
#[derive(Clone, PartialEq, Eq)]
pub struct Decision {
    pub id: EventId,
    /// The event's conflict keys, for its partial order. Inode
    /// numbers: this run only.
    pub keys: Keys,
    /// Decided at the limit over an incomplete frontier. The determinism
    /// claim covers complete decisions only, and of those the ones no thread
    /// slept through on a timer or on I/O from outside the tree: such a
    /// thread is quiet at the decision and wakes on its own after it.
    pub partial: bool,
    /// Threads asleep on a timer at this decision (`GateBackend::sleepers`).
    /// Counted in unmutated runs only: a baseline's telemetry reports it.
    pub sleepers: u32,
    /// The mutator fired at this hold: its exit status, or why it has none
    /// (a primitive failure, never a finding).
    pub mutation: Option<Result<ExitStatus, String>>,
}

/// Without `keys`: one line per decision in the printed log.
impl std::fmt::Debug for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut d = f.debug_struct("Decision");
        d.field("id", &self.id).field("partial", &self.partial);
        d.field("sleepers", &self.sleepers).field("mutation", &self.mutation).finish()
    }
}

/// The canonical log as a schedule: every decision, partial ones
/// included, in order.
pub fn project(log: &[Decision]) -> Vec<Step> {
    log.iter().map(|d| Step { id: d.id.clone(), mutate: d.mutation.is_some() }).collect()
}

/// Replay a schedule: POS still names events and seeds the mutator.
pub struct Replay<'a> {
    pub fixed: Fixed<'a>,
    /// Minimization: fire the mutator at this step alone, and on a divergence
    /// past it go on under POS, unmutated. None (confirmation): fire at every
    /// recorded mutation, and any divergence ends the run.
    pub only: Option<usize>,
    /// Minimization: where the run left the schedule, past `only`.
    pub diverged: Option<Divergence>,
}

impl Replay<'_> {
    /// Past the one enabled hold: keep it and go on (None); otherwise the
    /// run ends on it.
    fn left(&mut self, d: Divergence) -> Option<Divergence> {
        if schedule::tolerated(self.only, &d) {
            self.diverged = Some(d);
            return None;
        }
        Some(d)
    }
}

/// The oracle's side of one run.
pub struct Judge<'a> {
    pub canary: &'a Canary,
    /// The attacker: an input, never inferred.
    pub alice: Alice,
    /// What the probe found. None: no final hold (the SUT died by a signal).
    pub reached: Option<Vec<Finding>>,
    /// The probed task: `(tid, tgid, process)`, to normalize its handles.
    pub task: Option<(u32, u32, String)>,
}

/// How a run ended. An `Err` from `run` is none of these: crfuzz or the
/// scenario failed, and the run says nothing.
#[derive(Debug)]
pub enum End {
    /// The SUT tree is gone, a replay's schedule followed to its end.
    Exited,
    /// The SUT was still running at the deadline (hung or deadlocked): a
    /// `RuntimeError`, not an invalid run.
    Deadline,
    /// SIGINT or SIGTERM arrived (`stop_on_signals`): the run was cut short.
    Interrupted,
    /// A replay left its schedule.
    Diverged(Divergence),
    /// Alice's credentials got past the canary gate (the self-check). The
    /// caller judges whether the SUT opened it.
    SelfCheck,
}

static STOP: AtomicBool = AtomicBool::new(false);

/// A SIGINT or SIGTERM has arrived since `stop_on_signals`.
pub fn stopped() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// The first SIGINT or SIGTERM sets `stopped()`, so loops end at their next
/// check and every Drop runs; the handler restores the default disposition,
/// so a second one kills at once.
pub fn stop_on_signals() {
    extern "C" fn stop(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
        // Async-signal-safe.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }
    }
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        for sig in [libc::SIGINT, libc::SIGTERM] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Run the SUT under POS until it exits, appending each decision to `log`
/// (caller-owned, so it survives every ending). With a `mutator`, fire it at
/// the first hold matching `target`'s syscall, path and occurrence, in any
/// thread; a replay fires where its schedule says instead. With a `judge`,
/// the mutator runs as alice, self-checked against the canary, and the root
/// process's `exit_group` is probed.
pub fn run(
    be: &mut GateBackend,
    pos: &mut Pos,
    mutator: Option<&Path>,
    target: Option<&EventId>,
    mut replay: Option<&mut Replay>,
    mut judge: Option<&mut Judge>,
    deadline: Instant,
    log: &mut Vec<Decision>,
) -> Result<End> {
    let root = be.child().id();
    let mut footprint = BTreeSet::new();
    let mut held: Vec<Event> = Vec::new();
    let mut ids: Vec<EventId> = Vec::new();
    // The last frontier was left as it was (nothing to pick).
    let mut idle = false;
    loop {
        // Never under a tree hold: each iteration ungates before the next.
        if stopped() {
            return Ok(End::Interrupted);
        }
        let complete = match wait_frontier(be, &mut held, deadline.min(Instant::now() + LIMIT), idle)? {
            Frontier::Exited => {
                let left = replay.filter(|r| r.diverged.is_none()).and_then(|r| r.fixed.finish().err().and_then(|d| r.left(d)));
                return Ok(left.map_or(End::Exited, End::Diverged));
            }
            f => f == Frontier::Complete,
        };
        idle = true;
        // Checked after the wait, not before: a frontier cut short by the
        // deadline is never picked from (a replay would read it as a divergence).
        if Instant::now() >= deadline {
            return Ok(End::Deadline);
        }
        // Name events once, as they arrive: occurrence counts history.
        let canary = judge.as_deref().map(|j| j.canary.dir.as_path());
        ids.extend(held[ids.len()..].iter().map(|e| {
            let path = e.path.as_deref().map(|p| name::event_path(p, canary));
            pos.id(&e.process, e.nr, path)
        }));
        // A gated thread already blocked is not busy, so the tree can read
        // quiet when it isn't.
        if be.gated() {
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
                    Err(d) => {
                        if let Some(d) = r.left(d) {
                            return Ok(End::Diverged(d));
                        }
                    }
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
        // The target in any process: windows are one per (syscall, path,
        // occurrence). The first such hold fires, once.
        let hit = !ev.keys.all
            && target.is_some_and(|t| (t.nr, &t.path, t.n) == (id.nr, &id.path, id.n) && !log.iter().any(|d| d.mutation.is_some()));
        let sleepers = if mutator.is_none() { be.sleepers(&held) } else { 0 };
        // Logged at once: every ending from here (deadline, invalid run,
        // error) keeps it.
        log.push(Decision { id, keys: ev.keys.clone(), partial: !complete, sleepers, mutation: None });
        if let Some(p) = &ev.path {
            // Dirfd-relative: the fd number means nothing at the final hold.
            if p.is_absolute() || ev.dirfd.is_none() {
                footprint.insert(p.clone());
            }
        }
        let judged = judge.as_deref().map(|j| (&j.alice, j.canary));
        // The whole tree stays put while the mutator runs.
        let mutated = match mutator {
            Some(prog) if ev.path.is_some() && fire.unwrap_or(hit) => {
                be.gate_tree()?;
                let r = be.mutate(&ev, prog, judged, seed, MUTATOR_TIMEOUT);
                // The self-check failed: the run ends here. Anything else
                // (alice unmapped in the task's namespace) is a primitive failure.
                let ended = matches!(r, Ok(None));
                log.last_mut().expect("pushed above").mutation = Some(match r {
                    Ok(Some(status)) => Ok(status),
                    Ok(None) => Err("self-check: alice's credentials are not stopped by the canary gate".into()),
                    Err(e) => Err(format!("{e:#}")),
                });
                if ended {
                    return Ok(End::SelfCheck);
                }
                true
            }
            _ => false,
        };
        // The final hold. exit_group has no path, so it is never also mutated.
        let probe = match judge.as_deref_mut() {
            Some(j) if ev.nr == libc::SYS_exit_group && ev.tgid == root => {
                be.gate_tree()?;
                j.task = Some((ev.tid, ev.tgid, ev.process.clone()));
                Some(be.probe(&ev, &j.alice, j.canary, &footprint, MUTATOR_TIMEOUT))
            }
            _ => None,
        };
        // Answer before ungating, so a signal can't restart the syscall
        // mid-release.
        let released = be.release(&ev);
        if mutated || probe.is_some() {
            be.ungate_tree()?;
        }
        released?;
        idle = false;
        // A failed probe: the run is invalid.
        match (probe.transpose()?, judge.as_deref_mut()) {
            (Some(Some(found)), Some(j)) => j.reached = Some(found),
            (Some(None), _) => return Ok(End::SelfCheck),
            _ => {}
        }
        // The rest still held were keyed before the mutation: re-walk them, so
        // the next decisions order on what they will now resolve. Ungated, so a
        // stat can't block on a gated FUSE server; as best-effort as at hold time.
        if mutated {
            held.iter_mut().for_each(|e| be.rekey(e));
        }
    }
}
