// SPDX-License-Identifier: GPL-2.0
//
// The engine: a thread table fed by the backend, and a decision at every full
// readout.
//
// Full-readout design (docs/superpowers/specs/2026-10-04-crfuzz-full-readout-
// design.md, sections 2, 3 and 6): every thread of the run's cgroup is tracked
// as Running, Blocked, Parked or Exited, and a decision is taken only when
// none is running, so the ready set is exactly the threads parked at a
// checkpoint. A thread that runs too long while others wait is frozen
// (section 5). "Which event goes next" is asked through `DecisionPolicy`
// (design doc section 3) or answered by the attacker/oracle orchestration.

use crate::attacker;
use crate::attacker::AttackOutcome;
use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::Poll;
use crate::backend::ThreadStateKind;
use crate::checkpoint::CheckpointId;
use crate::config::AttackDecl;
use crate::config::DivergencePolicy;
use crate::config::Mode;
use crate::config::PolicyType;
use crate::config::ScenarioConfig;
use crate::event::ActorId;
use crate::event::EventId;
use crate::event::ThreadPath;
use crate::log::CanonicalLog;
use crate::log::DebugEntry;
use crate::log::DebugLog;
use crate::oracle::Oracle;
use crate::oracle::OracleVerdict;
use crate::oracle::PathIdentity;
use crate::oracle::WindowContext;
use crate::policy::Decision;
use crate::policy::DecisionPolicy;
use crate::policy::FixedSchedule;
use crate::policy::PosPolicy;
use crate::policy::ReadyCheckpointHit;
use crate::role::Pid;
use crate::role::Provenance;
use crate::role::RoleRef;
use crate::role::RoleTable;
use anyhow::Result;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

/// What drives releases in the `Enforcing` phase.
///
/// The `DecisionPolicy` seam answers "which held event goes next" for replay
/// and POS. The attacker/oracle orchestration (`PolicyType::AutoAttack`) does
/// not fit that seam -- only the victim is ever held, so there is no choice of
/// role, and each release is bracketed by an attacker turn and an oracle
/// observation the `decide` signature cannot express. It therefore drives the
/// engine directly, as a second kind of driver rather than a policy.
enum Driver {
    Policy(Box<dyn DecisionPolicy>),
    Attack(AttackDriver),
}

/// State for the attacker/oracle orchestration.
struct AttackDriver {
    /// The external attacker run inside each window.
    spec: AttackDecl,
    /// The window whose oracle has not run yet: set when the victim is released
    /// to a use, observed at the victim's next hold or its leader's exit -- the
    /// first point the use has provably completed and the victim is frozen
    /// again.
    pending: Option<WindowContext>,
    oracle: Oracle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Holding every role except the one the policy releases.
    Enforcing,
    /// The policy has nothing left to enforce; let everything go.
    Draining,
}

/// How a run ended.
///
/// NOTE (design doc section 14-H, unresolved): discovery-mode runs where the
/// racer's action causes an uninteresting early failure -- the container simply
/// fails to start, say -- do not obviously map onto any of these three, and the
/// doc does not say whether that needs a fourth category or collapses into one
/// of these. Distinguishing such a run from a real finding is the oracle's
/// problem (section 7), and is itself open (section 14-B), so the engine does
/// not invent a category here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// The policy finished and `Draining` was reached.
    Completed,
    /// A step's condition could not be satisfied, under `on_divergence: abort`.
    Diverged { step_idx: u64, reason: String },
    /// The scenario ended with the policy still unfinished.
    ///
    /// The base design tracks this with a supervisory wall-clock timeout from
    /// the canonical log's last `step_idx` advance. That timer belongs to the
    /// harness, which is out of this scaffold's scope; what the engine can see
    /// on its own is that every process is gone while the policy still wants
    /// something, which is the same condition arriving by a different route.
    TimedOut { reason: String },
    /// Every thread is at rest, no decision is possible, and no Blocked
    /// thread is in a timed sleep, so nothing can ever change: each thread
    /// still waiting, as `role/tN tid (comm) state: wchan .. syscall ..`.
    Deadlocked { threads: Vec<String> },
}

/// How often the watchdog samples CPU while a readout is pending.
const WATCHDOG_TICK: Duration = Duration::from_millis(250);

/// A frozen thread is runnable but never dispatched, which sched_ext's own
/// watchdog (`timeout_ms`, at most 30 s) counts against: thaw it before then.
const FORCED_THAW: Duration = Duration::from_secs(20);

/// One thread of the run's cgroup, as the sensor last reported it (design doc
/// section 2).
#[derive(Debug)]
struct Thread {
    state: State,
    /// `WakeStart` seen, `WakeDone` not yet: not at rest, whatever `state`
    /// says.
    wake_in_progress: bool,
    tgid: Pid,
    /// Its clone path within its thread group (design doc section 3).
    path: ThreadPath,
    /// Threads it has created so far: the index its next one gets.
    clones: u32,
    /// The checkpoint hit it is held at: Parked, or not yet asleep in it.
    hit: Option<ReadyCheckpointHit>,
    /// Held by the watchdog, and so at rest whatever `state` says. `state`
    /// keeps following the sensor: a freeze can race the thread's own sleep.
    frozen: Option<Frozen>,
    /// Its `cpu_ns` when the watchdog first saw it Running since the last
    /// release.
    cpu_base: Option<u64>,
}

impl Thread {
    fn at_rest(&self) -> bool {
        self.frozen.is_some() || (self.state != State::Running && !self.wake_in_progress)
    }
}

#[derive(Debug)]
struct Frozen {
    at: Instant,
    /// The thread the first release since the freeze let go: thawed once it
    /// is back at rest, so a spinner can see what that release changed.
    after: Option<Pid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Running,
    Blocked,
    Parked,
    /// Terminal: later records for the tid are ignored.
    Exited,
}

pub struct Engine<B: CheckpointBackend> {
    config: ScenarioConfig,
    backend: B,
    roles: RoleTable,
    driver: Driver,
    phase: Phase,
    /// Every thread of the run, by tid. Ordered, so whatever iterates it does
    /// so reproducibly.
    threads: BTreeMap<Pid, Thread>,
    /// The ready set of the current decision: the Parked threads' hits, in
    /// canonical order.
    ready: Vec<ReadyCheckpointHit>,
    /// How each ready entry's role was resolved, for the debug log only.
    provenance: HashMap<Pid, Provenance>,
    /// The pid behind each ready entry. Kept out of `ReadyCheckpointHit` so a
    /// policy structurally cannot see a pid and start depending on one.
    ready_pids: Vec<Pid>,
    /// `(actor, checkpoint)` -> hits seen so far this run, so each checkpoint
    /// hit gets the POS `occurrence` of its event (plan section 3.2). Reset with
    /// the engine, i.e. per run.
    occurrences: HashMap<(ActorId, CheckpointId), u32>,
    canonical: CanonicalLog,
    debug: DebugLog,
    /// The ready set as it stood at each `decide()` call: the
    /// ready-set-sequence section 10.1's determinism claim depends on,
    /// recorded so it can be compared across runs; see the crate docs,
    /// "Section 14-A".
    decisions: Vec<String>,
    /// Oracle rulings, one per observed window: `(release step index, verdict)`.
    /// Kept off the canonical log, which must stay equal to the enforced release
    /// sequence so its projection replays exactly; a finding is reported
    /// alongside, not woven into it.
    oracle_verdicts: Vec<(u64, OracleVerdict)>,
    started: Instant,
    /// Decisions taken while some Blocked thread was in a timed sleep: it
    /// wakes at a wall-clock time, so these are not seed-reproducible.
    timed_sleep_decisions: u32,
    /// Decisions taken while some thread was frozen: not seed-reproducible.
    frozen_decisions: u32,
    /// `FORCED_THAW`; tests shorten it.
    forced_thaw: Duration,
    stop: Option<&'static AtomicBool>,
}

impl<B: CheckpointBackend> Engine<B> {
    pub fn new(config: ScenarioConfig, backend: B) -> Self {
        let driver = build_driver(&config);
        let roles = RoleTable::new(config.roles.clone(), config.cgroup.clone());
        let canonical = CanonicalLog::new(config.scenario_id.clone());
        Engine {
            config,
            backend,
            roles,
            driver,
            phase: Phase::Enforcing,
            threads: BTreeMap::new(),
            ready: Vec::new(),
            provenance: HashMap::new(),
            ready_pids: Vec::new(),
            occurrences: HashMap::new(),
            canonical,
            debug: DebugLog::default(),
            decisions: Vec::new(),
            oracle_verdicts: Vec::new(),
            started: Instant::now(),
            timed_sleep_decisions: 0,
            frozen_decisions: 0,
            forced_thaw: FORCED_THAW,
            stop: None,
        }
    }

    /// Stop at the next round when `stop` is set (by a signal handler), so the
    /// backend's `Drop` -- which lifts every gate -- still runs.
    pub fn with_stop(mut self, stop: &'static AtomicBool) -> Self {
        self.stop = Some(stop);
        self
    }

    /// The oracle's ruling on each observed window (empty unless the run used
    /// `auto_attack`).
    pub fn oracle_verdicts(&self) -> &[(u64, OracleVerdict)] {
        &self.oracle_verdicts
    }

    pub fn canonical_log(&self) -> &CanonicalLog {
        &self.canonical
    }

    pub fn debug_log(&self) -> &DebugLog {
        &self.debug
    }

    /// Decisions taken while a Blocked thread was in a timed sleep. Nonzero:
    /// the run is not reproducible from its seed alone.
    pub fn timed_sleep_decisions(&self) -> u32 {
        self.timed_sleep_decisions
    }

    /// Decisions taken while the watchdog had a thread frozen. Nonzero: the
    /// run is not reproducible from its seed alone.
    pub fn frozen_decisions(&self) -> u32 {
        self.frozen_decisions
    }

    /// The ready set at each decision point. See `decisions`.
    pub fn decision_trace(&self) -> &[String] {
        &self.decisions
    }

    /// How many times `(role, checkpoint)` has been seen so far this run,
    /// summed over the role's actors (one actor, or one per thread under
    /// `pos` and replay).
    ///
    /// Diagnostic only (and what the occurrence-assignment test asserts):
    /// `occurrence` counters are run-history-dependent, so nothing may build a
    /// byte-identity guarantee on them (plan section 6).
    pub fn occurrence_count(&self, role: RoleRef, checkpoint: &CheckpointId) -> u32 {
        self.occurrences
            .iter()
            .filter(|((actor, cp), _)| actor.role == role && cp == checkpoint)
            .map(|(_, n)| n)
            .sum()
    }

    /// The scheduling actor for `pid` in `role`: the role itself, or under
    /// `pos` and replay the role plus this thread's clone path.
    fn actor_for(&mut self, role: RoleRef, pid: Pid) -> ActorId {
        if self.config.mode.is_auto_attack() {
            return ActorId::role(role);
        }
        ActorId {
            role,
            thread: Some(self.thread(pid, pid, None).path.clone()),
        }
    }

    /// `tid`'s entry, created Running if new, with its clone path (design
    /// doc section 3): a group leader is `t0`; a thread is its creator's path
    /// plus the creator's clone count, or the leader's when no creator in its
    /// group is known (it joined along with its group). A fork's child leads
    /// a new group.
    fn thread(&mut self, tid: Pid, tgid: Pid, creator: Option<Pid>) -> &mut Thread {
        if !self.threads.contains_key(&tid) {
            let mut path = ThreadPath(vec![0]);
            if tid != tgid {
                let parent = creator
                    .filter(|c| self.threads.get(c).is_some_and(|t| t.tgid == tgid))
                    .unwrap_or(tgid);
                if let Some(p) = self.threads.get_mut(&parent) {
                    path = ThreadPath([p.path.0.as_slice(), &[p.clones]].concat());
                    p.clones += 1;
                }
            }
            self.threads.insert(
                tid,
                Thread {
                    state: State::Running,
                    wake_in_progress: false,
                    tgid,
                    path,
                    clones: 0,
                    hit: None,
                    frozen: None,
                    cpu_base: None,
                },
            );
        }
        self.threads.get_mut(&tid).expect("inserted above")
    }

    /// Whether the driver has nothing further it wants to enforce.
    fn driver_is_finished(&self) -> bool {
        match &self.driver {
            Driver::Policy(p) => p.is_finished(),
            // The orchestration never wants more than the scenario produces:
            // it acts on whatever windows the victim reaches and is done when
            // the victim is.
            Driver::Attack(_) => true,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn run(&mut self) -> Result<RunOutcome> {
        let checkpoints = self.config.checkpoints.clone();
        self.backend.attach(&checkpoints)?;
        // Created outside the cgroup, so no `Created` record names them.
        for pid in self.backend.spawned() {
            self.thread(pid, pid, None);
        }

        let mut timeout = None;
        loop {
            let closed = match self.backend.poll(timeout)? {
                Poll::Events(events) => {
                    for e in events {
                        self.handle_event(e)?;
                    }
                    false
                }
                Poll::Idle => false,
                Poll::Closed => true,
            };
            if self.stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
                anyhow::bail!("interrupted by a signal");
            }
            let lost = self.backend.dropped()?;
            if lost > 0 {
                anyhow::bail!(
                    "the thread-state sensor lost {lost} record(s): the readout cannot be trusted"
                );
            }

            if closed {
                // Gone without an `Exited` record: a spawned child that died
                // before joining the cgroup.
                let gone: Vec<Pid> = self
                    .threads
                    .iter()
                    .filter(|(tid, t)| {
                        t.state != State::Exited
                            && !std::path::Path::new(&format!("/proc/{tid}")).exists()
                    })
                    .map(|(tid, _)| *tid)
                    .collect();
                for tid in gone {
                    self.exit_thread(tid);
                }
                if self.threads.values().all(|t| t.state == State::Exited) {
                    // A leader that exited ahead of its group (`pthread_exit`)
                    // left the last window unruled.
                    self.run_pending_oracle();
                    return Ok(self.final_outcome());
                }
            }

            timeout = self.watchdog()?;
            if !self.at_rest() {
                continue;
            }
            if self.readout_complete() {
                if !self.recapture()? {
                    // A dead notification's wakeup or exit is already
                    // reported: read it before deciding.
                    timeout = Some(Duration::ZERO);
                    continue;
                }
                // Classify, then probe: a sleeper that /proc already shows
                // awake had its wakeup recorded before that read, so the probe
                // sees it and this readout is stale; read on instead.
                let timed = self.timed_sleeper();
                if self.backend.pending() {
                    timeout = Some(Duration::ZERO);
                    continue;
                }
                let acted = self.advance(timed)?;
                if let Some(outcome) = acted.outcome {
                    return Ok(outcome);
                }
                if acted.released > 0 {
                    continue;
                }
            }
            // At rest and no decision possible: only a sleeper that wakes on
            // its own, or a thaw, can change that.
            let waiting = self
                .threads
                .values()
                .any(|t| matches!(t.state, State::Blocked | State::Parked));
            let frozen = self.threads.values().any(|t| t.frozen.is_some());
            if waiting && !frozen && !self.timed_sleeper() && !self.backend.pending() {
                // Everything is at rest, so the last released use has provably
                // completed: rule on its window before giving up, rather than
                // losing the verdict to the deadlock.
                self.run_pending_oracle();
                return Ok(self.deadlocked());
            }
        }
    }

    /// Whether some Blocked thread will wake on its own at a wall-clock time
    /// (design doc section 2, "Timed sleeps"): a timed sleep, or an I/O wait.
    fn timed_sleeper(&self) -> bool {
        self.threads
            .iter()
            .any(|(tid, t)| t.state == State::Blocked && self.backend.wakes_on_its_own(*tid))
    }

    /// No thread running or mid-wakeup (design doc section 2).
    fn at_rest(&self) -> bool {
        self.threads.values().all(Thread::at_rest)
    }

    /// The CPU watchdog (design doc section 5). Thaws what is due, then,
    /// while a readout is pending (someone Parked, someone Running), freezes
    /// every Running thread over its CPU budget since the last release.
    /// Returns the poll timeout: the tick while a readout is pending or a
    /// thread is frozen (to reach its forced thaw), else none. Wall time only
    /// decides when to look.
    fn watchdog(&mut self) -> Result<Option<Duration>> {
        // Retire any tracked thread that has left the scenario cgroup. The
        // cgroup-scoped sensor can no longer report it, so it can never reach
        // rest on its own; leaving it would keep `at_rest()` false forever.
        // Such a task is not part of the run, so retiring it is safe.
        let outside: Vec<Pid> = self
            .threads
            .iter()
            .filter(|(&tid, t)| t.state != State::Exited && !self.backend.in_scope(tid))
            .map(|(&tid, _)| tid)
            .collect();
        for tid in outside {
            log::warn!(
                "watchdog: tid {tid} ({}) left the scenario cgroup; retiring it",
                proc_file(tid, "comm"),
            );
            if let Some(handle) = self.threads[&tid].hit.as_ref().map(|h| h.handle) {
                if let Err(e) = self.backend.release(handle) {
                    log::warn!("watchdog: releasing out-of-scope tid {tid}: {e:#}");
                }
            }
            self.exit_thread(tid);
        }

        let due: Vec<(Pid, bool)> = self
            .threads
            .iter()
            .filter_map(|(&tid, t)| {
                let f = t.frozen.as_ref()?;
                let forced = f.at.elapsed() >= self.forced_thaw;
                let rested = f.after.is_some_and(|a| self.threads[&a].at_rest());
                (forced || rested || t.state == State::Exited).then_some((tid, forced))
            })
            .collect();
        for (tid, forced) in due {
            if forced {
                log::warn!("watchdog: thawing tid {tid}, frozen {:?}", self.forced_thaw);
            }
            self.backend.thaw(tid)?;
            let t = self.threads.get_mut(&tid).expect("listed above");
            t.frozen = None;
            t.cpu_base = None;
        }

        let parked = self.threads.values().any(|t| t.state == State::Parked);
        let running: Vec<Pid> = self
            .threads
            .iter()
            .filter(|(_, t)| t.state == State::Running && t.frozen.is_none())
            .map(|(tid, _)| *tid)
            .collect();
        let pending = parked && !running.is_empty();
        if pending {
            let budget = self.config.watchdog_cpu_secs.saturating_mul(1_000_000_000);
            for tid in running {
                let Some(now) = self.backend.cpu_ns(tid) else {
                    continue;
                };
                let t = self.threads.get_mut(&tid).expect("listed above");
                let used = now.saturating_sub(*t.cpu_base.get_or_insert(now));
                if used <= budget {
                    continue;
                }
                self.backend.freeze(tid)?;
                self.threads.get_mut(&tid).expect("listed above").frozen = Some(Frozen {
                    at: Instant::now(),
                    after: None,
                });
                log::warn!("{}", self.freeze_diagnostic(tid, used));
            }
        }
        let frozen = self.threads.values().any(|t| t.frozen.is_some());
        Ok((pending || frozen).then_some(WATCHDOG_TICK))
    }

    /// One bounded line: the frozen thread, its CPU, its syscall, and the
    /// Parked set it kept waiting.
    fn freeze_diagnostic(&self, tid: Pid, used_ns: u64) -> String {
        const SHOWN: usize = 8;
        let parked: Vec<String> = self
            .threads
            .iter()
            .filter(|(_, t)| t.state == State::Parked)
            .filter_map(|(&p, t)| Some(format!("{}@{}", self.name(p), t.hit.as_ref()?.checkpoint)))
            .collect();
        let mut shown = parked[..parked.len().min(SHOWN)].join(", ");
        if parked.len() > SHOWN {
            shown += &format!(" (+{} more)", parked.len() - SHOWN);
        }
        format!(
            "watchdog: froze {} tid {tid} ({}) after {:.1} s CPU since the last release; \
             syscall {}; parked: {shown}",
            self.name(tid),
            proc_file(tid, "comm"),
            used_ns as f64 / 1e9,
            proc_file(tid, "syscall"),
        )
    }

    /// `role/tN`, or `-/tN` for an unmatched thread.
    fn name(&self, tid: Pid) -> String {
        let role = self
            .roles
            .lookup(tid)
            .map_or_else(|| "-".to_string(), |r| self.roles.render(r));
        format!("{role}/{}", self.threads[&tid].path)
    }

    /// The rest of the full readout, once at rest: someone is parked, and
    /// every `one` role has appeared. (`dropped` is checked every round.)
    fn readout_complete(&self) -> bool {
        self.threads.values().any(|t| t.state == State::Parked) && self.roles.all_roles_seen()
    }

    /// Refresh every parked event's conflict keys (design doc section 4): an
    /// earlier release may have rebound a name on its path. Priorities are
    /// keyed by `EventId`, so only conflict membership changes. A
    /// notification that is gone (interrupted, or its thread dying) drops its
    /// entry; returns false if any did.
    fn recapture(&mut self) -> Result<bool> {
        let mut all = true;
        for t in self.threads.values_mut().filter(|t| t.state == State::Parked) {
            let hit = t.hit.as_mut().expect("a parked thread has its hit");
            match self.backend.recapture(hit.handle)? {
                Some(keys) => hit.keys = keys,
                None => {
                    log::debug!("recapture of {:?} failed; dropping it", hit.handle);
                    t.hit = None;
                    t.state = State::Blocked;
                    all = false;
                }
            }
        }
        Ok(all)
    }

    /// Each thread still waiting, with its wait state. The `/proc` reads are
    /// best-effort: `?` when unreadable.
    fn deadlocked(&self) -> RunOutcome {
        let threads = self
            .threads
            .iter()
            .filter(|(_, t)| matches!(t.state, State::Blocked | State::Parked))
            .map(|(&tid, t)| {
                format!(
                    "{} tid {tid} ({}) {:?}: wchan {} syscall {}",
                    self.name(tid),
                    proc_file(tid, "comm"),
                    t.state,
                    proc_file(tid, "wchan"),
                    proc_file(tid, "syscall")
                )
            })
            .collect();
        RunOutcome::Deadlocked { threads }
    }

    /// Called when the scenario has ended and nothing is left held.
    fn final_outcome(&self) -> RunOutcome {
        if self.phase == Phase::Draining || self.driver_is_finished() {
            return RunOutcome::Completed;
        }
        // Every role finished, but the policy still wanted something no
        // remaining process could ever produce. The base design tracks this
        // with the harness's supervisory timeout; arriving at it by exhaustion
        // is the same outcome reached by a different route.
        RunOutcome::TimedOut {
            reason: format!(
                "scenario ended in phase {:?} with the policy still unfinished",
                self.phase
            ),
        }
    }

    fn handle_event(&mut self, event: BackendEvent) -> Result<()> {
        match event {
            BackendEvent::TaskAppeared(task) => {
                // Only a task inside the run's scope is part of the run. A
                // task that has left it -- runc's init entering the
                // container's own cgroup, say -- is invisible to the
                // cgroup-scoped sensor, so tracking it would leave a `Running`
                // entry nothing can ever retire and stall the readout.
                if self.backend.in_scope(task.pid) {
                    self.thread(task.pid, task.tgid, None);
                }
                if let Some((_, provenance)) = self.roles.resolve_role(&task) {
                    self.provenance.insert(task.pid, provenance);
                }
            }
            BackendEvent::CheckpointHit {
                pid,
                checkpoint,
                handle,
                path,
                keys,
            } => {
                if self
                    .threads
                    .get(&pid)
                    .is_some_and(|t| t.state == State::Exited)
                {
                    // Its notification died with it. Still answer it: a
                    // notification left unanswered parks the tracee forever,
                    // and `release` tolerates an id the kernel already
                    // abandoned (it logs and returns).
                    self.backend.release(handle)?;
                    return Ok(());
                }
                // A task the role table does not recognise -- including one
                // that has left the scenario cgroup -- is not ours to
                // schedule: release it at once and never create an entry for
                // it. Recording it would leave a `Running` entry the sensor
                // can never retire. That is the blast-radius guarantee -- a
                // bug in this engine must not be able to degrade or hang
                // unrelated work on the machine.
                let Some(role) = self.roles.lookup(pid) else {
                    self.backend.release(handle)?;
                    return Ok(());
                };
                let role_name = self.roles.render(role);
                // POS event identity: the nth time this `(actor, checkpoint)`
                // pair has been seen this run (plan section 3.2). Assigned here,
                // in the engine, so a policy never has to.
                let actor = self.actor_for(role, pid);
                let occurrence = {
                    let next = self
                        .occurrences
                        .entry((actor.clone(), checkpoint.clone()))
                        .or_insert(0);
                    let n = *next;
                    *next += 1;
                    n
                };
                let event = EventId::new(actor, checkpoint.clone(), occurrence);
                let t = self.thread(pid, pid, None);
                // Every record the thread made before this notification was
                // applied first (`GateBackend::poll`), so a thread asleep with
                // no wake in progress is asleep in it.
                if t.state == State::Blocked && !t.wake_in_progress {
                    t.state = State::Parked;
                }
                t.hit = Some(ReadyCheckpointHit {
                    role,
                    role_name,
                    checkpoint,
                    handle,
                    path,
                    event,
                    keys,
                });
            }
            BackendEvent::ThreadState {
                tid,
                tgid,
                kind,
                arg,
            } => self.thread_state(tid, tgid, kind, arg),
        }
        Ok(())
    }

    /// Apply one sensor record (design doc section 2's table).
    fn thread_state(&mut self, tid: Pid, tgid: Pid, kind: ThreadStateKind, arg: u32) {
        match kind {
            // A group detach names only the leader.
            ThreadStateKind::Left if arg != 0 => {
                let group: Vec<Pid> = self
                    .threads
                    .iter()
                    .filter(|(_, t)| t.tgid == tgid)
                    .map(|(tid, _)| *tid)
                    .collect();
                for tid in group {
                    self.exit_thread(tid);
                }
                return;
            }
            ThreadStateKind::Exited | ThreadStateKind::Left => {
                self.exit_thread(tid);
                return;
            }
            _ => {}
        }
        let creator = (kind == ThreadStateKind::Created).then_some(arg as Pid);
        let t = self.thread(tid, tgid, creator);
        if t.state == State::Exited {
            return;
        }
        match kind {
            ThreadStateKind::WakeStart => t.wake_in_progress = true,
            ThreadStateKind::WakeDone => {
                t.wake_in_progress = false;
                // A release sets Running first, so a Parked thread waking is
                // a signal interrupting its seccomp wait: the notification
                // is dead, and the thread will re-park with a new one.
                if t.state == State::Parked {
                    log::debug!("tid {tid}: woken while parked; dropping its hit");
                    t.hit = None;
                }
                t.state = State::Running;
            }
            ThreadStateKind::Asleep => {
                t.state = if t.hit.is_some() && !t.wake_in_progress {
                    State::Parked
                } else {
                    State::Blocked
                };
            }
            // `Created` and `Joined` only bring a thread into the table, which
            // `thread` did.
            _ => {}
        }
    }

    /// The thread exited or left the cgroup: terminal.
    fn exit_thread(&mut self, tid: Pid) {
        let Some(t) = self.threads.get_mut(&tid) else {
            return;
        };
        if t.state == State::Exited {
            return;
        }
        t.state = State::Exited;
        t.wake_in_progress = false;
        t.hit = None;
        // An exit is not a decision point. The victim's leader exiting does
        // complete its last released use, so that window is ruled on here
        // (`auto_attack` has a single role, the victim).
        if t.tgid == tid && self.roles.lookup(tid).is_some() {
            self.run_pending_oracle();
        }
        self.roles.on_task_exit(tid);
        self.provenance.remove(&tid);
    }

    /// The ready set: every Parked thread's hit, canonically ordered before
    /// a policy sees it (plan Phase 2).
    ///
    /// POS's redraw state reads the ready set, so its membership and order must
    /// stop being an OS-scheduling accident. Sorting by `EventId` --
    /// `(role, thread, checkpoint, occurrence)` -- makes a decision a function
    /// of the ready *set*, not of the order events happened to arrive in; the
    /// full readout makes the set every thread at a checkpoint.
    fn canonicalize_ready(&mut self) {
        let mut pairs: Vec<(ReadyCheckpointHit, Pid)> = self
            .threads
            .iter()
            .filter(|(_, t)| t.state == State::Parked)
            .filter_map(|(tid, t)| Some((t.hit.clone()?, *tid)))
            .collect();
        pairs.sort_by(|(a, _), (b, _)| a.event.cmp(&b.event));
        (self.ready, self.ready_pids) = pairs.into_iter().unzip();
    }

    /// `timed`: whether some Blocked thread was in a timed sleep at this
    /// readout.
    fn advance(&mut self, timed: bool) -> Result<Advanced> {
        let mut released = 0usize;
        self.canonicalize_ready();
        let frozen = self.threads.values().any(|t| t.frozen.is_some());

        // The attacker/oracle orchestration drives itself; it does not consult a
        // `DecisionPolicy`, so it takes a separate path.
        if self.phase == Phase::Enforcing && matches!(self.driver, Driver::Attack(_)) {
            let n = self.advance_attack()?;
            if timed {
                self.timed_sleep_decisions += n as u32;
            }
            if frozen {
                self.frozen_decisions += n as u32;
            }
            released += n;
        }

        if self.phase == Phase::Enforcing && matches!(self.driver, Driver::Policy(_)) {
            let mut last_divergence: Option<String> = None;
            while !self.ready.is_empty() {
                self.decisions.push(
                    self.ready
                        .iter()
                        .map(|h| match &h.event.actor.thread {
                            Some(t) => format!("{}/{}@{}", h.role_name, t, h.checkpoint),
                            None => format!("{}@{}", h.role_name, h.checkpoint),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                );
                if timed {
                    self.timed_sleep_decisions += 1;
                }
                if frozen {
                    self.frozen_decisions += 1;
                }
                let decision = match &mut self.driver {
                    Driver::Policy(p) => p.decide(&self.ready),
                    Driver::Attack(_) => unreachable!("attack driver takes the branch above"),
                };
                match decision {
                    Decision::Release(i) => {
                        self.release_at(i, true)?;
                        released += 1;
                        // Exactly one event runs at a time: the whole point of
                        // `Enforcing` is that everyone else stays held. Break,
                        // so the next decision waits for the next full
                        // readout, which the released thread is part of.
                        break;
                    }
                    Decision::Drain => {
                        self.phase = Phase::Draining;
                        break;
                    }
                    Decision::Divergence(reason) => {
                        match self.config.on_divergence {
                            DivergencePolicy::Abort => {
                                return Ok(Advanced {
                                    released,
                                    outcome: Some(RunOutcome::Diverged {
                                        step_idx: self.canonical.len() as u64,
                                        reason,
                                    }),
                                });
                            }
                            DivergencePolicy::Block => break,
                            DivergencePolicy::Skip => {
                                // Guard against a policy whose `skip` is a
                                // no-op: an unchanged reason means skipping
                                // achieved nothing, so treat it as a block
                                // rather than spinning.
                                if last_divergence.as_deref() == Some(reason.as_str()) {
                                    break;
                                }
                                last_divergence = Some(reason);
                                if let Driver::Policy(p) = &mut self.driver {
                                    p.skip();
                                }
                            }
                        }
                    }
                }
            }
        }

        if self.phase == Phase::Draining {
            // Draining releases are not decisions, so they are not recorded:
            // the canonical log must stay equal to the enforced sequence, or
            // its projection would replay steps nobody chose.
            while !self.ready.is_empty() {
                self.release_at(0, false)?;
                released += 1;
            }
        }

        Ok(Advanced {
            released,
            outcome: None,
        })
    }

    /// One step of the attacker/oracle orchestration (`PolicyType::AutoAttack`).
    ///
    /// Handles at most one ready entry per call, then returns so the released
    /// victim can reach its next hold before the next step -- the same
    /// one-at-a-time discipline the policy loop keeps. Per the window model
    /// (attacker brainstorm): observe the previous window (the victim is frozen
    /// again, so its use has run), run the attacker on the path this use will
    /// resolve, then release the victim.
    fn advance_attack(&mut self) -> Result<usize> {
        if self.ready.is_empty() {
            return Ok(0);
        }

        // The victim has parked again (this is the readout that follows), so
        // whatever use it last ran has completed: rule on the previous window.
        self.run_pending_oracle();

        let checkpoint = self.ready[0].checkpoint.clone();
        let path = self.ready[0].path.clone();
        let pid = self.ready_pids[0];
        let tgid = self.thread(pid, pid, None).tgid;

        // Hold the whole victim, so a sibling woken by the attacker's actions
        // (inotify, a pipe) cannot run inside the window.
        self.backend.gate_group(tgid)?;

        // Fingerprint the path on either side of the attacker's turn. The
        // victim is frozen throughout, so any difference between the two is
        // the window's substitution -- not the victim's own syscall, which has
        // not run yet. A post-*use* diff would misread every legitimate
        // `mount`, because a mount changes the object its target resolves to.
        let before = path.as_deref().and_then(PathIdentity::of);

        // Run the attacker inside the frozen window, on the path this syscall
        // resolves. A failure to act is a setup problem (attacker brainstorm's
        // ACTION-FAILED), never a finding: log it and release the victim
        // anyway, so the run is not derailed by one unusable primitive.
        let outcome = match &self.driver {
            Driver::Attack(a) => attacker::run(&a.spec, checkpoint.as_str(), path.as_deref()),
            Driver::Policy(_) => unreachable!("advance_attack runs only for the attack driver"),
        };
        if let AttackOutcome::Failed { error } = &outcome {
            log::warn!("attacker could not act at {checkpoint}: {error}");
        }

        let after = path.as_deref().and_then(PathIdentity::of);
        // Before the release: a hit released into a still-gated group would
        // be held again on its way back to userspace.
        self.backend.ungate_group(tgid)?;

        // Release the victim so the use runs; record it so the log projects to a
        // replayable schedule. The step index is the position this release takes.
        let step_idx = self.canonical.len() as u64;
        self.release_at(0, true)?;

        // Remember the window; its oracle runs at the victim's next hold or its
        // leader's exit.
        if let Driver::Attack(a) = &mut self.driver {
            a.pending = Some(WindowContext {
                checkpoint,
                path,
                before,
                after,
                step_idx,
            });
        }
        Ok(1)
    }

    /// Rule on the pending window, if any, and record the verdict. The victim
    /// must be frozen when this is called, so the window's use has run.
    fn run_pending_oracle(&mut self) {
        let observed = match &mut self.driver {
            Driver::Attack(a) => a
                .pending
                .take()
                .map(|ctx| (ctx.step_idx, a.oracle.observe(&ctx))),
            Driver::Policy(_) => None,
        };
        if let Some((step_idx, verdict)) = observed {
            if let OracleVerdict::Violation(reason) = &verdict {
                log::warn!("oracle finding at step {step_idx}: {reason}");
            }
            self.oracle_verdicts.push((step_idx, verdict));
        }
    }

    fn release_at(&mut self, i: usize, record: bool) -> Result<()> {
        let hit = self.ready.remove(i);
        let pid = self.ready_pids.remove(i);
        // Running before the answer, so its wakeup is not read as a signal.
        let t = self.thread(pid, pid, None);
        t.state = State::Running;
        t.hit = None;
        // Every budget restarts; a frozen thread waits for this one.
        for t in self.threads.values_mut() {
            t.cpu_base = None;
            if let Some(f) = &mut t.frozen {
                f.after.get_or_insert(pid);
            }
        }
        if record {
            let step_idx = self.canonical.record(
                hit.role_name.clone(),
                hit.event.actor.thread.as_ref().map(ToString::to_string),
                hit.checkpoint.clone(),
            );
            self.debug.record(DebugEntry {
                step_idx,
                pid,
                role: hit.role_name,
                checkpoint: hit.checkpoint,
                provenance: self
                    .provenance
                    .get(&pid)
                    .copied()
                    .unwrap_or(Provenance::Cached),
                elapsed_ns: self.started.elapsed().as_nanos(),
            });
        }
        self.backend.release(hit.handle)?;
        Ok(())
    }
}

/// `/proc/<tid>/<file>`, best-effort: `?` when unreadable.
fn proc_file(tid: Pid, file: &str) -> String {
    std::fs::read_to_string(format!("/proc/{tid}/{file}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

struct Advanced {
    released: usize,
    outcome: Option<RunOutcome>,
}

fn build_driver(config: &ScenarioConfig) -> Driver {
    match &config.mode {
        Mode::Replay { steps } => Driver::Policy(Box::new(FixedSchedule::new(steps.clone()))),
        Mode::Discovery { policy } => match policy.policy_type {
            // The attacker/oracle orchestration. Config validation guarantees
            // an `attack` section and a single victim role, so the `expect`
            // cannot fire on a parsed config; it stays explicit rather than
            // silently substituting an empty attacker.
            PolicyType::AutoAttack => Driver::Attack(AttackDriver {
                spec: config
                    .attack
                    .clone()
                    .expect("auto_attack config carries an attack section (validated)"),
                pending: None,
                oracle: Oracle::new(config.oracle.clone().unwrap_or_default()),
            }),
            // POS: seeded per-event priority with conflict-only redraw. See
            // `policy::PosPolicy`.
            PolicyType::Pos => Driver::Policy(Box::new(PosPolicy::new(policy.seed))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::NotifyHandle;
    use crate::backend::StubBackend;
    use crate::role::RoleId;
    use crate::role::TaskInfo;

    fn config(policy: &str, attack: &str) -> ScenarioConfig {
        ScenarioConfig::from_json(&format!(
            r#"{{ "scenario_id": "s", "cgroup": "/c",
                 "roles": [{{ "id": "victim", "comm": "v" }}],
                 "policy": {policy} {attack} }}"#
        ))
        .unwrap()
    }

    fn pos() -> Engine<StubBackend> {
        Engine::new(config(r#"{ "type": "pos", "seed": 1 }"#, ""), StubBackend::new())
    }

    fn state(tid: Pid, tgid: Pid, kind: ThreadStateKind) -> BackendEvent {
        BackendEvent::ThreadState {
            tid,
            tgid,
            kind,
            arg: 0,
        }
    }

    fn hit(pid: Pid, handle: u64) -> BackendEvent {
        BackendEvent::CheckpointHit {
            pid,
            checkpoint: CheckpointId::new("openat"),
            handle: NotifyHandle(handle),
            path: None,
            keys: Vec::new(),
        }
    }

    #[test]
    fn pos_gives_each_thread_its_own_actor_and_auto_attack_does_not() {
        let victim = RoleRef::one(RoleId(0));
        let mut pos = pos();
        pos.thread(100, 100, None);
        pos.thread(101, 100, Some(100));
        assert_ne!(pos.actor_for(victim, 100), pos.actor_for(victim, 101));
        assert_eq!(
            pos.actor_for(victim, 101).thread,
            Some(ThreadPath(vec![0, 0])),
            "the leader's first clone"
        );

        let mut aa = Engine::new(
            config(
                r#"{ "type": "auto_attack" }"#,
                r#", "attack": { "argv": ["true"] }"#,
            ),
            StubBackend::new(),
        );
        assert_eq!(aa.actor_for(victim, 100), ActorId::role(victim));
        assert_eq!(aa.actor_for(victim, 101), ActorId::role(victim));
    }

    #[test]
    fn a_pending_window_is_ruled_on_when_the_victim_s_leader_exits() {
        let mut e = Engine::new(
            config(
                r#"{ "type": "auto_attack" }"#,
                r#", "attack": { "argv": ["true"] }"#,
            ),
            StubBackend::new(),
        );
        for pid in [100, 101] {
            e.handle_event(BackendEvent::TaskAppeared(TaskInfo {
                pid,
                tgid: 100,
                parent_tgid: 1,
                comm: "v".into(),
                cgroup: "/c/run0".into(),
            }))
            .unwrap();
        }
        // Thread 101's window was released, and it never parks again.
        if let Driver::Attack(a) = &mut e.driver {
            a.pending = Some(WindowContext {
                checkpoint: CheckpointId::new("openat"),
                path: None,
                before: None,
                after: None,
                step_idx: 0,
            });
        }
        e.handle_event(state(101, 100, ThreadStateKind::Exited)).unwrap();
        assert!(e.oracle_verdicts().is_empty(), "a non-leader exit");
        e.handle_event(state(100, 100, ThreadStateKind::Exited)).unwrap();
        assert_eq!(e.oracle_verdicts(), [(0, OracleVerdict::Clean)]);
    }

    #[test]
    fn a_pending_window_is_ruled_before_a_deadlock() {
        // The victim parks at one use, is released, then sleeps somewhere that
        // is not a checkpoint and never wakes: the run deadlocks. Everything is
        // at rest, so the released use has provably completed and its window
        // must still be ruled on rather than lost to the deadlock.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"BENIGN").unwrap();
        let backend = StubBackend::new()
            .task(TaskInfo {
                pid: 100,
                tgid: 100,
                parent_tgid: 1,
                comm: "v".into(),
                cgroup: "/c/run0".into(),
            })
            .hit_path(100, "openat", Some(target.to_str().unwrap()))
            .state(100, ThreadStateKind::Asleep, 1);
        let mut e = Engine::new(
            config(
                r#"{ "type": "auto_attack" }"#,
                r#", "attack": { "argv": ["true"] }"#,
            ),
            backend,
        );
        assert!(matches!(e.run().unwrap(), RunOutcome::Deadlocked { .. }));
        assert_eq!(e.oracle_verdicts().len(), 1, "the pending window was ruled on");
    }

    #[test]
    fn a_hit_parks_its_thread_only_once_it_is_asleep_in_either_order() {
        let mut e = pos();
        e.handle_event(BackendEvent::TaskAppeared(TaskInfo {
            pid: 100,
            tgid: 100,
            parent_tgid: 1,
            comm: "v".into(),
            cgroup: "/c/run0".into(),
        }))
        .unwrap();
        e.handle_event(hit(100, 0)).unwrap();
        assert!(!e.at_rest(), "a hit alone: still on its way to sleep");
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        assert!(e.at_rest() && e.readout_complete());

        // A signal: its wakeup drops the dead hit, and the re-park (whose
        // `Asleep` came in the batch before its hit) parks again.
        e.handle_event(state(100, 100, ThreadStateKind::WakeStart)).unwrap();
        assert!(!e.at_rest(), "mid-wakeup");
        e.handle_event(state(100, 100, ThreadStateKind::WakeDone)).unwrap();
        assert!(e.threads[&100].hit.is_none());
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        assert!(e.at_rest() && !e.readout_complete(), "blocked, not parked");
        e.handle_event(hit(100, 1)).unwrap();
        assert_eq!(e.threads[&100].state, State::Parked);
        assert!(e.readout_complete());
    }

    #[test]
    fn a_stale_asleep_or_a_wake_in_progress_never_parks_a_hit() {
        let mut e = pos();
        e.handle_event(BackendEvent::TaskAppeared(TaskInfo {
            pid: 100,
            tgid: 100,
            parent_tgid: 1,
            comm: "v".into(),
            cgroup: "/c/run0".into(),
        }))
        .unwrap();
        // An earlier sleep; its wakeup arrives in the hit's batch, ahead of it.
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        e.handle_event(state(100, 100, ThreadStateKind::WakeStart)).unwrap();
        e.handle_event(state(100, 100, ThreadStateKind::WakeDone)).unwrap();
        e.handle_event(hit(100, 0)).unwrap();
        assert_eq!(e.threads[&100].state, State::Running, "the stale Asleep");
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        assert_eq!(e.threads[&100].state, State::Parked);

        // Released, asleep again, and a wake already started when the next
        // hit lands: it waits for the next `Asleep`.
        e.threads.get_mut(&100).unwrap().hit = None;
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        e.handle_event(state(100, 100, ThreadStateKind::WakeStart)).unwrap();
        e.handle_event(hit(100, 1)).unwrap();
        assert_eq!(e.threads[&100].state, State::Blocked);
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        assert_eq!(e.threads[&100].state, State::Blocked, "an Asleep mid-wake");
        e.handle_event(state(100, 100, ThreadStateKind::WakeDone)).unwrap();
        e.handle_event(state(100, 100, ThreadStateKind::Asleep)).unwrap();
        assert_eq!(e.threads[&100].state, State::Parked);
    }

    #[test]
    fn an_out_of_scope_hit_is_released_and_never_recorded() {
        let mut e = Engine::new(
            config(r#"{ "type": "pos", "seed": 1 }"#, ""),
            StubBackend::new().out_of_scope(100),
        );
        // It matches the role's comm, but its cgroup is outside the scenario:
        // forked by an in-scope runc, then moved into the container's own
        // cgroup. The role table must not hand it a role.
        e.handle_event(BackendEvent::TaskAppeared(TaskInfo {
            pid: 100,
            tgid: 100,
            parent_tgid: 1,
            comm: "v".into(),
            cgroup: "/other/ctr0".into(),
        }))
        .unwrap();
        assert!(e.roles.lookup(100).is_none(), "out of scope: no role");
        e.handle_event(hit(100, 7)).unwrap();
        assert_eq!(e.backend.released, [NotifyHandle(7)], "answered at once");
        assert!(
            !e.threads.contains_key(&100),
            "never tracked: no stale Running entry the sensor cannot retire"
        );
    }

    #[test]
    fn a_tracked_thread_that_leaves_scope_is_retired_by_the_watchdog() {
        // Resolved in scope, then moved out (the container's own cgroup): the
        // sensor can no longer report it, so it must not keep `at_rest()` false.
        let mut e = Engine::new(
            config(r#"{ "type": "pos", "seed": 1 }"#, ""),
            StubBackend::new().out_of_scope(100),
        );
        e.handle_event(state(100, 100, ThreadStateKind::Joined)).unwrap();
        assert_eq!(e.threads[&100].state, State::Running);
        e.watchdog().unwrap();
        assert_eq!(e.threads[&100].state, State::Exited, "retired, not waited on");
        assert!(e.at_rest());
    }

    #[test]
    fn a_hit_for_an_exited_thread_still_answers_its_notification() {
        let mut e = pos();
        e.handle_event(state(100, 100, ThreadStateKind::Joined)).unwrap();
        e.handle_event(state(100, 100, ThreadStateKind::Exited)).unwrap();
        assert_eq!(e.threads[&100].state, State::Exited);
        e.handle_event(hit(100, 3)).unwrap();
        assert_eq!(
            e.backend.released,
            [NotifyHandle(3)],
            "the dead hit is answered, not left parked"
        );
    }

    #[test]
    fn a_group_join_numbers_the_group_off_its_leader() {
        let mut e = pos();
        let joined = |tid, arg| BackendEvent::ThreadState {
            tid,
            tgid: 100,
            kind: ThreadStateKind::Joined,
            arg,
        };
        // As `GateBackend::poll` expands a group attach: the leader, then
        // the rest of the group in tid order.
        e.handle_event(joined(100, 1)).unwrap();
        e.handle_event(joined(101, 0)).unwrap();
        e.handle_event(joined(103, 0)).unwrap();
        e.handle_event(BackendEvent::ThreadState {
            tid: 104,
            tgid: 100,
            kind: ThreadStateKind::Created,
            arg: 101,
        })
        .unwrap();
        let paths: Vec<String> = e.threads.values().map(|t| t.path.to_string()).collect();
        assert_eq!(paths, ["t0", "t0.0", "t0.1", "t0.0.0"]);
    }

    #[test]
    fn a_closed_backend_with_a_thread_never_heard_from_ends_the_run() {
        // Spawned, but gone without an `Exited` record (it never joined the
        // cgroup): with no `/proc` entry it is exited, not waited on forever.
        let mut e = Engine::new(
            config(r#"{ "type": "pos", "seed": 1 }"#, ""),
            StubBackend::new().spawn(2_000_000_000),
        );
        assert_eq!(e.run().unwrap(), RunOutcome::Completed);
        assert_eq!(e.threads[&2_000_000_000].state, State::Exited);
    }

    #[test]
    fn exits_are_terminal_and_a_group_detach_covers_the_group() {
        let mut e = pos();
        e.handle_event(state(100, 100, ThreadStateKind::Joined)).unwrap();
        e.handle_event(state(101, 100, ThreadStateKind::Joined)).unwrap();
        e.handle_event(state(200, 200, ThreadStateKind::Joined)).unwrap();
        e.handle_event(BackendEvent::ThreadState {
            tid: 100,
            tgid: 100,
            kind: ThreadStateKind::Left,
            arg: 1,
        })
        .unwrap();
        assert_eq!(e.threads[&101].state, State::Exited);
        assert_eq!(e.threads[&200].state, State::Running);
        e.handle_event(state(101, 100, ThreadStateKind::WakeStart)).unwrap();
        assert!(!e.threads[&101].wake_in_progress, "ignored after exit");
    }

    #[test]
    fn spawned_children_are_seeded_running_as_group_leaders() {
        let mut e = Engine::new(
            config(r#"{ "type": "pos", "seed": 1 }"#, ""),
            StubBackend::new().spawn(7).exit(7),
        );
        e.run().unwrap();
        // An exit of a tid never seen would have made no entry.
        assert_eq!(e.threads[&7].path, ThreadPath(vec![0]));
    }

    /// The victim 100 parks at `openat` while the unmatched spinner 200 runs:
    /// 2 s of CPU against a 1 s budget.
    fn spinning(b: StubBackend) -> StubBackend {
        b.spawn(200)
            .cpu(200, &[0, 2_000_000_000])
            .spinner(200)
            .exit(200)
            .task(TaskInfo {
                pid: 100,
                tgid: 100,
                parent_tgid: 1,
                comm: "v".into(),
                cgroup: "/c/run0".into(),
            })
            .hit(100, "openat")
    }

    #[test]
    fn a_spinner_over_budget_is_frozen_and_thawed_once_the_release_is_back_at_rest() {
        let mut c = config(r#"{ "type": "pos", "seed": 1 }"#, "");
        c.watchdog_cpu_secs = 1;
        let b = spinning(StubBackend::new())
            .state(100, ThreadStateKind::Asleep, 1)
            .exit(100);
        let mut e = Engine::new(c, b);
        assert_eq!(e.run().unwrap(), RunOutcome::Completed);
        // Frozen, it no longer blocked the readout: the decision was taken
        // with it frozen, and the spinner was thawed only after the released
        // victim slept again (it exits only once thawed).
        assert_eq!(e.decision_trace(), ["victim/t0@openat"]);
        assert_eq!(e.frozen_decisions(), 1);
        assert_eq!(
            e.backend.gate_calls,
            [("freeze", 200), ("release", 100), ("thaw", 200)]
        );
    }

    #[test]
    fn a_run_does_not_end_deadlocked_while_a_thread_is_frozen() {
        // A replay step nobody reaches: no decision can release the victim,
        // so only the forced thaw lets the spinner on.
        let c = ScenarioConfig::from_json(
            r#"{ "scenario_id": "s", "cgroup": "/c", "watchdog_cpu_secs": 1,
                 "roles": [{ "id": "victim", "comm": "v" }],
                 "checkpoints": [
                     { "id": "openat", "kind": "syscall", "target": "openat" },
                     { "id": "stat", "kind": "syscall", "target": "newfstatat" }
                 ],
                 "steps": [{ "role": "victim", "until": "stat" }] }"#,
        )
        .unwrap();
        let mut e = Engine::new(c, spinning(StubBackend::new()));
        e.forced_thaw = Duration::from_millis(100);
        let started = Instant::now();
        assert!(matches!(e.run().unwrap(), RunOutcome::Deadlocked { .. }));
        assert!(started.elapsed() >= e.forced_thaw, "waited out the freeze");
        assert_eq!(e.backend.gate_calls, [("freeze", 200), ("thaw", 200)]);
        assert!(e.frozen_decisions() >= 1);
    }

    #[test]
    fn the_freeze_diagnostic_names_the_thread_and_the_parked_set() {
        let mut e = pos();
        e.backend = spinning(StubBackend::new());
        e.thread(200, 200, None);
        for _ in 0..3 {
            let Poll::Events(events) = e.backend.poll(None).unwrap() else {
                panic!()
            };
            for ev in events {
                e.handle_event(ev).unwrap();
            }
        }
        assert_eq!(e.threads[&100].state, State::Parked);
        let line = e.freeze_diagnostic(200, 2_000_000_000);
        assert!(line.starts_with("watchdog: froze -/t0 tid 200 ("), "{line}");
        assert!(line.contains("2.0 s CPU"), "{line}");
        assert!(line.ends_with("parked: victim/t0@openat"), "{line}");
    }

    #[test]
    fn clone_paths_do_not_depend_on_how_creations_interleave() {
        let paths = |seed| {
            // 100 creates 101, forks 300, creates 102; 101 creates 103; 300
            // creates 301; 200 creates 201.
            let b = StubBackend::new()
                .spawn(100)
                .spawn(200)
                .created(100, 101, 100)
                .created(100, 300, 300)
                .created(100, 102, 100)
                .created(101, 103, 100)
                .created(300, 301, 300)
                .created(200, 201, 200);
            let b = [100, 101, 102, 103, 200, 201, 300, 301]
                .into_iter()
                .fold(b, |b, t| b.exit(t))
                .shuffle(seed);
            let mut e = Engine::new(config(r#"{ "type": "pos", "seed": 1 }"#, ""), b);
            e.run().unwrap();
            e.threads
                .iter()
                .map(|(tid, t)| format!("{tid}={}", t.path))
                .collect::<Vec<_>>()
        };
        let expected = [
            "100=t0", "101=t0.0", "102=t0.1", "103=t0.0.0", "200=t0", "201=t0.0", "300=t0",
            "301=t0.0",
        ];
        for seed in 0..64 {
            assert_eq!(paths(seed), expected, "seed {seed}");
        }
    }
}
