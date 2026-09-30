// SPDX-License-Identifier: GPL-2.0
//
// The three-phase state machine: Barrier -> Enforcing -> Draining.
//
// Design doc: Background ("Schedule and the three-phase state machine"), with
// the `Enforcing` phase generalized per section 3 so that "which role goes
// next" is asked through `DecisionPolicy` rather than answered by
// `schedule[step_idx]` directly.

use crate::attacker;
use crate::attacker::AttackOutcome;
use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::Poll;
use crate::backend::EXIT_HANDLE;
use crate::checkpoint::CheckpointId;
use crate::config::AttackDecl;
use crate::config::DivergencePolicy;
use crate::config::Mode;
use crate::config::PolicyType;
use crate::config::ScenarioConfig;
use crate::log::CanonicalLog;
use crate::log::DebugEntry;
use crate::log::DebugLog;
use crate::oracle::OracleVerdict;
use crate::oracle::PathIdentity;
use crate::oracle::WindowContext;
use crate::policy::Decision;
use crate::policy::DecisionPolicy;
use crate::policy::FixedSchedule;
use crate::policy::OrderedWalk;
use crate::policy::ReadyCheckpointHit;
use crate::role::Pid;
use crate::role::Provenance;
use crate::role::RoleTable;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

/// What drives releases in the `Enforcing` phase.
///
/// The `DecisionPolicy` seam answers "which held role goes next" for replay and
/// the ordered-walk discovery policy. The attacker/oracle orchestration
/// (`PolicyType::AutoAttack`) does not fit that seam -- only the victim is ever
/// held, so there is no choice of role, and each release is bracketed by an
/// attacker turn and an oracle observation the `decide` signature cannot
/// express. It therefore drives the engine directly, as a second kind of
/// driver rather than a policy.
enum Driver {
    Policy(Box<dyn DecisionPolicy>),
    Attack(AttackDriver),
}

/// State for the attacker/oracle orchestration.
struct AttackDriver {
    /// The external attacker run inside each window.
    spec: AttackDecl,
    /// The window whose oracle has not run yet: set when the victim is released
    /// to a use, observed at the victim's next hold or exit -- the first point
    /// the use has provably completed and the victim is frozen again.
    pending: Option<WindowContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for every `one`-cardinality role to appear at least once.
    Barrier,
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
    /// The run stopped making progress.
    ///
    /// The base design tracks this with a supervisory wall-clock timeout from
    /// the canonical log's last `step_idx` advance. That timer belongs to the
    /// harness, which is out of this scaffold's scope; what the engine can see
    /// on its own is that the backend has no further events *and* the policy is
    /// blocked, which is the same condition arriving by a different route.
    TimedOut { reason: String },
}

/// Bound on consecutive no-progress polls before the engine gives up.
///
/// Not a substitute for the harness's supervisory timeout -- it exists so that
/// a blocked run terminates deterministically instead of spinning, which
/// matters because a test must not be able to hang the suite.
const MAX_IDLE_ROUNDS: u32 = 64;

pub struct Engine<B: CheckpointBackend> {
    config: ScenarioConfig,
    backend: B,
    roles: RoleTable,
    driver: Driver,
    phase: Phase,
    /// Every role/checkpoint pair currently blocked and eligible for release.
    ready: Vec<ReadyCheckpointHit>,
    /// How each ready entry's role was resolved, for the debug log only.
    provenance: HashMap<Pid, Provenance>,
    /// The pid behind each ready entry. Kept out of `ReadyCheckpointHit` so a
    /// policy structurally cannot see a pid and start depending on one.
    ready_pids: Vec<Pid>,
    /// pid -> tgid, from `TaskAppeared`. A role is a thread group, so only the
    /// thread-group leader's exit is the role exiting.
    tgids: HashMap<Pid, Pid>,
    canonical: CanonicalLog,
    debug: DebugLog,
    /// The ready set as it stood at each `decide()` call: the
    /// ready-set-sequence section 10.1's determinism claim depends on,
    /// recorded so it can be compared across runs. Finer-grained than arrival
    /// order on purpose; see the crate docs, "Section 14-A is no longer open".
    decisions: Vec<String>,
    /// Oracle rulings, one per observed window: `(release step index, verdict)`.
    /// Kept off the canonical log, which must stay equal to the enforced release
    /// sequence so its projection replays exactly; a finding is reported
    /// alongside, not woven into it.
    oracle_verdicts: Vec<(u64, OracleVerdict)>,
    started: Instant,
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
            phase: Phase::Barrier,
            ready: Vec::new(),
            provenance: HashMap::new(),
            ready_pids: Vec::new(),
            tgids: HashMap::new(),
            canonical,
            debug: DebugLog::default(),
            decisions: Vec::new(),
            oracle_verdicts: Vec::new(),
            started: Instant::now(),
        }
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

    /// The ready set at each decision point. See `decisions`.
    pub fn decision_trace(&self) -> &[String] {
        &self.decisions
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

        let mut closed = false;
        let mut idle_rounds = 0u32;

        loop {
            let progressed = match self.backend.poll()? {
                Poll::Events(events) => {
                    for e in events {
                        self.handle_event(e)?;
                    }
                    true
                }
                Poll::Idle => false,
                Poll::Closed => {
                    closed = true;
                    false
                }
            };

            let acted = self.advance()?;
            if let Some(outcome) = acted.outcome {
                return Ok(outcome);
            }

            if progressed || acted.released > 0 {
                idle_rounds = 0;
            } else {
                idle_rounds += 1;
            }

            if closed && self.ready.is_empty() {
                return Ok(self.final_outcome());
            }
            if idle_rounds >= MAX_IDLE_ROUNDS {
                return Ok(RunOutcome::TimedOut {
                    reason: format!(
                        "no progress for {MAX_IDLE_ROUNDS} polls in phase {:?} with {} role(s) held",
                        self.phase,
                        self.ready.len()
                    ),
                });
            }
        }
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
                self.tgids.insert(task.pid, task.tgid);
                if let Some((_, provenance)) = self.roles.resolve_role(&task) {
                    self.provenance.insert(task.pid, provenance);
                }
            }
            BackendEvent::CheckpointHit {
                pid,
                checkpoint,
                handle,
                path,
            } => {
                // A task the role table does not recognise is not ours to
                // schedule: release it at once and never record it. That is the
                // blast-radius guarantee -- a bug in this engine must not be
                // able to degrade or hang unrelated work on the machine.
                let Some(role) = self.roles.lookup(pid) else {
                    self.backend.release(handle)?;
                    return Ok(());
                };
                let role_name = self.roles.render(role);
                self.ready.push(ReadyCheckpointHit {
                    role,
                    role_name,
                    checkpoint,
                    handle,
                    path,
                });
                self.ready_pids.push(pid);
            }
            BackendEvent::TaskExited(pid) => {
                // Resolve before eviction: `until: exit` needs to know whose
                // exit this was.
                let role = self.roles.lookup(pid);
                let is_leader = self.is_thread_group_leader(pid);
                self.roles.on_task_exit(pid);
                self.provenance.remove(&pid);
                self.tgids.remove(&pid);

                // A role's exit becomes an ordinary ready-set entry carrying the
                // reserved `exit` checkpoint, so a policy sees one uniform kind
                // of thing to decide over. Only the thread-group leader's exit
                // counts: a role is a thread group, and a single Go runtime
                // thread going away is not the role exiting.
                if let (Some(role), true) = (role, is_leader) {
                    let role_name = self.roles.render(role);
                    self.ready.push(ReadyCheckpointHit {
                        role,
                        role_name,
                        checkpoint: CheckpointId::exit(),
                        handle: EXIT_HANDLE,
                        path: None,
                    });
                    self.ready_pids.push(pid);
                }
            }
        }
        Ok(())
    }

    /// A role is a thread group, so a single Go runtime thread going away is
    /// not the role exiting -- only the thread-group leader's exit is. A pid
    /// never announced defaults to being its own leader.
    fn is_thread_group_leader(&self, pid: Pid) -> bool {
        self.tgids.get(&pid).copied().unwrap_or(pid) == pid
    }

    fn advance(&mut self) -> Result<Advanced> {
        let mut released = 0usize;

        if self.phase == Phase::Barrier && self.roles.all_roles_seen() {
            self.phase = Phase::Enforcing;
        }

        // The attacker/oracle orchestration drives itself; it does not consult a
        // `DecisionPolicy`, so it takes a separate path.
        if self.phase == Phase::Enforcing && matches!(self.driver, Driver::Attack(_)) {
            released += self.advance_attack()?;
        }

        if self.phase == Phase::Enforcing && matches!(self.driver, Driver::Policy(_)) {
            let mut last_divergence: Option<String> = None;
            while !self.ready.is_empty() {
                self.decisions.push(
                    self.ready
                        .iter()
                        .map(|h| format!("{}@{}", h.role_name, h.checkpoint))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                let decision = match &mut self.driver {
                    Driver::Policy(p) => p.decide(&self.ready),
                    Driver::Attack(_) => unreachable!("attack driver takes the branch above"),
                };
                match decision {
                    Decision::Release(i) => {
                        self.release_at(i, true)?;
                        released += 1;
                        // Exactly one role runs at a time: the whole point of
                        // `Enforcing` is that everyone else stays held. Break
                        // rather than draining the ready set, so the released
                        // role reaches its next checkpoint (or exits) and
                        // rejoins the ready set before the next decision.
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

        // The victim is held again, so whatever use it last ran has completed:
        // this is the race-free point to rule on the previous window.
        self.run_pending_oracle();

        let checkpoint = self.ready[0].checkpoint.clone();
        let path = self.ready[0].path.clone();

        // The victim's exit carries the reserved `exit` checkpoint. Its window
        // was observed just above; let it go and there is no attacker to run.
        if checkpoint.is_exit() {
            self.release_at(0, true)?;
            return Ok(1);
        }

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

        // Release the victim so the use runs; record it so the log projects to a
        // replayable schedule. The step index is the position this release takes.
        let step_idx = self.canonical.len() as u64;
        self.release_at(0, true)?;

        // Remember the window; its oracle runs at the victim's next hold or exit.
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
                .map(|ctx| (ctx.step_idx, crate::oracle::observe(&ctx))),
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
        if record {
            let step_idx = self
                .canonical
                .record(hit.role_name.clone(), hit.checkpoint.clone());
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
            }),
            // Drawn against every declared role, including pool roles: a
            // pool's existence (if not its membership) is fixed at
            // config-parse time, so this needs nothing the ready set would
            // otherwise have to supply. See `policy::OrderedWalk`.
            PolicyType::OrderedWalk => {
                Driver::Policy(Box::new(OrderedWalk::new(policy.seed, config.roles.len())))
            }
        },
    }
}
