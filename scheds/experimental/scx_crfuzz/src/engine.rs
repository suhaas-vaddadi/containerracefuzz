// SPDX-License-Identifier: GPL-2.0
//
// The three-phase state machine: Barrier -> Enforcing -> Draining.
//
// Design doc: Background ("Schedule and the three-phase state machine"), with
// the `Enforcing` phase generalized per section 3 so that "which role goes
// next" is asked through `DecisionPolicy` rather than answered by
// `schedule[step_idx]` directly.

use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::Poll;
use crate::backend::EXIT_HANDLE;
use crate::checkpoint::CheckpointId;
use crate::config::DivergencePolicy;
use crate::config::Mode;
use crate::config::PolicyType;
use crate::config::ScenarioConfig;
use crate::log::CanonicalLog;
use crate::log::DebugEntry;
use crate::log::DebugLog;
use crate::policy::Decision;
use crate::policy::DecisionPolicy;
use crate::policy::FixedSchedule;
use crate::policy::OrderedWalk;
use crate::policy::Pct;
use crate::policy::RandomWalk;
use crate::policy::ReadyCheckpointHit;
use crate::role::Pid;
use crate::role::Provenance;
use crate::role::RoleTable;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

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
    policy: Box<dyn DecisionPolicy>,
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
    /// The ready set as it stood at each `decide()` call.
    ///
    /// Design doc section 10.1 rests ordering determinism on `decide()` being
    /// "a pure function of `(seed, ready-set-sequence)`". This is that
    /// ready-set-sequence, recorded so the premise can actually be checked
    /// rather than assumed.
    ///
    /// It is deliberately finer-grained than the order in which hits arrive.
    /// Two runs can see the same arrivals in the same order and still diverge,
    /// because what `decide()` is handed is the set of everything that has
    /// arrived *and not yet been released* at that instant. Whether a second
    /// role's hit lands just before or just after a decision changes the set
    /// that decision was made over -- and so changes which random draw is
    /// consumed -- without changing the arrival order at all. Section 14-A
    /// asks about arrival order; this is the quantity the purity claim
    /// actually depends on.
    decisions: Vec<String>,
    started: Instant,
}

impl<B: CheckpointBackend> Engine<B> {
    pub fn new(config: ScenarioConfig, backend: B) -> Self {
        let policy = build_policy(&config);
        let roles = RoleTable::new(config.roles.clone(), config.cgroup.clone());
        let canonical = CanonicalLog::new(config.scenario_id.clone());
        Engine {
            config,
            backend,
            roles,
            policy,
            phase: Phase::Barrier,
            ready: Vec::new(),
            provenance: HashMap::new(),
            ready_pids: Vec::new(),
            tgids: HashMap::new(),
            canonical,
            debug: DebugLog::default(),
            decisions: Vec::new(),
            started: Instant::now(),
        }
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

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn policy_name(&self) -> &'static str {
        self.policy.name()
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
        if self.phase == Phase::Draining || self.policy.is_finished() {
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
            } => {
                // A task the role table does not recognise is not ours to
                // schedule: release it at once and never record it. That is the
                // blast-radius guarantee -- a bug in this engine must not be
                // able to degrade or hang unrelated work on the machine.
                let Some(role) = self.role_of(pid) else {
                    self.backend.release(handle)?;
                    return Ok(());
                };
                let role_name = self.roles.render(role);
                self.ready.push(ReadyCheckpointHit {
                    role,
                    role_name,
                    checkpoint,
                    handle,
                });
                self.ready_pids.push(pid);
            }
            BackendEvent::TaskExited(pid) => {
                // Resolve before eviction: `until: exit` needs to know whose
                // exit this was.
                let role = self.role_of(pid);
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
                    });
                    self.ready_pids.push(pid);
                }
            }
        }
        Ok(())
    }

    fn role_of(&self, pid: Pid) -> Option<crate::role::RoleRef> {
        self.roles.lookup(pid)
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
            let one_roles = self.roles.one_roles();
            self.policy.on_barrier(&one_roles);
            self.phase = Phase::Enforcing;
        }

        if self.phase == Phase::Enforcing {
            let mut last_divergence: Option<String> = None;
            while !self.ready.is_empty() {
                self.decisions.push(
                    self.ready
                        .iter()
                        .map(|h| format!("{}@{}", h.role_name, h.checkpoint))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                match self.policy.decide(&self.ready) {
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
                                self.policy.skip();
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

fn build_policy(config: &ScenarioConfig) -> Box<dyn DecisionPolicy> {
    match &config.mode {
        Mode::Replay { steps } => Box::new(FixedSchedule::new(steps.clone())),
        Mode::Discovery { policy } => match policy.policy_type {
            PolicyType::RandomWalk => Box::new(RandomWalk::new(policy.seed)),
            // Drawn against every declared role, including pool roles: a
            // pool's existence (if not its membership) is fixed at
            // config-parse time, so this needs nothing the ready set would
            // otherwise have to supply. See `policy::OrderedWalk`.
            PolicyType::OrderedWalk => {
                Box::new(OrderedWalk::new(policy.seed, config.roles.len()))
            }
            // `d` and `k` are guaranteed present for `pct` by config
            // validation; the fallbacks keep this total rather than panicking
            // on a config built in code rather than parsed.
            PolicyType::Pct => Box::new(Pct::new(
                policy.seed,
                policy.params.d.unwrap_or(1),
                policy.params.k.unwrap_or(0),
            )),
        },
    }
}
