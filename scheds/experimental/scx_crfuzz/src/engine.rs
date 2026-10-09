// SPDX-License-Identifier: GPL-2.0
//
// One run of the sweep: hold the victim at every checkpoint hit, rule on the
// run so far, run the attacker if this hit is the selected window, release.
//
// Each hit gets a window key, `<checkpoint>#<n>`: the victim's nth hit of that
// checkpoint. Counting per checkpoint, not over the whole run, keeps a key
// stable when unrelated hits from another Go thread interleave differently.
// It is not stable when two victim thread groups (runc and `runc init`) hit
// the same checkpoint concurrently: their hits can swap numbers between runs.
// A run cannot see that, so the sweep compares each attacked window's path
// with the dry run's.
//
// A dry run (`attack.at` unset) lists every window; the sweep then runs once
// per window with `at` set to it. One attack per run, and only findings first
// seen after it are kept, so every finding in that run is the attacked
// window's doing, and the pair (scenario, window) is the reproducer.

use crate::attacker;
use crate::attacker::AttackOutcome;
use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::NotifyHandle;
use crate::backend::Poll;
use crate::checkpoint::CheckpointId;
use crate::config::ScenarioConfig;
use crate::oracle::Oracle;
use crate::role::Pid;
use crate::role::Victims;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Every spawned process exited.
    Completed,
    /// The backend reported nothing for `MAX_IDLE_ROUNDS` polls in a row.
    TimedOut { reason: String },
}

/// Bound on consecutive no-progress polls before the engine gives up, so a
/// stuck run terminates instead of spinning, and a test cannot hang the suite.
const MAX_IDLE_ROUNDS: u32 = 64;

/// One victim checkpoint hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// `<checkpoint>#<n>`.
    pub key: String,
    /// The path the held syscall resolved, when the backend captured it.
    pub path: Option<PathBuf>,
}

/// An oracle finding: an object the attacked window changed, and the window
/// key it was seen at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub seen_at: String,
    pub reason: String,
}

pub struct Engine<B: CheckpointBackend> {
    config: ScenarioConfig,
    backend: B,
    victims: Victims,
    /// Hits so far per checkpoint, for the window key.
    counts: HashMap<CheckpointId, u32>,
    windows: Vec<Window>,
    /// Built in `new`, before anything is spawned: it snapshots the host.
    oracle: Oracle,
    findings: Vec<Finding>,
    /// Whether the selected window was reached and attacked.
    attacked: bool,
}

impl<B: CheckpointBackend> Engine<B> {
    pub fn new(config: ScenarioConfig, backend: B) -> Self {
        let victims = Victims::new(
            config.victim.clone(),
            config.cgroup.clone(),
            config.container_cgroup.clone(),
        );
        let oracle = Oracle::new(config.oracle.clone());
        Engine {
            config,
            backend,
            victims,
            counts: HashMap::new(),
            windows: Vec::new(),
            oracle,
            findings: Vec::new(),
            attacked: false,
        }
    }

    pub fn windows(&self) -> &[Window] {
        &self.windows
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Whether the selected window was reached and attacked. False for a dry
    /// run, and for a run that never reached `at` -- which is not a clean run.
    pub fn attacked(&self) -> bool {
        self.attacked
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn run(&mut self) -> Result<RunOutcome> {
        let checkpoints = self.config.checkpoints.clone();
        self.backend.attach(&checkpoints)?;

        let mut idle_rounds = 0u32;
        let outcome = loop {
            match self.backend.poll()? {
                Poll::Events(events) => {
                    idle_rounds = 0;
                    for e in events {
                        self.handle_event(e)?;
                    }
                }
                Poll::Idle => idle_rounds += 1,
                Poll::Closed => break RunOutcome::Completed,
            }
            if idle_rounds >= MAX_IDLE_ROUNDS {
                break RunOutcome::TimedOut {
                    reason: format!("no backend event for {MAX_IDLE_ROUNDS} polls"),
                };
            }
        };
        Ok(outcome)
    }

    fn handle_event(&mut self, event: BackendEvent) -> Result<()> {
        match event {
            BackendEvent::TaskAppeared(task) => {
                self.victims.resolve(&task);
            }
            BackendEvent::TaskExited(pid) => self.victims.on_exit(pid),
            BackendEvent::CheckpointHit {
                pid,
                checkpoint,
                handle,
                path,
            } => self.on_hit(pid, checkpoint, handle, path)?,
        }
        Ok(())
    }

    fn on_hit(
        &mut self,
        pid: Pid,
        checkpoint: CheckpointId,
        handle: NotifyHandle,
        path: Option<PathBuf>,
    ) -> Result<()> {
        // Not the victim's: release at once and never record it. A bug here
        // must not be able to hang unrelated work on the machine.
        if !self.victims.contains(pid) {
            return self.backend.release(handle);
        }

        // Resolved to the victim: extend the backend's hold to its whole thread
        // group before observing or attacking. A backend that only holds the
        // calling thread (seccomp) treats this as a no-op; the gate uses it to
        // freeze the siblings. Non-victims were released above, so a
        // bystander's checkpoint never gates the bystander's thread group.
        self.backend.hold(pid, handle)?;

        let n = self.counts.entry(checkpoint.clone()).or_insert(0);
        let key = format!("{checkpoint}#{n}");
        *n += 1;

        // Watch the object this window resolved; the oracle diffs the watched
        // set around the attack.
        if let Some(p) = &path {
            self.oracle.watch(p.clone());
        }

        if self.config.attack.at.as_deref() == Some(key.as_str()) {
            // Snapshot before the attacker runs and again after it, and report
            // every watched object it changed. The victim is frozen for the
            // whole call, so anything that moved is the attacker's doing. A
            // primitive that fails (EPERM, EROFS) is a setup problem, never a
            // finding.
            let before = self.oracle.snapshot();
            if let AttackOutcome::Failed { error } =
                attacker::run(&self.config.attack, checkpoint.as_str(), path.as_deref())
            {
                log::warn!("attacker could not act at {key}: {error}");
            }
            self.attacked = true;
            let after = self.oracle.snapshot();
            for reason in before.diff(&after) {
                log::warn!("oracle finding at {key}: {reason}");
                self.findings.push(Finding {
                    seen_at: key.clone(),
                    reason,
                });
            }
        }

        log::debug!("window {key} pid {pid} path {path:?}");
        self.windows.push(Window { key, path });
        self.backend.release(handle)
    }
}
