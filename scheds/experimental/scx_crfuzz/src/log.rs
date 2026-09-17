// SPDX-License-Identifier: GPL-2.0
//
// The canonical log, and its projection back into a replay schedule.
//
// Design doc: Background ("Canonical log") and section 3.5.
//
// The canonical log is PID-free by construction -- pids differ between runs,
// so leaving them out is what makes "did two runs make the same sequence of
// decisions?" answerable by byte-comparing two files. Pids and timings go in a
// separate debug log that is never compared.

use crate::checkpoint::CheckpointId;
use crate::config::Step;
use crate::config::StopCondition;
use crate::role::Pid;
use crate::role::Provenance;
use std::fmt::Write as _;

/// One dispatch decision: `(step_idx, role, checkpoint_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEntry {
    pub step_idx: u64,
    /// The role as `RoleTable::render` spells it: `victim`, or `racer#2`.
    pub role: String,
    pub checkpoint: CheckpointId,
}

/// The comparable record of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLog {
    /// Which scenario this log belongs to.
    ///
    /// NOTE (design doc section 14-D, unresolved): reproducing a discovery-mode
    /// finding means replaying the projected schedule "against a fresh instance
    /// of the same scenario" -- but for a mutated config, "the same scenario"
    /// means the same generated OCI spec, and neither the log format nor
    /// section 8's schema records which generated config a log came from. This
    /// field is the place that link would live; carrying the scenario id costs
    /// nothing and gives the pairing somewhere to attach. It does not settle
    /// 14-D's other half -- whether the mutator's own output is seeded and
    /// reproducible at all -- which is a question about the mutator, not this
    /// log.
    pub scenario_id: String,
    pub entries: Vec<CanonicalEntry>,
}

impl CanonicalLog {
    pub fn new(scenario_id: impl Into<String>) -> Self {
        CanonicalLog {
            scenario_id: scenario_id.into(),
            entries: Vec::new(),
        }
    }

    /// Record one release. Returns the step index assigned to it.
    pub fn record(&mut self, role: impl Into<String>, checkpoint: CheckpointId) -> u64 {
        let step_idx = self.entries.len() as u64;
        self.entries.push(CanonicalEntry {
            step_idx,
            role: role.into(),
            checkpoint,
        });
        step_idx
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The byte-comparable rendering.
    ///
    /// Deliberately excludes the policy that produced it: a replay of a
    /// projected schedule must be able to render byte-identically to the
    /// discovery run it came from, and a policy name in the header would make
    /// that impossible by construction.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# scenario {}", self.scenario_id);
        for e in &self.entries {
            let _ = writeln!(out, "{}\t{}\t{}", e.step_idx, e.role, e.checkpoint);
        }
        out
    }

    /// Project the log into a replay schedule's `steps[]` (section 3.5).
    ///
    /// This is a field drop, not a translation: a canonical entry already
    /// carries exactly the two fields a step needs. That is the whole mechanism
    /// behind "a bug discovery mode finds is replayable" -- there is no second
    /// system here that has to be correct, and so nothing extra to validate.
    pub fn project_to_steps(&self) -> Vec<Step> {
        self.entries
            .iter()
            .map(|e| Step {
                role: e.role.clone(),
                until: if e.checkpoint.is_exit() {
                    StopCondition::Exit
                } else {
                    StopCondition::Checkpoint(e.checkpoint.clone())
                },
            })
            .collect()
    }
}

/// One line of the non-compared debug log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugEntry {
    pub step_idx: u64,
    pub pid: Pid,
    pub role: String,
    pub checkpoint: CheckpointId,
    pub provenance: Provenance,
    /// Nanoseconds since the run started.
    pub elapsed_ns: u128,
}

/// Pids, timings and how each role was resolved: everything the canonical log
/// leaves out because including it would make two runs incomparable.
#[derive(Debug, Clone, Default)]
pub struct DebugLog {
    pub entries: Vec<DebugEntry>,
}

impl DebugLog {
    pub fn record(&mut self, entry: DebugEntry) {
        self.entries.push(entry);
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            let _ = writeln!(
                out,
                "{:>6}  pid={:<7} role={:<12} cp={:<12} via={:?} +{}ns",
                e.step_idx, e.pid, e.role, e.checkpoint, e.provenance, e.elapsed_ns
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> CanonicalLog {
        let mut l = CanonicalLog::new("runc-exec-symlink");
        l.record("victim", CheckpointId::new("stat"));
        l.record("racer#0", CheckpointId::new("symlink"));
        l.record("victim", CheckpointId::exit());
        l
    }

    #[test]
    fn step_indices_are_assigned_in_order() {
        let l = log();
        assert_eq!(
            l.entries.iter().map(|e| e.step_idx).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn rendering_is_stable_and_carries_no_pids() {
        let rendered = log().render();
        assert_eq!(
            rendered,
            "# scenario runc-exec-symlink\n0\tvictim\tstat\n1\tracer#0\tsymlink\n2\tvictim\texit\n"
        );
        assert_eq!(rendered, log().render());
    }

    #[test]
    fn projection_drops_step_idx_and_keeps_role_and_checkpoint() {
        let steps = log().project_to_steps();
        assert_eq!(steps.len(), 3);
        assert_eq!(
            steps[0],
            Step::new(
                "victim",
                StopCondition::Checkpoint(CheckpointId::new("stat"))
            )
        );
        assert_eq!(
            steps[1].role, "racer#0",
            "pool member survives the projection"
        );
    }

    #[test]
    fn projection_maps_the_reserved_exit_checkpoint_back_to_an_exit_step() {
        let steps = log().project_to_steps();
        assert_eq!(steps[2].until, StopCondition::Exit);
    }

    #[test]
    fn the_debug_log_carries_what_the_canonical_log_deliberately_omits() {
        let mut d = DebugLog::default();
        d.record(DebugEntry {
            step_idx: 0,
            pid: 4242,
            role: "victim".into(),
            checkpoint: CheckpointId::new("stat"),
            provenance: Provenance::Matcher,
            elapsed_ns: 1234,
        });
        let r = d.render();
        assert!(r.contains("4242"));
        assert!(!log().render().contains("4242"));
    }
}
