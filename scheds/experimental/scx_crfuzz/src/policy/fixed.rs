// SPDX-License-Identifier: GPL-2.0
//
// `FixedSchedule` -- the base design's behaviour, restated in the
// decision-policy vocabulary (design doc section 3.3).
//
// Nothing here changes what the base design does. It looks up
// `schedule[step_idx]`, finds the matching entry in the ready set, and returns
// it; a missing match is the base design's `handle_divergence`, unchanged.
//
// One reading has to be pinned down, because the Background summary is
// ambiguous and the choice is load-bearing. "A step names a role and a
// stopping condition" could mean either:
//
//   (a) a step is one *release*: the named role is let past exactly the named
//       checkpoint, and every checkpoint it passes is its own step; or
//   (b) a step is a *run-until*: the named role is released repeatedly,
//       transparently and unrecorded, until it reaches the named checkpoint.
//
// This implements (a), because sections 3.3 and 3.5 -- the sections that
// define the generalized engine -- require it. 3.3 says `decide` "finds the
// matching entry in `ready` and returns it", i.e. returns one entry to
// release. 3.5 says the canonical log, recorded verbatim, *is* a valid
// `steps[]` list. Under (b) that identity collapses: the log would record only
// stopping points while the run also performed unrecorded intermediate
// releases, so replaying the log would not reproduce the run, and the central
// "a found bug is automatically replayable" claim would fail.
//
// The practical consequence is that a hand-authored schedule must name every
// release, not just the interesting ones. A schedule that skips ahead to a
// checkpoint its role can only reach via earlier releases is unsatisfiable,
// and is reported as a divergence rather than silently fast-forwarded.

use super::Decision;
use super::DecisionPolicy;
use super::ReadyCheckpointHit;
use crate::config::Step;
use crate::config::StopCondition;

#[derive(Debug)]
pub struct FixedSchedule {
    steps: Vec<Step>,
    step_idx: usize,
}

impl FixedSchedule {
    pub fn new(steps: Vec<Step>) -> Self {
        FixedSchedule { steps, step_idx: 0 }
    }

    pub fn step_idx(&self) -> usize {
        self.step_idx
    }

    pub fn remaining(&self) -> usize {
        self.steps.len().saturating_sub(self.step_idx)
    }

    fn matches(step: &Step, hit: &ReadyCheckpointHit) -> bool {
        if step.role != hit.role_name {
            return false;
        }
        match &step.until {
            StopCondition::Exit => hit.checkpoint.is_exit(),
            StopCondition::Checkpoint(c) => *c == hit.checkpoint,
        }
    }
}

impl DecisionPolicy for FixedSchedule {
    fn name(&self) -> &'static str {
        "fixed_schedule"
    }

    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision {
        let Some(step) = self.steps.get(self.step_idx) else {
            return Decision::Drain;
        };
        match ready.iter().position(|h| Self::matches(step, h)) {
            Some(i) => {
                self.step_idx += 1;
                Decision::Release(i)
            }
            None => Decision::Divergence(format!(
                "step {} expects role `{}` at `{}`, which is not in the ready set",
                self.step_idx, step.role, step.until
            )),
        }
    }

    fn skip(&mut self) {
        self.step_idx += 1;
    }

    fn is_finished(&self) -> bool {
        self.step_idx >= self.steps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointId;
    use crate::policy::testing::hit;
    use crate::policy::testing::pool_hit;

    fn schedule() -> Vec<Step> {
        vec![
            Step::new(
                "victim",
                StopCondition::Checkpoint(CheckpointId::new("stat")),
            ),
            Step::new(
                "racer",
                StopCondition::Checkpoint(CheckpointId::new("symlink")),
            ),
            Step::new("victim", StopCondition::Exit),
        ]
    }

    #[test]
    fn releases_the_step_s_role_and_advances() {
        let mut p = FixedSchedule::new(schedule());
        let ready = vec![hit("racer", 1, "symlink", 1), hit("victim", 0, "stat", 2)];
        assert_eq!(p.decide(&ready), Decision::Release(1));
        assert_eq!(p.step_idx(), 1);
    }

    #[test]
    fn picks_the_step_s_role_even_when_several_roles_are_ready() {
        // Section 3.2's point: a fixed schedule is the degenerate case of a
        // choice over a ready set, not a different mechanism.
        let mut p = FixedSchedule::new(schedule());
        p.decide(&[hit("victim", 0, "stat", 1)]);
        let ready = vec![hit("victim", 0, "openat", 2), hit("racer", 1, "symlink", 3)];
        assert_eq!(p.decide(&ready), Decision::Release(1));
    }

    #[test]
    fn a_role_at_the_wrong_checkpoint_is_a_divergence() {
        let mut p = FixedSchedule::new(schedule());
        let d = p.decide(&[hit("victim", 0, "openat", 1)]);
        assert!(matches!(d, Decision::Divergence(_)));
        assert_eq!(p.step_idx(), 0, "a divergence must not advance the step");
    }

    #[test]
    fn exit_steps_match_only_the_reserved_exit_checkpoint() {
        let mut p = FixedSchedule::new(schedule());
        p.decide(&[hit("victim", 0, "stat", 1)]);
        p.decide(&[hit("racer", 1, "symlink", 2)]);
        assert!(matches!(
            p.decide(&[hit("victim", 0, "openat", 3)]),
            Decision::Divergence(_)
        ));
        assert_eq!(
            p.decide(&[hit("victim", 0, "exit", 4)]),
            Decision::Release(0)
        );
    }

    #[test]
    fn skip_advances_past_an_unsatisfiable_step() {
        let mut p = FixedSchedule::new(schedule());
        assert!(matches!(
            p.decide(&[hit("racer", 1, "symlink", 1)]),
            Decision::Divergence(_)
        ));
        p.skip();
        assert_eq!(
            p.decide(&[hit("racer", 1, "symlink", 1)]),
            Decision::Release(0)
        );
    }

    #[test]
    fn a_schedule_is_finished_only_once_every_step_is_enforced() {
        let mut p = FixedSchedule::new(schedule());
        assert!(!p.is_finished());
        p.decide(&[hit("victim", 0, "stat", 1)]);
        assert!(!p.is_finished());
        p.decide(&[hit("racer", 1, "symlink", 2)]);
        p.decide(&[hit("victim", 0, "exit", 3)]);
        assert!(p.is_finished());
    }

    #[test]
    fn an_exhausted_schedule_drains() {
        let mut p = FixedSchedule::new(vec![]);
        assert_eq!(p.decide(&[hit("victim", 0, "stat", 1)]), Decision::Drain);
    }

    #[test]
    fn pool_members_are_matched_by_their_disambiguated_name() {
        let mut p = FixedSchedule::new(vec![Step::new(
            "racer#1",
            StopCondition::Checkpoint(CheckpointId::new("symlink")),
        )]);
        let ready = vec![
            pool_hit("racer", 1, 0, "symlink", 1),
            pool_hit("racer", 1, 1, "symlink", 2),
        ];
        assert_eq!(p.decide(&ready), Decision::Release(1));
    }
}
