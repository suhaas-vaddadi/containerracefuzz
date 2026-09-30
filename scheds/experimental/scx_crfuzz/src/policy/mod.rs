// SPDX-License-Identifier: GPL-2.0
//
// The decision-policy abstraction (design doc section 3).
//
// This is the one seam the base design's `Enforcing` phase gives up:
// `step = schedule[step_idx]` is not a law of the engine, it is one possible
// answer to "what happens next", asked through an interface a second answer
// can also implement (section 3.1).
//
// Section 3.1 also explains why this is an interface inside one engine rather
// than a second binary: the moment discovery mode can have its own log format,
// "a found bug is automatically replayable" stops being a property of the
// engine and becomes a claim about a translation step -- which would itself
// need validating, reintroducing exactly the non-nameability risk this design
// exists to close.

mod fixed;
mod ordered_walk;

pub use fixed::FixedSchedule;
pub use ordered_walk::OrderedWalk;

use crate::backend::NotifyHandle;
use crate::checkpoint::CheckpointId;
use crate::role::RoleRef;
use std::path::PathBuf;

/// One role/checkpoint pair currently blocked and eligible to be released.
///
/// Section 3.2: this is the first place the design allows *more than one* role
/// to sit at a checkpoint simultaneously. The base design's fixed schedule is
/// the degenerate case where a correctly-authored schedule leaves the ready set
/// with exactly one matching member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyCheckpointHit {
    pub role: RoleRef,
    /// The role spelled the way the canonical log and `steps[]` spell it
    /// (`victim`, `racer#2`). Carried alongside `role` so a policy can match
    /// against a schedule without needing the role table.
    pub role_name: String,
    pub checkpoint: CheckpointId,
    pub handle: NotifyHandle,
    /// The path the held syscall resolved, when the backend captured it (see
    /// `BackendEvent::CheckpointHit::path`). The `DecisionPolicy` policies do
    /// not read it -- release ordering does not depend on the path -- but the
    /// attacker/oracle orchestration does, so it travels with the hit.
    pub path: Option<PathBuf>,
}

/// What a policy decided to do with the current ready set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Release `ready[index]`.
    Release(usize),
    /// Nothing in the ready set satisfies what this policy is waiting for.
    /// The engine applies the config's `on_divergence` policy.
    Divergence(String),
    /// This policy has nothing further to enforce; the engine moves to
    /// `Draining`. Only a finite schedule ever returns this.
    Drain,
}

/// How "which role gets released next" is answered.
///
/// The engine calls `decide` only with a non-empty ready set.
pub trait DecisionPolicy {
    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision;

    /// Advance past an unsatisfiable step, for `on_divergence: skip`.
    /// Meaningless for a policy with no notion of a current step.
    fn skip(&mut self) {}

    /// Whether this policy has nothing further it wants to enforce.
    ///
    /// Asked when the scenario ends, to tell "every role finished and the run
    /// is simply over" from "every role finished while the schedule still had
    /// steps left". A policy with no notion of being finished -- an algorithmic
    /// one, which would happily keep deciding for as long as roles keep
    /// arriving -- is finished whenever the scenario is, hence the default.
    fn is_finished(&self) -> bool {
        true
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::role::RoleId;

    /// Build a ready-set entry for a `one` role named `name`.
    pub fn hit(name: &str, role: usize, checkpoint: &str, handle: u64) -> ReadyCheckpointHit {
        ReadyCheckpointHit {
            role: RoleRef::one(RoleId(role)),
            role_name: name.to_string(),
            checkpoint: CheckpointId::new(checkpoint),
            handle: NotifyHandle(handle),
            path: None,
        }
    }

    /// Build a ready-set entry for pool member `member` of role `role`.
    pub fn pool_hit(
        name: &str,
        role: usize,
        member: u32,
        checkpoint: &str,
        handle: u64,
    ) -> ReadyCheckpointHit {
        ReadyCheckpointHit {
            role: RoleRef::pool_member(RoleId(role), member),
            role_name: format!("{name}#{member}"),
            checkpoint: CheckpointId::new(checkpoint),
            handle: NotifyHandle(handle),
            path: None,
        }
    }
}
