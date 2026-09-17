// SPDX-License-Identifier: GPL-2.0
//
// `OrderedWalk` -- draw a target *role* before anything has run, and wait for
// it to become ready, rather than indexing into whatever the ready set
// happens to contain when `decide()` is called.
//
// This exists to close design doc section 14-A. `RandomWalk` indexes by
// position in the ready set (`gen_range(0..ready.len())`), and that position
// is set by real OS scheduling: arrival order, not the seed, decides which
// physical role a given draw releases. Measured directly against real
// processes, that arrival order is not reproducible -- see the crate docs,
// "Section 14-A is no longer open" -- so the same seed can release a
// different role on different runs of the same scenario.
//
// `OrderedWalk` draws a target `RoleId` from the seed alone, before anything
// has run and independent of anything that happens at runtime, and then
// searches the ready set for a match rather than indexing into it. Arrival
// order can only change *when* the target shows up, never *which* target was
// chosen. A target names a role, not a `(role, checkpoint)` pair: unlike
// `FixedSchedule`, discovery mode does not know in advance which checkpoint a
// role will actually reach next, so the policy releases whichever checkpoint
// the target role happens to be sitting at.
//
// Draws are made against the full declared role count -- including pool
// roles -- rather than only the `one`-cardinality roles handed to
// `on_barrier`, since a pool's *existence* (if not its membership) is fixed
// at config-parse time and so is available before any process has run. A
// target naming a pool role is satisfied by whichever member is ready; if
// several are, the canonically-smallest `RoleRef` wins (lowest member index),
// never whichever happened to arrive first.
//
// A `one`-cardinality role's identity is spent the moment its thread group
// exits: it can never again produce a ready hit. Left unhandled, a later
// draw can land back on that same `RoleId` -- observed directly, against
// real processes in the VM, running this policy against
// `scenarios/discovery.json`: the run released every checkpoint correctly
// and then hung for the full idle-round bound, because the *next* draw
// re-targeted a role that had already permanently exited. `exhausted`
// tracks this and excludes such roles from future draws. It is updated only
// when *this policy's own chosen target* is satisfied by that role's
// reserved `exit` hit -- never by scanning the rest of the ready set for
// exits belonging to some other, not-currently-targeted role. That
// restriction matters: which checkpoint an *untargeted* role happens to be
// sitting at, at the instant of some other decision, is exactly the kind of
// real-timing-dependent ready-set membership this policy exists to stay
// independent of (see `lib.rs`, section 14-A). Learning exhaustion only from
// a target this policy itself already committed to and already waited out
// keeps the target *sequence* a function of the seed and of which roles have
// been spent so far -- not of real-world timing.

use super::Decision;
use super::DecisionPolicy;
use super::ReadyCheckpointHit;
use crate::role::RoleId;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::HashSet;

/// Uniform choice over declared roles, made before the ready set is
/// consulted at all.
#[derive(Debug)]
pub struct OrderedWalk {
    rng: ChaCha8Rng,
    /// Total declared roles (`one` and `pool` alike), fixed at config-parse
    /// time. The universe a target is drawn from.
    role_count: usize,
    /// The role currently being waited on. Drawn fresh once the previous
    /// target is satisfied (`decide` returns `Release`) or abandoned
    /// (`skip`).
    current_target: Option<RoleId>,
    /// Decision *points*, not `decide()` calls: repeated calls while still
    /// waiting on the same target (the engine re-polls and re-enters
    /// `Enforcing` without a new draw) do not count again. This is the same
    /// quantity `RandomWalk::decision_count` reports for PCT's `k` estimate.
    decisions: u64,
    /// `one`-cardinality roles known to have permanently exited. See the
    /// module doc comment.
    exhausted: HashSet<RoleId>,
}

impl OrderedWalk {
    pub fn new(seed: u64, role_count: usize) -> Self {
        OrderedWalk {
            rng: ChaCha8Rng::seed_from_u64(seed),
            role_count: role_count.max(1),
            current_target: None,
            decisions: 0,
            exhausted: HashSet::new(),
        }
    }

    pub fn decision_count(&self) -> u64 {
        self.decisions
    }

    /// The role currently being waited on, if a target has been drawn.
    pub fn current_target(&self) -> Option<RoleId> {
        self.current_target
    }

    fn draw_target(&mut self) -> RoleId {
        RoleId(self.rng.gen_range(0..self.role_count))
    }

    /// Draw a target, retrying against roles already known exhausted.
    ///
    /// Bounded rather than looping until a live role is found: role counts
    /// at this tool's scale are small (design doc section 4.3: 2-4 declared
    /// roles), so a bounded number of retries makes landing on a live role
    /// overwhelmingly likely without risking a genuine infinite loop in the
    /// degenerate case where every declared role has exhausted. In that
    /// degenerate case there is nothing left to target at all regardless of
    /// how the draw is made, and the engine's own idle-round bound is the
    /// correct backstop, not a loop in the policy.
    fn draw_live_target(&mut self) -> RoleId {
        for _ in 0..self.role_count.saturating_mul(8).max(8) {
            let candidate = self.draw_target();
            if !self.exhausted.contains(&candidate) {
                return candidate;
            }
        }
        self.draw_target()
    }
}

impl DecisionPolicy for OrderedWalk {
    fn name(&self) -> &'static str {
        "ordered_walk"
    }

    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision {
        debug_assert!(
            !ready.is_empty(),
            "engine must not decide on an empty ready set"
        );
        if self.current_target.is_none() {
            self.current_target = Some(self.draw_live_target());
            self.decisions += 1;
        }
        let target = self.current_target.expect("just set above");

        // The canonically-smallest match wins a multi-member tie (a pool
        // target with more than one ready member), not the first one to
        // arrive -- the same reasoning `Pct`'s tie-break uses.
        let found = ready
            .iter()
            .enumerate()
            .filter(|(_, h)| h.role.role == target)
            .min_by_key(|(_, h)| h.role);

        match found {
            Some((i, hit)) => {
                // A `one` role's reserved exit hit (`member == None`;
                // `role.rs::claim` never assigns `member` for a `one` role)
                // retires it from future draws -- see the module doc
                // comment for why this is learned only here, not from the
                // rest of the ready set.
                if hit.checkpoint.is_exit() && hit.role.member.is_none() {
                    self.exhausted.insert(target);
                }
                self.current_target = None;
                Decision::Release(i)
            }
            None => Decision::Divergence(format!(
                "waiting for role {target:?} to reach a checkpoint"
            )),
        }
    }

    fn skip(&mut self) {
        // Give up on the current target -- it may belong to a role that has
        // already exited, or one that will never match anything this run --
        // and let the next `decide()` draw a fresh one.
        //
        // NOTE: under `on_divergence: skip`, a target that keeps missing
        // causes an immediate redraw-and-retry loop entirely within one
        // `Engine::advance()` call (no poll in between, since nothing in the
        // ready set changed). For the scenario scale this tool targets --
        // 2-4 declared roles (design doc section 4.3) -- that loop resolves
        // in a handful of iterations. It is not bounded for a config with a
        // large role count and a mostly-empty ready set; that is a known,
        // unaddressed edge rather than a design decision.
        self.current_target = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::testing::hit;
    use crate::policy::testing::pool_hit;

    #[test]
    fn the_same_seed_produces_the_same_decision_sequence() {
        let ready = vec![hit("victim", 0, "stat", 1), hit("racer", 1, "symlink", 2)];
        let run = |seed| {
            let mut p = OrderedWalk::new(seed, 2);
            (0..16).map(|_| p.decide(&ready)).collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7));
    }

    #[test]
    fn different_seeds_can_diverge() {
        let ready = vec![hit("victim", 0, "stat", 1), hit("racer", 1, "symlink", 2)];
        let run = |seed| {
            let mut p = OrderedWalk::new(seed, 2);
            (0..16).map(|_| p.decide(&ready)).collect::<Vec<_>>()
        };
        assert_ne!(run(7), run(8));
    }

    #[test]
    fn the_target_role_does_not_depend_on_arrival_order_in_the_ready_set() {
        // The regression case for section 14-A: the same seed must pick the
        // same *role*, whichever physical order the two roles happened to
        // arrive in the ready set.
        let forward = vec![hit("victim", 0, "stat", 1), hit("racer", 1, "symlink", 2)];
        let backward = vec![hit("racer", 1, "symlink", 2), hit("victim", 0, "stat", 1)];

        let mut a = OrderedWalk::new(7, 2);
        let mut b = OrderedWalk::new(7, 2);
        let Decision::Release(i) = a.decide(&forward) else {
            panic!("expected a release")
        };
        let Decision::Release(j) = b.decide(&backward) else {
            panic!("expected a release")
        };
        assert_eq!(
            forward[i].role_name, backward[j].role_name,
            "same seed must release the same role regardless of ready-set order"
        );
    }

    #[test]
    fn decide_waits_for_the_drawn_target_rather_than_matching_whatever_is_ready() {
        let mut p = OrderedWalk::new(1, 3);
        // Role 99 is outside the declared role count, so no target this
        // policy could ever draw (0..3) matches it -- the ready set is
        // guaranteed to never satisfy whichever target got drawn.
        let ready = vec![hit("mystery", 99, "openat", 1)];
        let d1 = p.decide(&ready);
        assert!(matches!(d1, Decision::Divergence(_)));
        // Repeated calls against the same unsatisfied target must not redraw
        // or otherwise change the answer.
        let d2 = p.decide(&ready);
        assert_eq!(d1, d2);
    }

    #[test]
    fn skip_clears_the_target_so_a_fresh_one_is_drawn() {
        let mut p = OrderedWalk::new(2, 3);
        let ready = vec![hit("mystery", 99, "openat", 1)];
        p.decide(&ready);
        assert!(p.current_target().is_some());
        p.skip();
        assert!(p.current_target().is_none());
    }

    #[test]
    fn pool_matches_pick_the_canonically_smallest_member_regardless_of_order() {
        let mut p = OrderedWalk::new(9, 1);
        p.current_target = Some(RoleId(0));
        let ready = vec![
            pool_hit("racer", 0, 1, "openat", 1),
            pool_hit("racer", 0, 0, "openat", 2),
        ];
        let Decision::Release(i) = p.decide(&ready) else {
            panic!("expected a release")
        };
        assert_eq!(
            ready[i].role_name, "racer#0",
            "lowest member index wins, not arrival position"
        );
    }

    #[test]
    fn a_one_role_s_exit_retires_it_from_future_draws() {
        // Regression test for a hang observed running this policy against
        // real processes in the VM (`scenarios/discovery.json`): every
        // checkpoint released correctly, then the run hung for the full
        // idle-round bound because the next draw re-targeted `victim`
        // (RoleId(0), `one`-cardinality) after it had already exited.
        let mut p = OrderedWalk::new(1, 2);
        p.current_target = Some(RoleId(0));

        // The one-role's reserved exit hit satisfies the current target and
        // must retire RoleId(0).
        let exit_ready = vec![hit("victim", 0, "exit", 1)];
        assert_eq!(p.decide(&exit_ready), Decision::Release(0));
        assert!(p.current_target().is_none());

        // Force the next draw to land on the now-exhausted role by shrinking
        // the live universe to just it -- `draw_live_target` must refuse and
        // fall through its retry budget rather than getting stuck forever,
        // and a *real* second role must still be pickable.
        p.current_target = None;
        let target = p.draw_live_target();
        assert_ne!(
            target,
            RoleId(0),
            "an exhausted role must not be re-drawn while a live one exists"
        );
    }

    #[test]
    fn a_pool_role_s_member_exit_does_not_retire_the_pool() {
        // A pool is open-ended (design doc section 5): one member exiting
        // must not stop the pool's `RoleId` from being drawn again -- more
        // members can still arrive.
        let mut p = OrderedWalk::new(1, 2);
        p.current_target = Some(RoleId(1));
        let ready = vec![pool_hit("racer", 1, 0, "exit", 1)];
        p.decide(&ready);
        assert!(
            !p.exhausted.contains(&RoleId(1)),
            "a pool member's own exit must not exhaust the pool's RoleId"
        );
    }

    #[test]
    fn decision_count_only_advances_on_a_new_draw() {
        let mut p = OrderedWalk::new(3, 3);
        let ready = vec![hit("mystery", 99, "openat", 1)];
        p.decide(&ready);
        p.decide(&ready);
        p.decide(&ready);
        assert_eq!(p.decision_count(), 1, "still waiting on the first target");
        p.skip();
        p.decide(&ready);
        assert_eq!(p.decision_count(), 2, "skip caused a fresh draw");
    }
}
