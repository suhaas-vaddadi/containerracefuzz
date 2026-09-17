// SPDX-License-Identifier: GPL-2.0
//
// `PCT` -- probabilistic concurrency testing (design doc section 3.4).
//
// Assign each role a random priority at barrier time, place `d - 1` random
// priority-inversion points along a *logical* step index, and at each decision
// release the highest-priority ready member, demoting a role's priority when a
// scheduled inversion point is reached.
//
// Why a logical clock rather than wall-clock time: the base design rejected
// time-slice/duration-based preemption because wall-clock duration is a
// function of CPU speed, cache state and system load. The identical argument
// applies to indexing inversion points by time. Counting *decision events* --
// a quantity the engine itself produces deterministically -- removes the
// machine-specific timing dependency entirely.

use super::Decision;
use super::DecisionPolicy;
use super::ReadyCheckpointHit;
use crate::role::RoleId;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Pct {
    rng: ChaCha8Rng,
    /// Bug depth: the number of ordering constraints a bug is assumed to need.
    d: u32,
    /// Estimated total decision points in the run, used to place the inversion
    /// points. Supplied by the harness from a counting run (section 3.4); the
    /// engine does not estimate it.
    k: u64,
    /// Priority per role *declaration*.
    ///
    /// Keyed by `RoleId`, so every member of a pool shares its declaration's
    /// priority. Section 14-C flags this as genuinely unsettled: section 3.4
    /// says priorities are assigned "at barrier time", but section 5 says pool
    /// membership is not fixed at barrier time, and neither section says
    /// whether a late-arriving member inherits the pool's priority or draws its
    /// own. Sharing is the choice consistent with "at barrier time" -- a
    /// per-member draw would have to happen at first match, contradicting it --
    /// but it does mean PCT cannot currently order two racers within one pool
    /// against each other. Revisit once the doc resolves 14-C.
    priorities: HashMap<RoleId, i64>,
    /// Logical decision indices at which a demotion fires, ascending.
    inversion_points: Vec<u64>,
    /// Which demotion fires next.
    next_inversion: usize,
    /// The logical clock: decisions made so far.
    decisions: u64,
}

impl Pct {
    pub fn new(seed: u64, d: u32, k: u64) -> Self {
        Pct {
            rng: ChaCha8Rng::seed_from_u64(seed),
            d: d.max(1),
            k,
            priorities: HashMap::new(),
            inversion_points: Vec::new(),
            next_inversion: 0,
            decisions: 0,
        }
    }

    pub fn decision_count(&self) -> u64 {
        self.decisions
    }

    pub fn inversion_points(&self) -> &[u64] {
        &self.inversion_points
    }

    pub fn priority_of(&self, role: RoleId) -> Option<i64> {
        self.priorities.get(&role).copied()
    }

    /// A role not present at barrier time -- a pool member that arrived during
    /// `Enforcing`. It inherits its declaration's priority if the declaration
    /// has one, and otherwise sits at the bottom, below every barrier role, so
    /// a late arrival cannot silently outrank the actors the run was set up
    /// around.
    fn priority_for(&mut self, role: RoleId) -> i64 {
        *self.priorities.entry(role).or_insert(0)
    }
}

impl DecisionPolicy for Pct {
    fn name(&self) -> &'static str {
        "pct"
    }

    fn on_barrier(&mut self, roles: &[RoleId]) {
        // Priorities `d + 1 ..= d + n`, permuted: every barrier role outranks
        // every demoted priority (`1 ..= d - 1`) until it is itself demoted.
        let mut values: Vec<i64> = (0..roles.len())
            .map(|i| self.d as i64 + 1 + i as i64)
            .collect();
        values.shuffle(&mut self.rng);
        for (role, value) in roles.iter().zip(values) {
            self.priorities.insert(*role, value);
        }

        // `d - 1` inversion points over the logical decision index `1 ..= k`.
        // Sorted so they fire in order; duplicates are kept rather than
        // resampled, which simply means two demotions land on one decision.
        let count = self.d.saturating_sub(1) as usize;
        let mut points: Vec<u64> = if self.k == 0 {
            Vec::new()
        } else {
            (0..count).map(|_| self.rng.gen_range(1..=self.k)).collect()
        };
        points.sort_unstable();
        self.inversion_points = points;
        self.next_inversion = 0;
    }

    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision {
        debug_assert!(
            !ready.is_empty(),
            "engine must not decide on an empty ready set"
        );
        self.decisions += 1;

        // Highest priority wins; ties break on the canonically-smallest
        // `RoleRef` (declaration index, then pool member index), not on
        // ready-set position -- the same reasoning `OrderedWalk` applies to
        // target selection (design doc section 14-A). Ready-set position is
        // itself a function of real OS scheduling and is not reproducible
        // run to run, so a tie-break that depends on it is not either.
        let mut best = 0usize;
        let mut best_priority = self.priority_for(ready[0].role.role);
        for (i, h) in ready.iter().enumerate().skip(1) {
            let p = self.priority_for(h.role.role);
            if p > best_priority || (p == best_priority && h.role < ready[best].role) {
                best = i;
                best_priority = p;
            }
        }

        // If this decision is an inversion point, the role we just chose is
        // demoted -- taking effect from the next decision onwards, which is
        // what makes the inversion observable as a reordering rather than as a
        // no-op on this same choice.
        while self
            .inversion_points
            .get(self.next_inversion)
            .is_some_and(|p| *p == self.decisions)
        {
            let demoted = (self.d as i64 - 1 - self.next_inversion as i64).max(1);
            self.priorities.insert(ready[best].role.role, demoted);
            self.next_inversion += 1;
        }

        Decision::Release(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::testing::hit;
    use crate::policy::testing::pool_hit;

    fn roles(n: usize) -> Vec<RoleId> {
        (0..n).map(RoleId).collect()
    }

    fn ready3() -> Vec<ReadyCheckpointHit> {
        vec![
            hit("a", 0, "openat", 0),
            hit("b", 1, "stat", 1),
            hit("c", 2, "rename", 2),
        ]
    }

    fn run(seed: u64, d: u32, k: u64, rounds: usize) -> Vec<Decision> {
        let mut p = Pct::new(seed, d, k);
        p.on_barrier(&roles(3));
        (0..rounds).map(|_| p.decide(&ready3())).collect()
    }

    #[test]
    fn the_same_seed_produces_the_same_decision_sequence() {
        assert_eq!(run(5, 3, 50, 40), run(5, 3, 50, 40));
    }

    #[test]
    fn different_seeds_diverge() {
        assert_ne!(run(5, 3, 50, 40), run(6, 3, 50, 40));
    }

    #[test]
    fn barrier_assigns_every_role_a_distinct_priority_above_the_demotion_range() {
        let mut p = Pct::new(1, 3, 100);
        p.on_barrier(&roles(4));
        let mut got: Vec<i64> = roles(4)
            .iter()
            .map(|r| p.priority_of(*r).unwrap())
            .collect();
        got.sort_unstable();
        assert_eq!(got, vec![4, 5, 6, 7], "d + 1 ..= d + n");
        assert!(got.iter().all(|v| *v > p.d as i64 - 1));
    }

    #[test]
    fn places_d_minus_one_inversion_points_within_k() {
        let mut p = Pct::new(2, 4, 30);
        p.on_barrier(&roles(2));
        assert_eq!(p.inversion_points().len(), 3);
        assert!(p.inversion_points().iter().all(|i| (1..=30).contains(i)));
        assert!(p.inversion_points().windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn depth_one_places_no_inversion_points_and_never_reorders() {
        let mut p = Pct::new(3, 1, 100);
        p.on_barrier(&roles(3));
        assert!(p.inversion_points().is_empty());
        // With no demotions, the highest-priority role wins every time.
        let first = p.decide(&ready3());
        for _ in 0..20 {
            assert_eq!(p.decide(&ready3()), first);
        }
    }

    #[test]
    fn an_inversion_point_demotes_the_role_it_fires_on() {
        let mut p = Pct::new(4, 3, 100);
        p.on_barrier(&roles(3));
        // Force a known inversion at decision 1.
        p.inversion_points = vec![1];
        p.next_inversion = 0;

        let Decision::Release(i) = p.decide(&ready3()) else {
            panic!()
        };
        let demoted = ready3()[i].role.role;
        assert!(
            p.priority_of(demoted).unwrap() < p.d as i64,
            "demoted below every barrier priority"
        );
        // The next decision must therefore pick someone else.
        let Decision::Release(j) = p.decide(&ready3()) else {
            panic!()
        };
        assert_ne!(i, j);
    }

    #[test]
    fn ties_break_on_the_canonical_role_ref_ordering_not_ready_set_position() {
        // Two members of one pool share their declaration's priority
        // (section 14-C). The choice must be a function of role identity
        // (lowest member index), not of hash iteration order or of which
        // position in the ready set either one happened to arrive at.
        let mut p = Pct::new(5, 1, 10);
        p.on_barrier(&roles(1));
        let ready = vec![
            pool_hit("racer", 0, 0, "openat", 0),
            pool_hit("racer", 0, 1, "openat", 1),
        ];
        for _ in 0..20 {
            assert_eq!(p.decide(&ready), Decision::Release(0));
        }

        // Reversed arrival order -- must still pick member 0, now at
        // position 1, not whichever position arrived first.
        let reversed = vec![
            pool_hit("racer", 0, 1, "openat", 1),
            pool_hit("racer", 0, 0, "openat", 0),
        ];
        for _ in 0..20 {
            assert_eq!(p.decide(&reversed), Decision::Release(1));
        }
    }

    #[test]
    fn a_late_arriving_role_does_not_outrank_the_barrier_roles() {
        let mut p = Pct::new(6, 2, 100);
        p.on_barrier(&roles(2));
        let ready = vec![hit("a", 0, "openat", 0), hit("late", 9, "stat", 1)];
        let Decision::Release(i) = p.decide(&ready) else {
            panic!()
        };
        assert_eq!(i, 0, "the barrier role must win over an unranked newcomer");
    }

    #[test]
    fn k_of_zero_is_survivable() {
        let mut p = Pct::new(7, 3, 0);
        p.on_barrier(&roles(2));
        assert!(p.inversion_points().is_empty());
        assert!(matches!(
            p.decide(&[hit("a", 0, "openat", 0)]),
            Decision::Release(0)
        ));
    }
}
