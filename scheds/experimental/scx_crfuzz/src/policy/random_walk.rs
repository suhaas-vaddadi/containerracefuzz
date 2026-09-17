// SPDX-License-Identifier: GPL-2.0
//
// `RandomWalk` -- uniformly pick one member of the ready set
// (design doc section 3.4).
//
// The simplest possible policy: a baseline, and adequate for shallow bugs.
// Also the policy the throwaway counting run uses to estimate PCT's `k`.

use super::Decision;
use super::DecisionPolicy;
use super::ReadyCheckpointHit;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Uniform choice over the ready set, from a seeded stream.
///
/// ChaCha8 rather than `StdRng`: section 10.1 requires that the same seed
/// produce a byte-identical canonical log, and `StdRng`'s algorithm is
/// explicitly allowed to change between `rand` releases. A reproducer recorded
/// today has to still reproduce after a routine `cargo update`.
#[derive(Debug)]
pub struct RandomWalk {
    rng: ChaCha8Rng,
    decisions: u64,
}

impl RandomWalk {
    pub fn new(seed: u64) -> Self {
        RandomWalk {
            rng: ChaCha8Rng::seed_from_u64(seed),
            decisions: 0,
        }
    }

    /// How many decisions this policy has made.
    ///
    /// This is the quantity a counting run reports as PCT's `k` estimate
    /// (section 3.4).
    pub fn decision_count(&self) -> u64 {
        self.decisions
    }
}

impl DecisionPolicy for RandomWalk {
    fn name(&self) -> &'static str {
        "random_walk"
    }

    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision {
        debug_assert!(
            !ready.is_empty(),
            "engine must not decide on an empty ready set"
        );
        self.decisions += 1;
        Decision::Release(self.rng.gen_range(0..ready.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::testing::hit;

    fn ready(n: usize) -> Vec<ReadyCheckpointHit> {
        (0..n).map(|i| hit("r", i, "openat", i as u64)).collect()
    }

    fn run(seed: u64, rounds: usize) -> Vec<Decision> {
        let mut p = RandomWalk::new(seed);
        (0..rounds).map(|_| p.decide(&ready(4))).collect()
    }

    #[test]
    fn the_same_seed_produces_the_same_decision_sequence() {
        assert_eq!(run(7, 64), run(7, 64));
    }

    #[test]
    fn different_seeds_diverge() {
        assert_ne!(run(7, 64), run(8, 64));
    }

    #[test]
    fn decisions_stay_in_range_and_are_counted() {
        let mut p = RandomWalk::new(1);
        for n in 1..=8 {
            let d = p.decide(&ready(n));
            let Decision::Release(i) = d else {
                panic!("random walk must always release")
            };
            assert!(i < n);
        }
        assert_eq!(p.decision_count(), 8);
    }

    #[test]
    fn a_single_member_ready_set_releases_it() {
        let mut p = RandomWalk::new(99);
        assert_eq!(p.decide(&ready(1)), Decision::Release(0));
    }
}
