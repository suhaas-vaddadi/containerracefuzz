// SPDX-License-Identifier: GPL-2.0
//
// `Pos` -- POS (Partial Order Aware Concurrency Sampling, Yuan et al., CAV 2018)
// as a `DecisionPolicy`.
//
// Plan: `docs/superpowers/plans/2026-10-01-crfuzz-pos-policy.md`, section 4
// Phase 3. Mapping in section 1:
//
//   1. assign each ready event a random priority;
//   2. release the enabled event with the highest priority;
//   3. redraw the priorities of the still-ready events that *conflict* with the
//      one just released (Algorithm 4, lines 14-18).
//
// Two properties matter and are what the tests pin:
//
// - **Priority is keyed from the seed, never a sequential draw.** An event's
//   priority is a stable hash of `(seed, event_id)`, so independent events
//   cannot perturb each other's priorities and the same event gets the same
//   priority however the ready set is permuted. A sequential RNG would make
//   every decision depend on how many draws happened before it.
// - **Only conflicts redraw.** `keyed` from the seed plus redraw on conflict
//   gives POS's partial-order sampling; touching an unrelated event's priority
//   would make independent events interact, which is exactly what POS exists to
//   avoid.
//
// No pid, handle or wall clock is ever read: like every `DecisionPolicy`, this
// sees only roles, role names, checkpoints, paths and conflict keys.
//
// `skip` clears nothing -- POS has no current target, so a divergence is simply
// "nothing to release yet" and is re-asked once the ready set changes.
// `is_finished` stays the trait default (`true`).

use super::Decision;
use super::DecisionPolicy;
use super::ReadyCheckpointHit;
use crate::event::keys_conflict;
use crate::event::EventId;
use std::collections::HashMap;

/// POS over the ready set.
#[derive(Debug)]
pub struct PosPolicy {
    seed: u64,
    /// Event -> current priority.
    priority: HashMap<EventId, u32>,
    /// How many times each event's priority has been redrawn. Part of the
    /// redraw key, so repeated redraws keep sampling rather than saturating.
    redraws: HashMap<EventId, u32>,
    /// Decision points, for the same measurement purpose as the other policies.
    decisions: u64,
    /// Ready sets seen with no conflicting pair: the logging-only
    /// conflict-scope diagnostic (plan Phase 4). Pruning on this is not
    /// enforcing yet.
    isolated_decisions: u64,
}

impl PosPolicy {
    pub fn new(seed: u64) -> Self {
        PosPolicy {
            seed,
            priority: HashMap::new(),
            redraws: HashMap::new(),
            decisions: 0,
            isolated_decisions: 0,
        }
    }

    pub fn decision_count(&self) -> u64 {
        self.decisions
    }

    /// Ready sets with no conflicting pair, since the policy started.
    pub fn isolated_decisions(&self) -> u64 {
        self.isolated_decisions
    }

    /// The current priority of every event seen so far. Exposed for the purity
    /// test.
    pub fn priorities(&self) -> &HashMap<EventId, u32> {
        &self.priority
    }

    /// Total number of conflict redraws performed.
    pub fn redraw_count(&self) -> u64 {
        self.redraws.values().map(|n| *n as u64).sum()
    }

    fn ensure_priority(&mut self, hit: &ReadyCheckpointHit) {
        if !self.priority.contains_key(&hit.event) {
            let p = keyed_priority(self.seed, &hit.event);
            self.priority.insert(hit.event.clone(), p);
        }
    }
}

impl DecisionPolicy for PosPolicy {
    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision {
        debug_assert!(
            !ready.is_empty(),
            "engine must not decide on an empty ready set"
        );
        for hit in ready {
            self.ensure_priority(hit);
        }

        // Argmax priority; ties broken by canonical `EventId` order so the
        // choice does not depend on ready-set order.
        let mut best = 0usize;
        for i in 1..ready.len() {
            let pi = self.priority[&ready[i].event];
            let pb = self.priority[&ready[best].event];
            if pi > pb || (pi == pb && ready[i].event < ready[best].event) {
                best = i;
            }
        }

        let released_event = ready[best].event.clone();
        let released_keys = ready[best].keys.clone();
        for (i, hit) in ready.iter().enumerate() {
            if i == best {
                continue;
            }
            if keys_conflict(&released_keys, &hit.keys) {
                let count = {
                    let c = self.redraws.entry(hit.event.clone()).or_insert(0);
                    *c += 1;
                    *c
                };
                let p = redraw_priority(self.seed, &released_event, &hit.event, count);
                self.priority.insert(hit.event.clone(), p);
            }
        }

        // Logging-only conflict-scope diagnostic (plan Phase 4): a ready set
        // with no conflicting pair adds no new partial orders. Never prunes.
        if ready.len() > 1
            && !(0..ready.len()).any(|i| {
                (i + 1..ready.len()).any(|j| keys_conflict(&ready[i].keys, &ready[j].keys))
            })
        {
            self.isolated_decisions += 1;
            log::debug!(
                "pos: {} ready event(s) with no conflicting pair -- isolated sampling",
                ready.len()
            );
        }

        self.decisions += 1;
        Decision::Release(best)
    }
}

// ---------------------------------------------------------------------------
// Stable keyed priority
// ---------------------------------------------------------------------------

/// FNV-1a over the encoded `(seed, event)`. A fixed, dependency-free hash, so
/// the same event gets the same priority on every build and every run -- a
/// `std` `DefaultHasher` is not guaranteed stable across versions, which would
/// break replay-by-seed.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn mix_to_priority(h: u64) -> u32 {
    (h ^ (h >> 32)) as u32
}

/// A canonical byte encoding of an event id. Written by hand rather than via
/// `serde` so the priority does not change if a later field is added.
fn encode_event(e: &EventId, out: &mut Vec<u8>) {
    out.extend_from_slice(&(e.actor.role.role.0 as u64).to_le_bytes());
    match e.actor.role.member {
        Some(m) => {
            out.push(1);
            out.extend_from_slice(&m.to_le_bytes());
        }
        None => out.push(0),
    }
    match &e.actor.thread {
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&(t.0.len() as u32).to_le_bytes());
            for n in &t.0 {
                out.extend_from_slice(&n.to_le_bytes());
            }
        }
        None => out.push(0),
    }
    let cp = e.checkpoint.as_str().as_bytes();
    out.extend_from_slice(&(cp.len() as u32).to_le_bytes());
    out.extend_from_slice(cp);
    out.extend_from_slice(&e.occurrence.to_le_bytes());
}

fn keyed_priority(seed: u64, event: &EventId) -> u32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&seed.to_le_bytes());
    encode_event(event, &mut buf);
    mix_to_priority(fnv1a(&buf))
}

fn redraw_priority(seed: u64, released: &EventId, event: &EventId, count: u32) -> u32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&seed.to_le_bytes());
    encode_event(released, &mut buf);
    encode_event(event, &mut buf);
    buf.extend_from_slice(&count.to_le_bytes());
    mix_to_priority(fnv1a(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ConflictKey;
    use crate::event::Direction;
    use crate::policy::testing::file_key;
    use crate::policy::testing::hit_full;

    fn shared_ready() -> Vec<ReadyCheckpointHit> {
        vec![
            hit_full(
                "victim",
                0,
                "openat",
                1,
                0,
                vec![file_key(1, "p", Direction::Rebind)],
            ),
            hit_full(
                "racer",
                1,
                "renameat2",
                2,
                0,
                vec![file_key(1, "p", Direction::Rebind)],
            ),
        ]
    }

    #[test]
    fn the_same_seed_and_ready_snapshots_give_the_same_decisions_and_priorities() {
        // Purity: `decide` is a function of `(seed, ready-set sequence)`. The
        // final priority map is compared too, because POS's redraw state is
        // what compounds across decisions.
        let ready = shared_ready();
        let run = |seed| {
            let mut p = PosPolicy::new(seed);
            let seq = vec![p.decide(&ready), p.decide(&ready)];
            (seq, p.priorities().clone())
        };
        assert_eq!(run(7), run(7));
    }

    #[test]
    fn different_seeds_can_diverge() {
        let ready = shared_ready();
        let run = |seed| {
            let mut p = PosPolicy::new(seed);
            p.decide(&ready)
        };
        let seeds: Vec<crate::policy::Decision> = (0..32).map(run).collect();
        assert!(
            seeds.windows(2).any(|w| w[0] != w[1]),
            "32 seeds chose the same event; POS is not sampling"
        );
    }

    #[test]
    fn only_conflicting_ready_events_are_redrawn() {
        let mut shared = PosPolicy::new(1);
        shared.decide(&shared_ready());
        assert_eq!(
            shared.redraw_count(),
            1,
            "the non-released event on the same key must be redrawn"
        );

        let disjoint = vec![
            hit_full(
                "victim",
                0,
                "openat",
                1,
                0,
                vec![file_key(1, "p", Direction::Rebind)],
            ),
            hit_full(
                "racer",
                1,
                "openat",
                2,
                0,
                vec![file_key(2, "q", Direction::Rebind)],
            ),
        ];
        let mut p = PosPolicy::new(1);
        p.decide(&disjoint);
        assert_eq!(p.redraw_count(), 0, "disjoint keys must not redraw");
    }

    #[test]
    fn adding_an_unrelated_ready_event_does_not_change_a_conflicting_pair() {
        // The relative release order of the conflicting pair must not depend on
        // an unrelated event being ready. Simulates the engine: release, drop,
        // decide again. The unrelated event may go first, but it never changes
        // which of the pair goes before the other.
        let pair_order = |with_c: bool| {
            let mut ready = shared_ready();
            if with_c {
                ready.push(hit_full(
                    "other",
                    2,
                    "openat",
                    3,
                    0,
                    vec![file_key(9, "z", Direction::Resolve)],
                ));
            }
            let mut p = PosPolicy::new(5);
            let mut order = Vec::new();
            while !ready.is_empty() {
                let Decision::Release(i) = p.decide(&ready) else {
                    panic!("pos must release")
                };
                order.push(ready.remove(i).role_name);
            }
            order.retain(|n| n != "other");
            order
        };
        assert_eq!(pair_order(false), pair_order(true));
    }

    #[test]
    fn a_resolve_never_conflicts_with_a_resolve() {
        // Both resolves on the same object: independent, so no redraw.
        let ready = vec![
            hit_full(
                "a",
                0,
                "newfstatat",
                1,
                0,
                vec![file_key(1, "p", Direction::Resolve)],
            ),
            hit_full(
                "b",
                1,
                "newfstatat",
                2,
                0,
                vec![file_key(1, "p", Direction::Resolve)],
            ),
        ];
        let mut p = PosPolicy::new(1);
        p.decide(&ready);
        assert_eq!(p.redraw_count(), 0);
    }

    /// A resolution chain token, anchor `(10,1)`, for the ancestor tests.
    fn chain_key(items: &[(&str, u64)], dir: Direction) -> ConflictKey {
        use crate::event::ComponentKey;
        use crate::event::FileToken;
        let mut parent = (10, 1);
        let chain = items
            .iter()
            .map(|(name, ino)| {
                let c = ComponentKey {
                    name: name.as_bytes().to_vec(),
                    parent,
                    obj: Some((10, *ino)),
                };
                parent = (10, *ino);
                c
            })
            .collect();
        ConflictKey::file(FileToken::new(10, 1, chain), dir)
    }

    #[test]
    fn an_ancestor_prefix_rebind_is_a_conflict() {
        // Victim resolves `/a/b/file`; attacker symlink-swaps `/a/b`. POS must
        // re-sample the victim, which leaf-only keying could not do.
        let ready = vec![
            hit_full(
                "victim",
                0,
                "newfstatat",
                1,
                0,
                vec![chain_key(
                    &[("a", 2), ("b", 3), ("file", 4)],
                    Direction::Resolve,
                )],
            ),
            hit_full(
                "attacker",
                1,
                "symlinkat",
                2,
                0,
                vec![chain_key(&[("a", 2), ("b", 3)], Direction::Rebind)],
            ),
        ];
        let mut p = PosPolicy::new(1);
        p.decide(&ready);
        assert_eq!(
            p.redraw_count(),
            1,
            "the deeper victim path must be redrawn"
        );
    }

    #[test]
    fn a_sibling_rebind_is_not_a_conflict() {
        let ready = vec![
            hit_full(
                "victim",
                0,
                "newfstatat",
                1,
                0,
                vec![chain_key(
                    &[("a", 2), ("b", 3), ("file", 4)],
                    Direction::Resolve,
                )],
            ),
            hit_full(
                "attacker",
                1,
                "symlinkat",
                2,
                0,
                vec![chain_key(
                    &[("a", 2), ("b", 3), ("other", 9)],
                    Direction::Rebind,
                )],
            ),
        ];
        let mut p = PosPolicy::new(1);
        p.decide(&ready);
        assert_eq!(p.redraw_count(), 0, "a sibling is independent");
    }

    #[test]
    fn the_encoding_length_prefixes_the_thread_path() {
        use crate::checkpoint::CheckpointId;
        use crate::event::ActorId;
        use crate::event::ThreadPath;
        use crate::role::RoleId;
        use crate::role::RoleRef;
        let enc = |path: &[u32]| {
            let actor = ActorId {
                role: RoleRef::one(RoleId(0)),
                thread: Some(ThreadPath(path.to_vec())),
            };
            let mut out = Vec::new();
            encode_event(
                &EventId::new(actor, CheckpointId::new("openat"), 0),
                &mut out,
            );
            out
        };
        assert_ne!(enc(&[0, 1]), enc(&[1]));
        assert_ne!(enc(&[0, 1]), enc(&[0]));
        // Nor across a redraw key's two concatenated encodings.
        assert_ne!(
            [enc(&[0, 1]), enc(&[1])].concat(),
            [enc(&[0]), enc(&[1, 1])].concat()
        );
    }

    #[test]
    fn it_always_releases_a_member_of_the_ready_set() {
        let ready = shared_ready();
        let mut p = PosPolicy::new(3);
        for _ in 0..16 {
            match p.decide(&ready) {
                Decision::Release(i) => assert!(i < ready.len()),
                other => panic!("pos must release, got {other:?}"),
            }
        }
    }
}
