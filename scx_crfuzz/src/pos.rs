//! POS over SUT threads (spec §3.5): seeded per-event priorities, release the
//! max, redraw only the ready events whose keys (D3) conflict with it. Events
//! are named by creation-tree thread names (D4). Pure: no I/O, so the
//! determinism test runs off-target.

use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// `(thread, syscall, path, occurrence)`, the thread named by its place in
/// the creation tree, not its tid (D4). Ord is the canonical tie-break order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    pub thread: String,
    pub nr: i64,
    pub path: Option<PathBuf>,
    pub n: u32,
}

/// One conflict key (D3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    /// `(dev, ino)` of a directory walked or of the target.
    Ino(u64, u64),
    /// `(dev, ino)` of a parent directory and one name in it.
    Name(u64, u64, OsString),
}

/// What resolving an event's path(s) touches (D3). `reads` holds every key the
/// walk passed, `writes` (a subset) the names and objects a rebind changes.
#[derive(Debug, Clone, Default)]
pub struct Keys {
    pub reads: BTreeSet<Key>,
    pub writes: BTreeSet<Key>,
    /// What it touches is unknown (no path, or a syscall we can't decode):
    /// conflicts with everything (D3: when unsure, report a conflict).
    pub all: bool,
}

impl Keys {
    /// Ordering the two can change an outcome: one rebinds something the other
    /// resolves through.
    pub fn conflicts(&self, other: &Keys) -> bool {
        self.all
            || other.all
            || !self.writes.is_disjoint(&other.reads)
            || !other.writes.is_disjoint(&self.reads)
    }
}

pub struct Pos {
    seed: u64,
    /// Prior hits per `(thread, nr, path)` this run.
    seen: HashMap<(String, i64, Option<PathBuf>), u32>,
    /// Times each ready event's priority was redrawn.
    redraws: HashMap<EventId, u32>,
}

impl Pos {
    pub fn new(seed: u64) -> Self {
        Self { seed, seen: HashMap::new(), redraws: HashMap::new() }
    }

    /// Name a newly held event: call once per held syscall, as it arrives.
    pub fn id(&mut self, thread: &str, nr: i64, path: Option<PathBuf>) -> EventId {
        let n = self.seen.entry((thread.into(), nr, path.clone())).or_default();
        *n += 1;
        EventId { thread: thread.into(), nr, path, n: *n - 1 }
    }

    /// Priority from the seed and the event alone, never its ready-set position
    /// (L:Engine, arrival order).
    pub fn prio(&self, id: &EventId) -> u64 {
        self.hash(id, &self.redraws.get(id).copied().unwrap_or(0).to_le_bytes())
    }

    /// The mutator's seed at this event's hold: from the seed and the event
    /// alone, so a replay fires the same mutation (D6).
    pub fn event_seed(&self, id: &EventId) -> u64 {
        self.hash(id, &[])
    }

    fn hash(&self, id: &EventId, tail: &[u8]) -> u64 {
        let mut h = Fnv::new(self.seed);
        // Length-prefixed so (thread, path) splits can't collide.
        h.write(&(id.thread.len() as u64).to_le_bytes());
        h.write(id.thread.as_bytes());
        h.write(&id.nr.to_le_bytes());
        match &id.path {
            Some(p) => {
                h.write(&[1]);
                h.write(p.as_os_str().as_bytes());
            }
            None => h.write(&[0]),
        }
        h.write(&id.n.to_le_bytes());
        h.write(tail);
        splitmix(h.0)
    }

    /// Index of the event to release from `ready`, redrawing the priorities of
    /// the rest that conflict with it. Order of `ready` doesn't matter (D4).
    pub fn pick(&mut self, ready: &[(&EventId, &Keys)]) -> Option<usize> {
        let top = (0..ready.len()).max_by_key(|&i| (self.prio(ready[i].0), Reverse(ready[i].0)))?;
        for (id, _) in ready.iter().filter(|(id, k)| *id != ready[top].0 && k.conflicts(ready[top].1)) {
            *self.redraws.entry((*id).clone()).or_default() += 1;
        }
        self.redraws.remove(ready[top].0);
        Some(top)
    }
}

/// FNV-1a, seeded: a hash that stays fixed across Rust releases (std's
/// DefaultHasher doesn't promise that).
struct Fnv(u64);

impl Fnv {
    fn new(seed: u64) -> Self {
        let mut h = Fnv(0xcbf2_9ce4_8422_2325);
        h.write(&seed.to_le_bytes());
        h
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
    }
}

/// Spread FNV's weak low bits.
fn splitmix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: i64 = 1;
    const RENAME: i64 = 2;
    const STAT: i64 = 3;

    /// A scripted thread: the syscalls it hits, in order.
    type Script = Vec<(i64, &'static str, Keys)>;

    fn keys(reads: &[u64], writes: &[u64]) -> Keys {
        let k = |s: &[u64]| s.iter().map(|&i| Key::Ino(0, i)).collect::<BTreeSet<_>>();
        let mut r = k(reads);
        r.extend(k(writes));
        Keys { reads: r, writes: k(writes), all: false }
    }

    /// Stub engine: every thread parks at its next syscall, so each frontier is
    /// complete; a thread released runs to its next one. Events of a frontier
    /// are handed to POS in the order `arrival(k)` gives for decision `k`.
    fn run(seed: u64, threads: &[Script], arrival: impl Fn(usize, &mut Vec<usize>)) -> Vec<EventId> {
        let mut pos = Pos::new(seed);
        let mut next = vec![0; threads.len()];
        // held: (thread, id), in arrival order.
        let mut held: Vec<(usize, EventId)> = Vec::new();
        let mut log = Vec::new();
        for k in 0.. {
            let mut newly: Vec<usize> = (0..threads.len())
                .filter(|&t| next[t] < threads[t].len() && !held.iter().any(|h| h.0 == t))
                .collect();
            arrival(k, &mut newly);
            for t in newly {
                let (nr, p, _) = &threads[t][next[t]];
                held.push((t, pos.id(&t.to_string(), *nr, Some(p.into()))));
            }
            let ready: Vec<_> = held.iter().map(|(t, id)| (id, &threads[*t][next[*t]].2)).collect();
            let Some(i) = pos.pick(&ready) else { break };
            let (t, id) = held.remove(i);
            next[t] += 1;
            log.push(id);
        }
        log
    }

    /// Two threads open `/f` (occurrence assignment depends on arrival), one
    /// read-only and one creating it, and a stat of `/f` conflicts with only
    /// the creator; a rename of a directory two others walk.
    fn threads() -> Vec<Script> {
        vec![
            vec![(OPEN, "/f", keys(&[1, 2], &[])), (OPEN, "/d/x", keys(&[1, 3, 4], &[])), (OPEN, "/g", keys(&[1, 5], &[]))],
            vec![(OPEN, "/f", keys(&[1], &[2])), (RENAME, "/d", keys(&[1], &[3, 6])), (OPEN, "/f", keys(&[1, 2], &[]))],
            vec![(OPEN, "/h", keys(&[1, 7], &[])), (OPEN, "/d/y", keys(&[1, 3, 8], &[]))],
            vec![(STAT, "/f", keys(&[1, 2], &[]))],
        ]
    }

    /// Every permutation of `v`.
    fn perms(v: Vec<usize>) -> Vec<Vec<usize>> {
        if v.len() <= 1 {
            return vec![v];
        }
        let mut out = Vec::new();
        for i in 0..v.len() {
            let mut rest = v.clone();
            let x = rest.remove(i);
            for mut p in perms(rest) {
                p.insert(0, x);
                out.push(p);
            }
        }
        out
    }

    /// Spec §4 milestone 4: same seed ⇒ same sampled order, whatever order each
    /// frontier's events arrive in. Complete frontiers make that a total order,
    /// which implies the partial one.
    #[test]
    fn same_seed_same_order_across_arrival_permutations() {
        let ts = threads();
        let mut orders = BTreeSet::new();
        for seed in 0..32 {
            let base = run(seed, &ts, |_, _| {});
            assert_eq!(base.len(), 9);
            // Permute the first frontier exhaustively, later ones by a per-decision rotation.
            for p in perms(vec![0, 1, 2, 3]) {
                for rot in 0..4 {
                    let got = run(seed, &ts, |k, v| {
                        if k == 0 {
                            *v = p.clone();
                        } else if !v.is_empty() {
                            let r = (rot + k) % v.len();
                            v.rotate_left(r);
                        }
                    });
                    assert_eq!(got, base, "seed {seed}, first frontier {p:?}, rotation {rot}");
                }
            }
            orders.insert(base);
        }
        assert!(orders.len() > 1, "the seed never changed the order");
    }

    /// Random scripts over a small path pool, so threads often meet at one
    /// `(nr, path)`, with keys drawn per event: same-`(nr, path)` events with
    /// different keys (other flags, other cwd), which the fixed script lacks.
    #[test]
    fn same_seed_same_order_random_scripts() {
        let paths = ["/a", "/b", "/c"];
        for s in 0..300u64 {
            let mut r = s;
            let mut rand = |n: u64| {
                r = splitmix(r.wrapping_add(0x9e37_79b9_7f4a_7c15));
                r % n
            };
            let set = |rand: &mut dyn FnMut(u64) -> u64| (1..=6).filter(|_| rand(3) == 0).collect::<Vec<u64>>();
            let ts: Vec<Script> = (0..2 + rand(3))
                .map(|_| {
                    (0..1 + rand(4))
                        .map(|_| {
                            let (rd, wr) = (set(&mut rand), if rand(2) == 0 { set(&mut rand) } else { vec![] });
                            (if rand(4) == 0 { RENAME } else { OPEN }, paths[rand(3) as usize], keys(&rd, &wr))
                        })
                        .collect()
                })
                .collect();
            for seed in 0..4 {
                let base = run(seed, &ts, |_, _| {});
                for p in 1..5u64 {
                    // Shuffle every frontier's arrivals, differently per decision.
                    let got = run(seed, &ts, |k, v| {
                        let mut x = splitmix(p ^ (k as u64) << 8);
                        for i in (1..v.len()).rev() {
                            x = splitmix(x);
                            v.swap(i, (x % (i as u64 + 1)) as usize);
                        }
                    });
                    assert_eq!(got, base, "script {s}, seed {seed}, shuffle {p}: {ts:?}");
                }
            }
        }
    }

    #[test]
    fn redraw_only_conflicting() {
        let (a, b, c) = (keys(&[1, 3], &[]), keys(&[1], &[3]), keys(&[1, 9], &[]));
        assert!(a.conflicts(&b) && b.conflicts(&a));
        assert!(!a.conflicts(&c), "shared root is a read on both sides");
        assert!(!b.conflicts(&c));
        let unknown = Keys { all: true, ..Keys::default() };
        assert!(unknown.conflicts(&c) && c.conflicts(&unknown));

        let mut pos = Pos::new(7);
        let ids: Vec<EventId> = ["/a", "/b", "/c"].iter().map(|p| pos.id("0", OPEN, Some(p.into()))).collect();
        let before: Vec<u64> = ids.iter().map(|id| pos.prio(id)).collect();
        // Give the rebind to whichever event wins; one other walks what it renames.
        let top = (0..3).max_by_key(|&i| before[i]).unwrap();
        let k = |i| if i == top { &b } else if i == (top + 1) % 3 { &a } else { &c };
        let ready: Vec<_> = (0..3).map(|i| (&ids[i], k(i))).collect();
        assert_eq!(pos.pick(&ready), Some(top));
        let after: Vec<u64> = ids.iter().map(|id| pos.prio(id)).collect();
        for i in 0..3 {
            let redrawn = i != top && ready[i].1.conflicts(ready[top].1);
            assert_eq!(before[i] != after[i], redrawn, "event {i}");
        }
    }

    #[test]
    fn occurrence_counts_per_thread_syscall_and_path() {
        let mut pos = Pos::new(0);
        let p = || Some(PathBuf::from("/f"));
        assert_eq!(pos.id("0", OPEN, p()).n, 0);
        assert_eq!(pos.id("0", OPEN, p()).n, 1);
        assert_eq!(pos.id("0/0", OPEN, p()).n, 0, "per thread");
        assert_eq!(pos.id("0", RENAME, p()).n, 0);
        assert_eq!(pos.id("0", OPEN, None).n, 0);
    }
}
