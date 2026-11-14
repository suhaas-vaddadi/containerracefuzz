//! What an event is called, so that the same event has the same name in
//! every run: its process's place in the creation tree, its syscall, its
//! path with the per-run parts taken out, and its occurrence. Pure: no I/O,
//! so it is tested off-target.

use std::path::{Path, PathBuf};

/// `(process, syscall, path, occurrence)`, the process named by its place in
/// the process creation tree, never by tid or OS thread (which differ every
/// run, Go's M:N threads above all). Ord is the canonical tie-break order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    pub process: String,
    pub nr: i64,
    /// `event_path()` of the path as issued.
    pub path: Option<PathBuf>,
    pub n: u32,
}

/// A held path as an event names it: the canary directory, which differs
/// every run, as `<canary>`, so a replay still matches.
pub fn event_path(p: &Path, canary: Option<&Path>) -> PathBuf {
    canary.and_then(|c| crate::schedule::uncanary(p, c)).unwrap_or_else(|| p.into())
}

/// FNV-1a, seeded: a hash that stays fixed across Rust releases (std's
/// DefaultHasher doesn't promise that).
pub(crate) struct Fnv(pub u64);

impl Fnv {
    pub fn new(seed: u64) -> Self {
        let mut h = Fnv(0xcbf2_9ce4_8422_2325);
        h.write(&seed.to_le_bytes());
        h
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
    }
}

/// Spread FNV's weak low bits.
pub(crate) fn splitmix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_path_names_the_canary() {
        let canary = Path::new("/var/lib/crfuzz/canary-4242-1");
        let e = |p: &str| event_path(Path::new(p), Some(canary));
        assert_eq!(e("/var/lib/crfuzz/canary-4242-1/dir"), Path::new("<canary>/dir"));
        // Another run's canary, a component-prefix lookalike, or no canary: as is.
        assert_eq!(e("/var/lib/crfuzz/canary-4242-10/x"), Path::new("/var/lib/crfuzz/canary-4242-10/x"));
        assert_eq!(e("/tmp/q"), Path::new("/tmp/q"));
        assert_eq!(event_path(Path::new("/var/lib/crfuzz/canary-4242-1/x"), None), Path::new("/var/lib/crfuzz/canary-4242-1/x"));
    }
}
