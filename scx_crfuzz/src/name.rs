//! What an event is called, so that the same event has the same name in
//! every run: its thread's place in the creation tree, its syscall, its path
//! with the per-run parts taken out, and its occurrence. Pure: no I/O, so it
//! is tested off-target.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// `(thread, syscall, path, occurrence)`, the thread named by its place in
/// the creation tree, not its tid (which differs every run). Ord is the
/// canonical tie-break order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    pub thread: String,
    pub nr: i64,
    /// `event_path()` of the path as issued.
    pub path: Option<PathBuf>,
    pub n: u32,
}

/// A held path as an event names it: the canary directory as `<canary>`, the
/// run cgroup's name (`run-<pid>-<epoch>`) as `<run>`. Both differ every run,
/// so a replay still matches. A component, not a prefix: runc opens cgroup
/// files relative to /sys/fs/cgroup.
pub fn event_path(p: &Path, canary: Option<&Path>, run: &Path) -> PathBuf {
    if let Some(p) = canary.and_then(|c| crate::schedule::uncanary(p, c)) {
        return p;
    }
    let run = run.file_name();
    if !p.components().any(|c| Some(c.as_os_str()) == run) {
        return p.into();
    }
    p.components().map(|c| if Some(c.as_os_str()) == run { OsStr::new("<run>") } else { c.as_os_str() }).collect()
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
    fn event_path_names_per_run_dirs() {
        let (canary, run) = (Path::new("/var/lib/crfuzz/canary-4242-1"), Path::new("/sys/fs/cgroup/crfuzz/run-4242-2"));
        let e = |p: &str| event_path(Path::new(p), Some(canary), run);
        assert_eq!(e("/var/lib/crfuzz/canary-4242-1/dir"), Path::new("<canary>/dir"));
        assert_eq!(e("/sys/fs/cgroup/crfuzz/run-4242-2/sut/cpu.max"), Path::new("/sys/fs/cgroup/crfuzz/<run>/sut/cpu.max"));
        assert_eq!(e("crfuzz/run-4242-2/busy/cgroup.freeze"), Path::new("crfuzz/<run>/busy/cgroup.freeze"));
        // Another run's cgroup, or a component-prefix lookalike: as is.
        assert_eq!(e("/sys/fs/cgroup/crfuzz/run-4242-20/sut/cpu.max"), Path::new("/sys/fs/cgroup/crfuzz/run-4242-20/sut/cpu.max"));
        assert_eq!(e("/tmp/q"), Path::new("/tmp/q"));
        assert_eq!(event_path(Path::new("/var/lib/crfuzz/canary-4242-1/x"), None, run), Path::new("/var/lib/crfuzz/canary-4242-1/x"));
    }
}
