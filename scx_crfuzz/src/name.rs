//! What an event is called, so that the same event has the same name in
//! every run: its process's place in the creation tree, the code that issued
//! it (the callsite), its syscall, its path with the per-run parts taken
//! out, and its occurrence. Pure: no I/O, so it is tested off-target.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// `(process, callsite, syscall, path, occurrence)`, the process named by its
/// place in the process creation tree, never by tid or OS thread (which
/// differ every run, Go's M:N threads above all). Ord is the canonical
/// tie-break order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    pub process: String,
    /// `callsite()` of the issuing code.
    pub callsite: u64,
    pub nr: i64,
    /// `event_path()` of the path as issued.
    pub path: Option<PathBuf>,
    pub n: u32,
}

/// A held path as an event names it, without what differs from run to run
/// or from one campaign's directory to another's:
/// - the canary directory as `<canary>`, and its name as `<canary>` wherever
///   else it shows (a container rootfs's mirror of it);
/// - the i-th of `dirs` (the `--scope`, then the `--private` directories) as
///   `<dir{i}>`, so campaigns in different scenario directories name, and
///   seed, their events alike;
/// - random digit runs as `<n>`: an all-digit component (a pid) or a
///   component's trailing run of 6 or more digits (a temp-file suffix, Go's
///   `os.CreateTemp`).
/// Byte-wise, so the rest stays as issued (`x/` follows a symlink where `x`
/// doesn't).
pub fn event_path(p: &Path, canary: Option<&Path>, dirs: &[PathBuf]) -> PathBuf {
    let name = canary.and_then(Path::file_name).map(OsStr::as_bytes);
    let mut b = p.as_os_str().as_bytes().to_vec();
    let under = |b: &[u8], d: &Path| b.starts_with(d.as_os_str().as_bytes()) && matches!(b.get(d.as_os_str().len()), None | Some(b'/'));
    if let Some(c) = canary.filter(|&c| under(&b, c)) {
        b.splice(..c.as_os_str().len(), *b"<canary>");
    } else if let Some(i) = dirs.iter().position(|d| under(&b, d)) {
        b.splice(..dirs[i].as_os_str().len(), format!("<dir{i}>").into_bytes());
    }
    let parts: Vec<Vec<u8>> = b
        .split(|&c| c == b'/')
        .map(|c| {
            let k = c.iter().rev().take_while(|x| x.is_ascii_digit()).count();
            match Some(c) {
                n if n == name => b"<canary>".to_vec(),
                // ponytail: a CreateTemp suffix under 6 digits (p ≈ 2e-4)
                // stays unnormalized; lower it if measurement shows one.
                _ if k > 0 && k == c.len() || k >= 6 => [&c[..c.len() - k], b"<n>"].concat(),
                _ => c.to_vec(),
            }
        })
        .collect();
    OsString::from_vec(parts.join(&b'/')).into()
}

/// `/proc/<pid>/maps`, parsed once per event: its mappings in address order.
pub struct Maps(Vec<Map>);

pub struct Map {
    pub start: u64,
    pub end: u64,
    pub exec: bool,
    /// The file mapped and the mapping's offset in it; None: anonymous.
    file: Option<(String, u64)>,
}

impl Maps {
    pub fn parse(maps: &str) -> Self {
        let line = |l: &str| {
            let mut f = l.split_whitespace();
            let (start, end) = f.next()?.split_once('-')?;
            let (exec, off, inode) = (f.next()?.contains('x'), u64::from_str_radix(f.next()?, 16).ok()?, f.nth(1)?);
            let file = f.next().filter(|_| inode != "0").map(|file| (file.to_string(), off));
            Some(Map { start: u64::from_str_radix(start, 16).ok()?, end: u64::from_str_radix(end, 16).ok()?, exec, file })
        };
        Maps(maps.lines().filter_map(line).collect())
    }

    /// The mapping that holds `ip`.
    pub fn find(&self, ip: u64) -> Option<&Map> {
        self.0.get(self.0.partition_point(|m| m.end <= ip)).filter(|m| m.start <= ip)
    }
}

/// The code an event was issued from: a hash of its user stack `ips`
/// (innermost first) as `(file, file offset)` pairs, so a load base (ASLR,
/// PIE) doesn't change it; and how many frames went into it.
/// Stops at the first frame outside a file mapping. Names two events of one
/// process apart where its goroutines or threads don't (they differ every run).
pub fn callsite(ips: &[u64], maps: &Maps) -> (u64, u32) {
    let mapped = |ip: u64| {
        let m = maps.find(ip)?;
        m.file.as_ref().map(|(file, off)| (file, ip - m.start + off))
    };
    let (mut h, mut frames) = (Fnv::new(0), 0);
    for (file, off) in ips.iter().map_while(|&ip| mapped(ip)) {
        h.write(&(file.len() as u64).to_le_bytes());
        h.write(file.as_bytes());
        h.write(&off.to_le_bytes());
        frames += 1;
    }
    (splitmix(h.0), frames)
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
        let canary = Path::new("/var/lib/crfuzz/canary-4242-1");
        let dirs = [PathBuf::from("/var/tmp/run123456/rootfs"), PathBuf::from("/var/tmp/run123456")];
        let e = |p: &str| event_path(Path::new(p), Some(canary), &dirs);
        assert_eq!(e("/var/lib/crfuzz/canary-4242-1/dir"), Path::new("<canary>/dir"));
        // Its mirror in a container's rootfs: the name, as a component.
        assert_eq!(e("/r/rootfs/var/lib/crfuzz/canary-4242-1/dir"), Path::new("/r/rootfs/var/lib/crfuzz/<canary>/dir"));
        assert_eq!(e("/r/canary-4242-10"), Path::new("/r/canary-4242-10"));
        assert_eq!(event_path(Path::new("/var/lib/crfuzz/canary-4242-1/x"), None, &dirs), Path::new("/var/lib/crfuzz/canary-4242-1/x"));
        // The first directory that holds it, whole components only.
        assert_eq!(e("/var/tmp/run123456/rootfs/bin/sh"), Path::new("<dir0>/bin/sh"));
        assert_eq!(e("/var/tmp/run123456/rootfs"), Path::new("<dir0>"));
        assert_eq!(e("/var/tmp/run123456/state"), Path::new("<dir1>/state"));
        assert_eq!(e("/var/tmp/run123456/rootfs2/x"), Path::new("<dir1>/rootfs2/x"));
        assert_eq!(e("rootfs/bin/sh"), Path::new("rootfs/bin/sh"), "relative: as issued");
        assert_eq!(e("/tmp/q"), Path::new("/tmp/q"));
        assert_eq!(e("/var/lib/containerd/.fsverity-check-3141592653"), Path::new("/var/lib/containerd/.fsverity-check-<n>"));
        assert_eq!(e("/proc/4242/status"), Path::new("/proc/<n>/status"));
        assert_eq!(e("/run/runc/busy/state-123456"), Path::new("/run/runc/busy/state-<n>"));
        assert_eq!(e("/var/lib/crfuzz/canary-4242-1/dir/tmp-1234567"), Path::new("<canary>/dir/tmp-<n>"));
        assert_eq!(e("/tmp/x/").as_os_str(), "/tmp/x/", "a trailing slash is kept");
        for p in ["/usr/lib64/libc.so.6", "/tmp/a12345", "/etc/sha256sum"] {
            assert_eq!(e(p), Path::new(p));
        }
        for p in ["/proc/4242/status", "/var/tmp/run123456/rootfs/bin/sh", "/var/lib/crfuzz/canary-4242-1/dir"] {
            assert_eq!(e(e(p).to_str().unwrap()), e(p), "idempotent");
        }
    }

    #[test]
    fn callsite_survives_aslr_and_stops_at_unmapped() {
        let maps = |base: u64| {
            Maps::parse(&format!(
                "{:x}-{:x} r-xp 00001000 fd:00 42 /usr/bin/sut\n{:x}-{:x} rw-p 00000000 00:00 0 \n{:x}-{:x} r-xp 00000000 00:00 0 [vdso]\n",
                base,
                base + 0x10000,
                base + 0x10000,
                base + 0x20000,
                base + 0x20000,
                base + 0x21000
            ))
        };
        let (a, b) = (maps(0x5550_0000_0000), maps(0x7ff0_0000_0000));
        let at = |base: u64, offs: &[u64]| offs.iter().map(|o| base + o).collect::<Vec<_>>();
        let site = callsite(&at(0x5550_0000_0000, &[0x10, 0x20]), &a);
        assert_eq!(site.1, 2, "both frames");
        assert_eq!(site, callsite(&at(0x7ff0_0000_0000, &[0x10, 0x20]), &b), "same offsets, other load base");
        assert_ne!(site, callsite(&at(0x5550_0000_0000, &[0x10, 0x30]), &a), "another caller");
        assert_ne!(site, callsite(&at(0x5550_0000_0000, &[0x10]), &a), "a shallower stack");
        // Past an anonymous or vdso frame the rest is unwinder garbage.
        for junk in [0x10008, 0x20008, 0x9_0000_0000] {
            assert_eq!(site, callsite(&at(0x5550_0000_0000, &[0x10, 0x20, junk, 0x40]), &a), "{junk:x}");
        }
        assert_eq!(callsite(&[], &a), callsite(&at(0x5550_0000_0000, &[0x10008]), &a), "no stack");
        let m = a.find(0x5550_0000_0010).unwrap();
        assert!(m.exec && (m.start, m.end) == (0x5550_0000_0000, 0x5550_0001_0000));
        assert!(!a.find(0x5550_0001_0008).unwrap().exec && a.find(0x5550_0002_1000).is_none() && a.find(1).is_none());
    }
}
