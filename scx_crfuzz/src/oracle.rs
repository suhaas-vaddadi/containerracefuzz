//! The oracle (spec §3.7, M6): a canary directory alice cannot reach, the
//! attacker identity, and the outcome class. A run is a `Violation` iff alice
//! can reach or has changed a canary afterwards: the mutator acts with at most
//! her privileges, so anything past them went through the SUT.

use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CString, OsString};
use std::fs::{self, DirBuilder, File, Permissions};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

const ROOT: &str = "/var/lib/crfuzz";

/// What the write half compares, with `Entry::id`: everything but times.
#[derive(Debug, PartialEq)]
pub struct State {
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    rdev: u64,
    body: Body,
}

#[derive(Debug, PartialEq)]
enum Body {
    Bytes(Vec<u8>),
    Target(PathBuf),
    Other,
}

pub struct Entry {
    /// For reachability (§5): a canary `(dev, ino)` seen anywhere alice can
    /// reach. Also compared: a bind mount from the same filesystem keeps `dev`.
    pub id: (u64, u64),
    pub state: State,
}

/// Keyed by path relative to the canary directory; "" is the gate itself.
pub type Tree = BTreeMap<PathBuf, Entry>;

/// Removes itself on drop unless `keep()` was called (§10.2).
pub struct Canary {
    pub dir: PathBuf,
    pub token: String,
    pub before: Tree,
    keep: bool,
}

impl Canary {
    /// A fresh canary for run `run` of this crfuzz, outside any rootfs, its
    /// top directory `root:root 0700` (the gate). Needs root.
    pub fn create(run: u32) -> Result<Self> {
        ensure!(unsafe { libc::geteuid() } == 0, "the canary must be root's");
        match DirBuilder::new().mode(0o755).create(ROOT) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e).context(ROOT),
            _ => {}
        }
        // A parent alice can write lets her swap the gate itself.
        for a in Path::new(ROOT).ancestors() {
            let m = fs::symlink_metadata(a)?;
            ensure!(m.uid() == 0 && m.mode() & 0o022 == 0 && !m.file_type().is_symlink(), "{} is not root-only", a.display());
        }
        let mut raw = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut raw)?;
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let dir = Path::new(ROOT).join(format!("canary-{}-{run}", std::process::id()));
        // The gate, closed before any entry exists. Fails if it exists: never reuse a stale one.
        DirBuilder::new().mode(0o700).create(&dir).with_context(|| dir.display().to_string())?;
        // Owned from here: a failure below removes the half-built canary.
        let mut c = Canary { dir, token, before: Tree::new(), keep: false };
        let (dir, token) = (&c.dir, &c.token);

        let at = |p: &str| dir.join(p);
        // Explicit chmod after create: creation modes are masked by the umask.
        let chmod = |p: &str, mode: u32| fs::set_permissions(at(p), Permissions::from_mode(mode));
        let file = |p: &str, mode: u32| -> Result<()> {
            fs::write(at(p), format!("{token} {p}\n"))?;
            Ok(chmod(p, mode)?)
        };
        let mkdir = |p: &str, mode: u32| -> Result<()> {
            fs::create_dir(at(p))?;
            Ok(chmod(p, mode)?)
        };
        let node = |p: &str, mode: u32, dev: libc::dev_t| -> Result<()> {
            let c = CString::new(at(p).as_os_str().as_bytes())?;
            ensure!(unsafe { libc::mknod(c.as_ptr(), mode, dev) } == 0, "mknod {p}: {}", std::io::Error::last_os_error());
            Ok(chmod(p, mode & 0o7777)?)
        };
        file("file", 0o644)?;
        file("exec", 0o755)?;
        file("suid", 0o4755)?;
        fs::hard_link(at("file"), at("hard"))?;
        symlink("file", at("link"))?;
        symlink(at("file"), at("abslink"))?;
        symlink(at("missing"), at("dangling"))?;
        mkdir("dir", 0o755)?;
        file("dir/file", 0o644)?;
        mkdir("dir/sub", 0o755)?;
        file("dir/sub/file", 0o644)?;
        mkdir("empty", 0o755)?;
        mkdir("sticky", 0o1777)?;
        node("fifo", libc::S_IFIFO | 0o644, 0)?;
        node("null", libc::S_IFCHR | 0o666, libc::makedev(1, 3))?;
        // Bound then closed: the socket file stays, nothing listens.
        drop(UnixListener::bind(at("sock"))?);
        chmod("sock", 0o755)?;

        c.before = c.snapshot()?;
        Ok(c)
    }

    pub fn snapshot(&self) -> Result<Tree> {
        let mut tree = Tree::new();
        // The gate's dev at creation: a mount over the gate itself is not walked.
        let dev = match self.before.get(Path::new("")) {
            Some(e) => e.id.0,
            None => fs::symlink_metadata(&self.dir)?.dev(),
        };
        walk(&self.dir, Path::new(""), dev, &self.before, &mut tree)?;
        Ok(tree)
    }

    /// `(dev, ino)` → entry, for reachability. `hard` shares `file`'s inode:
    /// the first name wins, so it is reported as `file`.
    pub fn ids(&self) -> HashMap<(u64, u64), PathBuf> {
        let mut ids = HashMap::new();
        for (k, e) in &self.before {
            ids.entry(e.id).or_insert_with(|| k.clone());
        }
        ids
    }

    /// The write half, once the SUT is gone. A gate that can't be re-read
    /// (removed, replaced) differs at every key.
    pub fn changed(&self) -> Vec<Finding> {
        let now = self.snapshot().unwrap_or_default();
        let keys: BTreeSet<&PathBuf> = self.before.keys().chain(now.keys()).collect();
        keys.into_iter()
            .filter(|k| self.before.get(*k).map(|e| (e.id, &e.state)) != now.get(*k).map(|e| (e.id, &e.state)))
            .map(|k| Finding::Changed { entry: k.clone() })
            .collect()
    }

    /// Leave the directory in place: for a Violation, or a baseline with
    /// findings, it is the evidence.
    pub fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for Canary {
    fn drop(&mut self) {
        // remove_dir_all descends into a mount left inside and empties it:
        // a canary that changed at all stays, logged. No `before` yet: a
        // half-built one from `create`, which nothing has touched.
        if !self.keep {
            if !self.before.is_empty() && !self.changed().is_empty() {
                eprintln!("left {}: changed", self.dir.display());
            } else if let Err(e) = fs::remove_dir_all(&self.dir) {
                eprintln!("left {}: {e}", self.dir.display());
            }
        }
    }
}

/// `before` empty: the first snapshot, which descends everywhere on `dev`.
fn walk(base: &Path, rel: &Path, dev: u64, before: &Tree, tree: &mut Tree) -> Result<()> {
    let p = base.join(rel);
    let m = fs::symlink_metadata(&p)?;
    let t = m.file_type();
    let body = if t.is_file() {
        // lstat→open is a race only the SUT could be on the other side of:
        // never follow or block on what it put there.
        let mut buf = Vec::new();
        let f = File::options().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&p)?;
        // ponytail: 1 MiB cap, size catches growth past it; hash the rest if a canary grows that big.
        f.take(1 << 20).read_to_end(&mut buf)?;
        Body::Bytes(buf)
    } else if t.is_symlink() {
        Body::Target(fs::read_link(&p)?)
    } else {
        Body::Other
    };
    let state = State { dev: m.dev(), mode: m.mode(), uid: m.uid(), gid: m.gid(), nlink: m.nlink(), size: m.size(), rdev: m.rdev(), body };
    let id = (m.dev(), m.ino());
    tree.insert(rel.into(), Entry { id, state });
    // A mount over a canary directory is already a dev change, or an inode
    // change for a bind mount from the same filesystem; its contents may be
    // the whole host. A directory that is new is a change by itself.
    if t.is_dir() && m.dev() == dev && before.get(rel).map_or(before.is_empty(), |e| e.id == id) {
        for e in fs::read_dir(&p)? {
            walk(base, &rel.join(e?.file_name()), dev, before, tree)?;
        }
    }
    Ok(())
}

/// The attacker (§1), in host ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alice {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub cap_eff: u64,
}

impl Alice {
    /// `--attacker uid:gid`: no supplementary groups, no capabilities.
    pub fn parse(s: &str) -> Result<Self> {
        let (u, g) = s.split_once(':').context("--attacker uid:gid")?;
        let (uid, gid): (u32, u32) = (u.parse()?, g.parse()?);
        // setres*id reads u32::MAX as -1, "leave unchanged": alice would keep root's.
        ensure!(uid != u32::MAX && gid != u32::MAX, "--attacker: {} is not an id", u32::MAX);
        Ok(Alice { uid, gid, groups: vec![], cap_eff: 0 })
    }
}

/// Task `tid`'s effective uid, as our namespace sees it (§5's handle check).
pub fn euid(tid: u32) -> Result<u32> {
    let s = fs::read_to_string(format!("/proc/{tid}/status"))?;
    let uid = s.lines().find_map(|l| l.strip_prefix("Uid:")).context("no Uid:")?;
    Ok(uid.split_whitespace().nth(1).context("short Uid:")?.parse()?)
}

impl std::fmt::Display for Alice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "alice: uid={} gid={} groups={:?} capeff={:016x}", self.uid, self.gid, self.groups, self.cap_eff)
    }
}

pub use crate::schedule::Finding;

/// Mount points in a mountinfo (field 5), as that task sees them, octal
/// escapes (`\040`) undone. Bytes: a mount point need not be UTF-8.
pub fn mount_points(mountinfo: &[u8]) -> Vec<PathBuf> {
    let unescape = |b: &[u8]| {
        let (mut out, mut i) = (Vec::new(), 0);
        while i < b.len() {
            match (b[i], b.get(i + 1..i + 4).and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok())) {
                (b'\\', Some(c)) => (out.push(c), i += 4),
                (c, _) => (out.push(c), i += 1),
            };
        }
        PathBuf::from(OsString::from_vec(out))
    };
    mountinfo.split(|&c| c == b'\n').filter_map(|l| l.split(|&c| c == b' ').nth(4)).map(unescape).collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Violation(Vec<Finding>),
    RuntimeRefused,
    RuntimeError,
    Clean,
}

/// §6, first match wins. An ending of None: the deadline.
pub fn outcome(findings: Vec<Finding>, sut: Option<ExitStatus>, baseline: Option<ExitStatus>) -> Outcome {
    let ok = |s: Option<ExitStatus>| s.is_some_and(|s| s.success());
    if !findings.is_empty() {
        Outcome::Violation(findings)
    } else if !ok(baseline) {
        Outcome::RuntimeError // the scenario is broken
    } else if ok(sut) {
        Outcome::Clean
    } else if sut.is_some_and(|s| s.code().is_some()) {
        Outcome::RuntimeRefused // exited nonzero: refused
    } else {
        Outcome::RuntimeError // signal or deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn outcome_order() {
        let (ok, fail, killed) = (Some(ExitStatus::from_raw(0)), Some(ExitStatus::from_raw(1 << 8)), Some(ExitStatus::from_raw(9)));
        let f = || vec![Finding::Changed { entry: "file".into() }];
        assert_eq!(outcome(f(), fail, ok), Outcome::Violation(f()));
        assert_eq!(outcome(vec![], fail, ok), Outcome::RuntimeRefused);
        assert_eq!(outcome(vec![], ok, fail), Outcome::RuntimeError);
        assert_eq!(outcome(vec![], killed, ok), Outcome::RuntimeError);
        assert_eq!(outcome(vec![], None, ok), Outcome::RuntimeError);
        assert_eq!(outcome(vec![], ok, ok), Outcome::Clean);
    }

    #[test]
    fn attacker_minus_one_refused() {
        assert!(Alice::parse("65534:4294967295").is_err());
        assert!(Alice::parse("4294967295:65534").is_err());
        assert_eq!(Alice::parse("65534:65534").unwrap().gid, 65534);
    }

    #[test]
    fn mount_points_unescape() {
        let mi = b"22 1 0:21 / / rw - ext4 /dev/vda rw\n36 22 98:0 / /a\\040b rw,noatime master:1 - tmpfs none rw\n";
        assert_eq!(mount_points(mi), [PathBuf::from("/"), PathBuf::from("/a b")]);
    }
}
