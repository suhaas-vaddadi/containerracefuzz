// SPDX-License-Identifier: GPL-2.0
//
// The oracle: the harness-owned half that turns an exposed window into a
// finding (attacker brainstorm, "Core decision: the attacker and the oracle
// are separate").
//
// The oracle never reads the attacker's action list. Detection is defined
// against spec-implied invariants, not against what the attack claims to do --
// which is what buys the payoff that a new attacker gets bug detection for
// free. The engine invokes `observe` *after* the victim's use has run, at the
// next point the victim is frozen again (its next checkpoint, or its exit), so
// the use it is ruling on has provably completed.
//
// Every window runs the whole battery, because the oracle does not know which
// attack family fired. Each check is an *outcome* every escape ends in,
// whatever race produced it:
//
// - **Host integrity** -- a watched host path was created, removed, replaced,
//   chmodded, chowned or written (CVE-2019-5736, CVE-2025-52881).
// - **Canary** -- the bytes of a host secret appear inside the rootfs: a
//   read-only escape that changes nothing on the host (CVE-2018-15664).
// - **Mounts** -- the container's mount table has a mount the spec does not
//   declare, a declared mount of the wrong type, a masked path that is not
//   masked, or a read-only path that is writable (CVE-2021-30465,
//   CVE-2019-19921, CVE-2019-16884, CVE-2025-31133, CVE-2025-52565).
// - **Handles** -- the container process's cwd or a directory fd resolves
//   outside its root (CVE-2024-21626).
// - **Privileges** -- the container process holds capabilities the spec did not
//   grant, lacks `no_new_privs`, or runs without the spec's seccomp filter.
//
// The first two are host-side and run whenever they are configured. The last
// three inspect every process whose root is the rootfs and whose executable
// lives inside it -- i.e. the container *after* it exec'd its entrypoint. The
// runtime's own init process has neither dropped its privileges nor closed its
// host fds yet, so ruling on it would read setup as escape.
//
// The intended truth comes from `OracleDecl`, which the harness fills (the
// binary derives it from the OCI bundle): the engine never learns what OCI is.

use crate::checkpoint::CheckpointId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

/// What the engine hands the oracle about the window it is ruling on.
///
/// `before` and `after` are the use path's identity on either side of the
/// attacker's turn. They show whether the attacker *acted* there, which is a
/// debug signal, not a finding: the attacker never loses the race, so a change
/// says nothing about whether the runtime then did anything wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowContext {
    pub checkpoint: CheckpointId,
    pub path: Option<PathBuf>,
    pub before: Option<PathIdentity>,
    pub after: Option<PathIdentity>,
    pub step_idx: u64,
}

/// A cheap, stable fingerprint of the filesystem object a path names.
///
/// `symlink_metadata` is deliberate: it describes the object the *name* refers
/// to, following nothing, so a file swapped for a symlink changes identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}

impl PathIdentity {
    /// The identity of `path`, or `None` if nothing is there to stat.
    pub fn of(path: &Path) -> Option<Self> {
        let md = std::fs::symlink_metadata(path).ok()?;
        Some(PathIdentity {
            device: md.dev(),
            inode: md.ino(),
            mode: md.mode(),
        })
    }
}

/// The scenario's intended truth: the config's top-level `oracle` block.
///
/// Every field is optional; an absent one disables the check that needs it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleDecl {
    /// The container's root filesystem, as the host sees it. Enables the
    /// canary scan and every container-process check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<PathBuf>,
    /// The mounts the spec declares, by container-relative target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountDecl>,
    /// Paths that must be masked: a read-only tmpfs, or a bind of `/dev/null`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub masked_paths: Vec<String>,
    /// Paths that must be mounted read-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly_paths: Vec<String>,
    /// Host paths nothing in the run may create, remove or change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watch: Vec<PathBuf>,
    /// A host file holding a secret that must never appear inside the rootfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<PathBuf>,
    /// Every capability the container process may hold in its effective set,
    /// as a bitmask in `CapEff` order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cap_eff: Option<u64>,
    /// The container process must have `no_new_privs` set.
    #[serde(default)]
    pub no_new_privs: bool,
    /// The fewest seccomp filters the container process may run under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_seccomp_filters: Option<u32>,
}

/// One declared mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountDecl {
    pub target: String,
    /// The filesystem type the topmost mount at `target` must have. `None` for
    /// a bind mount, which reports the type of whatever it binds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fstype: Option<String>,
}

/// The oracle's ruling on one window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleVerdict {
    /// No spec invariant was violated in this window.
    Clean,
    /// A spec-implied invariant was violated; the string is a human-readable
    /// description of what broke.
    Violation(String),
}

impl OracleVerdict {
    pub fn is_violation(&self) -> bool {
        matches!(self, OracleVerdict::Violation(_))
    }
}

/// Everything about a watched path a write, chmod, chown or swap can change.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    identity: (u64, u64),
    mode: u32,
    owner: (u32, u32),
    /// Size and mtime/ctime with nanoseconds: ctime cannot be set from
    /// userspace, so any write or metadata change on a real filesystem moves it.
    times: (u64, i64, i64, i64, i64),
    /// The first `CONTENT_PREFIX` bytes of a regular file. Pseudo-files
    /// (`/proc/sys/...`) keep their times fixed across writes, so for them the
    /// content is the only witness.
    content: Option<Vec<u8>>,
}

const CONTENT_PREFIX: u64 = 64 << 10;
// ponytail: whole-tree canary scan every window; index the rootfs if large images make windows slow.
const CANARY_MAX_FILE: u64 = 16 << 20;

impl Fingerprint {
    fn of(path: &Path) -> Option<Self> {
        let md = std::fs::symlink_metadata(path).ok()?;
        let content = md
            .is_file()
            .then(|| read_regular(path, CONTENT_PREFIX).unwrap_or_default());
        Some(Fingerprint {
            identity: (md.dev(), md.ino()),
            mode: md.mode(),
            owner: (md.uid(), md.gid()),
            times: (
                md.size(),
                md.mtime(),
                md.mtime_nsec(),
                md.ctime(),
                md.ctime_nsec(),
            ),
            content,
        })
    }

    /// What changed between two fingerprints of one path, in words.
    fn diff(before: &Option<Self>, now: &Option<Self>) -> Option<&'static str> {
        match (before, now) {
            (None, None) => None,
            (None, Some(_)) => Some("created"),
            (Some(_), None) => Some("removed"),
            (Some(b), Some(n)) if b.identity != n.identity => Some("replaced by another object"),
            (Some(b), Some(n)) if b.mode != n.mode => Some("mode changed"),
            (Some(b), Some(n)) if b.owner != n.owner => Some("owner changed"),
            (Some(b), Some(n)) if b.content != n.content => Some("content changed"),
            (Some(b), Some(n)) if b.times != n.times => Some("written"),
            _ => None,
        }
    }
}

/// The oracle for one run: the intended truth, plus the host baseline taken
/// before the victim started.
#[derive(Debug)]
pub struct Oracle {
    decl: OracleDecl,
    baseline: Vec<(PathBuf, Option<Fingerprint>)>,
    canary: Option<Vec<u8>>,
    /// Each finding is reported at the first window that shows it; a broken
    /// invariant stays broken, and repeating it every window would bury the
    /// window that caused it.
    reported: HashSet<String>,
}

impl Oracle {
    /// Snapshot the host. Must run before the victim does: the engine builds
    /// it in `Engine::new`, ahead of `run` spawning anything.
    pub fn new(decl: OracleDecl) -> Self {
        let baseline = decl
            .watch
            .iter()
            .map(|p| (p.clone(), Fingerprint::of(p)))
            .collect();
        let canary = decl.canary.as_ref().and_then(|p| match std::fs::read(p) {
            Ok(bytes) if !bytes.is_empty() => Some(bytes),
            // Engine construction is infallible, so a canary that cannot be
            // read is logged loudly and the check disabled, never faked.
            Ok(_) => {
                log::error!(
                    "oracle canary {} is empty: canary check disabled",
                    p.display()
                );
                None
            }
            Err(e) => {
                log::error!("oracle canary {}: {e}: canary check disabled", p.display());
                None
            }
        });
        Oracle {
            decl,
            baseline,
            canary,
            reported: HashSet::new(),
        }
    }

    /// Rule on one window: run the whole battery and report what newly broke.
    pub fn observe(&mut self, ctx: &WindowContext) -> OracleVerdict {
        if let (Some(path), Some(b), Some(a)) = (&ctx.path, &ctx.before, &ctx.after) {
            if b != a {
                log::debug!(
                    "attacker changed `{}` at {} ({b:?} -> {a:?})",
                    path.display(),
                    ctx.checkpoint
                );
            }
        }

        let mut broken = Vec::new();
        for (path, before) in &self.baseline {
            if let Some(what) = Fingerprint::diff(before, &Fingerprint::of(path)) {
                broken.push(format!("host path `{}`: {what}", path.display()));
            }
        }
        if let Some(rootfs) = &self.decl.rootfs {
            if let Some(needle) = &self.canary {
                if let Ok(md) = std::fs::metadata(rootfs) {
                    if let Some(hit) = find_bytes(rootfs, md.dev(), needle) {
                        broken.push(format!(
                            "the host canary's secret is readable in the container at `{}`",
                            hit.display()
                        ));
                    }
                }
            }
            #[cfg(target_os = "linux")]
            for pid in container_processes(rootfs) {
                broken.extend(inspect_process(pid, &self.decl));
            }
        }

        broken.retain(|b| self.reported.insert(b.clone()));
        if broken.is_empty() {
            OracleVerdict::Clean
        } else {
            OracleVerdict::Violation(broken.join("; "))
        }
    }
}

/// Up to `limit` bytes of `path` if it is a regular file, opened without
/// following a symlink or blocking: a path swapped for a FIFO, or for a link to
/// `/dev/zero`, between the caller's stat and this read cannot hang or flood
/// the oracle.
fn read_regular(path: &Path, limit: u64) -> Option<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    f.take(limit).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// The first regular file under `dir`, on device `dev`, whose content contains
/// `needle`. Symlinks are not followed and other filesystems are not entered.
fn find_bytes(dir: &Path, dev: u64, needle: &[u8]) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if md.dev() != dev {
            continue;
        }
        if md.is_dir() {
            if let Some(hit) = find_bytes(&path, dev, needle) {
                return Some(hit);
            }
        } else if md.is_file() && md.size() <= CANARY_MAX_FILE {
            if let Some(bytes) = read_regular(&path, CANARY_MAX_FILE) {
                if bytes.windows(needle.len()).any(|w| w == needle) {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// The mount-table violations in one process's `mountinfo`, whose mount points
/// are relative to that process's root -- i.e. container-relative. `exists`
/// says whether a container path exists: a masked or read-only path that does
/// must have its mount.
pub fn mount_violations(
    mountinfo: &str,
    decl: &OracleDecl,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let norm = |p: &str| match p.trim_end_matches('/') {
        "" => "/".to_string(),
        t => t.to_string(),
    };
    let mut declared: HashSet<String> = HashSet::from(["/".to_string()]);
    declared.extend(decl.mounts.iter().map(|m| norm(&m.target)));
    declared.extend(decl.masked_paths.iter().map(|p| norm(p)));
    declared.extend(decl.readonly_paths.iter().map(|p| norm(p)));

    // Later lines are mounted over earlier ones at the same target.
    let mut topmost: Vec<(String, String, String, String)> = Vec::new();
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        // The separator follows the six fixed fields and the optional ones; a
        // mount point named `-` is one of the fixed fields, not it.
        let Some(dash) = fields.iter().skip(6).position(|f| *f == "-").map(|i| i + 6) else {
            continue;
        };
        let (Some(root), Some(target), Some(opts), Some(fstype)) = (
            fields.get(3),
            fields.get(4),
            fields.get(5),
            fields.get(dash + 1),
        ) else {
            continue;
        };
        let entry = (
            norm(&unescape(target)),
            unescape(root),
            opts.to_string(),
            fstype.to_string(),
        );
        topmost.retain(|t| t.0 != entry.0);
        topmost.push(entry);
    }

    let mut out = Vec::new();
    for (target, root, opts, fstype) in &topmost {
        if !declared.contains(target) {
            out.push(format!(
                "undeclared mount at `{target}` ({fstype}, root `{root}`)"
            ));
        }
        if let Some(want) = decl
            .mounts
            .iter()
            .find(|m| norm(&m.target) == *target)
            .and_then(|m| m.fstype.as_ref())
        {
            if want != fstype {
                out.push(format!(
                    "mount at `{target}` is {fstype} (root `{root}`), the spec declares {want}"
                ));
            }
        }
        // runc masks a file with a bind of `/dev/null` and a directory with a
        // read-only tmpfs.
        let ro = opts.split(',').any(|o| o == "ro");
        if decl.masked_paths.iter().any(|p| norm(p) == *target)
            && !(fstype == "tmpfs" && ro)
            && root != "/null"
        {
            out.push(format!(
                "masked path `{target}` is not masked: {fstype}, root `{root}`"
            ));
        }
        if decl.readonly_paths.iter().any(|p| norm(p) == *target) && !ro {
            out.push(format!("read-only path `{target}` is mounted {opts}"));
        }
    }
    for p in decl.masked_paths.iter().chain(&decl.readonly_paths) {
        if !topmost.iter().any(|t| t.0 == norm(p)) && exists(p) {
            out.push(format!("`{p}` exists but has no mask or read-only mount"));
        }
    }
    out
}

/// Undo `mountinfo`'s octal escaping of space, tab, newline and backslash.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        match rest
            .get(i + 1..i + 4)
            .filter(|o| o.bytes().all(|b| (b'0'..=b'7').contains(&b)))
            .and_then(|o| u8::from_str_radix(o, 8).ok())
        {
            Some(b) => {
                out.push(b as char);
                rest = &rest[i + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[i + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The privilege violations in one process's `/proc/<pid>/status`.
pub fn privilege_violations(status: &str, decl: &OracleDecl) -> Vec<String> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
    };
    let mut out = Vec::new();
    if let Some(max) = decl.max_cap_eff {
        if let Some(eff) = field("CapEff").and_then(|v| u64::from_str_radix(v, 16).ok()) {
            if eff & !max != 0 {
                out.push(format!(
                    "holds capabilities the spec did not grant: CapEff {eff:#x}, extra {:#x}",
                    eff & !max
                ));
            }
        }
    }
    if decl.no_new_privs && field("NoNewPrivs") != Some("1") {
        out.push("no_new_privs is not set".to_string());
    }
    // `Seccomp_filters` is new in 5.9; without it there is nothing to count.
    if let (Some(min), Some(n)) = (
        decl.min_seccomp_filters,
        field("Seccomp_filters").and_then(|v| v.parse::<u32>().ok()),
    ) {
        if n < min {
            out.push(format!(
                "runs under {n} seccomp filter(s), the spec implies at least {min}"
            ));
        }
    }
    out
}

/// Every process that is the container after its entrypoint exec: its root is
/// the rootfs, and its executable is a file inside the rootfs.
#[cfg(target_os = "linux")]
fn container_processes(rootfs: &Path) -> Vec<i32> {
    let id = |md: std::fs::Metadata| (md.dev(), md.ino());
    let Ok(root) = std::fs::metadata(rootfs).map(id) else {
        return Vec::new();
    };
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    procs
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            let proc = PathBuf::from(format!("/proc/{pid}"));
            if std::fs::metadata(proc.join("root")).map(id).ok() != Some(root) {
                return false;
            }
            // The kernel prints the executable's path relative to the
            // container's root, which the host cannot reach; resolving that
            // path under the rootfs must land on the same file.
            // ponytail: an entrypoint run from a memfd or a container-only
            // mount (volume, tmpfs) is not recognised; exclude runc init by
            // its exe instead if that matters.
            let Ok(exe) = std::fs::read_link(proc.join("exe")) else {
                return false;
            };
            let exe = exe.to_string_lossy();
            // An unlinked entrypoint must not hide the process; runc's own
            // memfd copy of itself is unlinked too, so name it explicitly.
            if exe.ends_with(" (deleted)") {
                return !exe.starts_with("/memfd:");
            }
            let inside = rootfs.join(exe.trim_start_matches('/'));
            match (
                std::fs::metadata(inside),
                std::fs::metadata(proc.join("exe")),
            ) {
                (Ok(a), Ok(b)) => id(a) == id(b),
                _ => false,
            }
        })
        .collect()
}

/// Run the per-process checks on one container process.
#[cfg(target_os = "linux")]
fn inspect_process(pid: i32, decl: &OracleDecl) -> Vec<String> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let mut out = Vec::new();
    if let Ok(m) = std::fs::read_to_string(proc.join("mountinfo")) {
        let root = proc.join("root");
        out.extend(mount_violations(&m, decl, |p| {
            std::fs::symlink_metadata(root.join(p.trim_start_matches('/'))).is_ok()
        }));
    }
    if let Ok(s) = std::fs::read_to_string(proc.join("status")) {
        out.extend(
            privilege_violations(&s, decl)
                .into_iter()
                .map(|v| format!("container pid {pid} {v}")),
        );
    }
    let Ok(root) = std::fs::metadata(proc.join("root")) else {
        return out;
    };
    let mut handles = vec![proc.join("cwd")];
    if let Ok(fds) = std::fs::read_dir(proc.join("fd")) {
        handles.extend(fds.flatten().map(|e| e.path()));
    }
    for h in handles {
        if escapes_root(&h, (root.dev(), root.ino())) == Some(true) {
            let shown = std::fs::read_link(&h).unwrap_or_default();
            out.push(format!(
                "container pid {pid} holds `{}` -> `{}`, outside its root",
                h.display(),
                shown.display()
            ));
        }
    }
    out
}

/// Whether the directory a `/proc/<pid>/{cwd,fd/N}` link names lies outside
/// the process's root: walk `..` until reaching the root (inside) or a
/// directory that is its own parent (the top of some other tree: outside).
/// `None` for a non-directory, which has no `..` to walk.
// ponytail: only directory handles are walked; a leaked host *file* fd is caught when it is used (integrity, canary).
#[cfg(target_os = "linux")]
fn escapes_root(link: &Path, root: (u64, u64)) -> Option<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let open = |p: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(p)
            .ok()
    };
    let mut cur = open(link)?;
    for _ in 0..4096 {
        let md = cur.metadata().ok()?;
        let here = (md.dev(), md.ino());
        if here == root {
            return Some(false);
        }
        let parent = open(&PathBuf::from(format!(
            "/proc/self/fd/{}/..",
            cur.as_raw_fd()
        )))?;
        let pmd = parent.metadata().ok()?;
        if (pmd.dev(), pmd.ino()) == here {
            return Some(true);
        }
        cur = parent;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> WindowContext {
        WindowContext {
            checkpoint: CheckpointId::new("openat"),
            path: None,
            before: None,
            after: None,
            step_idx: 0,
        }
    }

    #[test]
    fn an_empty_decl_is_always_clean() {
        assert_eq!(
            Oracle::new(OracleDecl::default()).observe(&ctx()),
            OracleVerdict::Clean
        );
    }

    #[test]
    fn a_watched_host_path_that_changes_is_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let runc = dir.path().join("runc");
        let cron = dir.path().join("cron");
        std::fs::write(&runc, b"ELF").unwrap();
        let mut o = Oracle::new(OracleDecl {
            watch: vec![runc.clone(), cron.clone()],
            ..Default::default()
        });
        assert_eq!(o.observe(&ctx()), OracleVerdict::Clean);

        std::fs::write(&runc, b"EVIL").unwrap();
        std::fs::write(&cron, b"* * * * * root sh").unwrap();
        let v = o.observe(&ctx());
        let OracleVerdict::Violation(msg) = &v else {
            panic!("{v:?}")
        };
        assert!(
            msg.contains("runc`: content changed") && msg.contains("cron`: created"),
            "{msg}"
        );
        assert_eq!(o.observe(&ctx()), OracleVerdict::Clean, "already reported");
    }

    #[test]
    fn a_watched_file_swapped_for_a_symlink_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        let mut o = Oracle::new(OracleDecl {
            watch: vec![f.clone()],
            ..Default::default()
        });
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &f).unwrap();
        assert!(o.observe(&ctx()).is_violation());
    }

    #[test]
    fn the_canary_s_bytes_inside_the_rootfs_are_a_read_escape() {
        let dir = tempfile::tempdir().unwrap();
        let canary = dir.path().join("canary");
        let rootfs = dir.path().join("rootfs");
        std::fs::write(&canary, b"crfuzz-secret-7f3a").unwrap();
        std::fs::create_dir_all(rootfs.join("tmp")).unwrap();
        std::fs::write(rootfs.join("tmp/benign"), b"nothing here").unwrap();
        let mut o = Oracle::new(OracleDecl {
            rootfs: Some(rootfs.clone()),
            canary: Some(canary),
            ..Default::default()
        });
        assert_eq!(o.observe(&ctx()), OracleVerdict::Clean);

        std::fs::write(
            rootfs.join("tmp/copied"),
            b"prefix crfuzz-secret-7f3a suffix",
        )
        .unwrap();
        let v = o.observe(&ctx());
        assert!(
            matches!(&v, OracleVerdict::Violation(m) if m.contains("tmp/copied")),
            "{v:?}"
        );
    }

    fn spec_mounts() -> OracleDecl {
        OracleDecl {
            mounts: vec![
                MountDecl {
                    target: "/proc".into(),
                    fstype: Some("proc".into()),
                },
                MountDecl {
                    target: "/dev".into(),
                    fstype: Some("tmpfs".into()),
                },
            ],
            masked_paths: vec!["/proc/kcore".into(), "/sys/firmware".into()],
            readonly_paths: vec!["/proc/sys".into()],
            ..Default::default()
        }
    }

    const GOOD: &str = "\
1 0 0:50 / / rw,relatime - overlay overlay rw
2 1 0:51 / /proc rw,nosuid - proc proc rw
3 1 0:52 / /dev rw,nosuid - tmpfs tmpfs rw
4 2 0:52 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw
5 2 0:51 /sys /proc/sys ro,nosuid - proc proc rw
6 1 0:53 / /sys/firmware ro - tmpfs tmpfs ro
";

    #[test]
    fn a_mount_table_matching_the_spec_is_clean() {
        assert_eq!(
            mount_violations(GOOD, &spec_mounts(), |_| true),
            Vec::<String>::new()
        );
        // A bind of the host's `/dev/null` (devtmpfs) masks too.
        let devtmpfs = GOOD.replace(
            "0:52 /null /proc/kcore rw,nosuid - tmpfs",
            "0:5 /null /proc/kcore rw,nosuid - devtmpfs",
        );
        assert_eq!(
            mount_violations(&devtmpfs, &spec_mounts(), |_| true),
            Vec::<String>::new()
        );
    }

    #[test]
    fn each_mount_table_deviation_is_reported() {
        let bad = format!(
            "{GOOD}\
7 1 8:1 /etc /host\\040etc rw - ext4 /dev/vda1 rw
8 1 0:54 / /proc rw - tmpfs tmpfs rw
9 2 0:51 /sys/kernel/core_pattern /proc/kcore rw - proc proc rw
10 2 0:51 /sys /proc/sys rw - proc proc rw
"
        );
        let v = mount_violations(&bad, &spec_mounts(), |_| true);
        assert_eq!(v.len(), 4, "{v:#?}");
        assert!(
            v[0].contains("`/host etc`"),
            "escaped space is undone: {v:?}"
        );
        assert!(v.iter().any(|m| m.contains("`/proc` is tmpfs")));
        assert!(v.iter().any(|m| m.contains("`/proc/kcore` is not masked")));
        assert!(v.iter().any(|m| m.contains("`/proc/sys` is mounted rw")));
    }

    #[test]
    fn a_masked_path_that_exists_without_its_mount_is_reported() {
        let unmasked: String = GOOD
            .lines()
            .filter(|l| !l.contains("/proc/kcore"))
            .map(|l| format!("{l}\n"))
            .collect();
        let v = mount_violations(&unmasked, &spec_mounts(), |p| p == "/proc/kcore");
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("/proc/kcore"));
        assert!(
            mount_violations(&unmasked, &spec_mounts(), |_| false).is_empty(),
            "absent paths need no mask"
        );
    }

    #[test]
    fn a_writable_tmpfs_does_not_mask() {
        let rw = GOOD.replace("/sys/firmware ro - tmpfs", "/sys/firmware rw - tmpfs");
        assert_eq!(mount_violations(&rw, &spec_mounts(), |_| true).len(), 1);
    }

    #[test]
    fn privileges_beyond_the_spec_are_reported() {
        let decl = OracleDecl {
            max_cap_eff: Some(0x00000000a80425fb),
            no_new_privs: true,
            min_seccomp_filters: Some(2),
            ..Default::default()
        };
        let ok = "CapEff:\t00000000a80425fb\nNoNewPrivs:\t1\nSeccomp_filters:\t2\n";
        assert_eq!(privilege_violations(ok, &decl), Vec::<String>::new());
        let bad = "CapEff:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        assert_eq!(privilege_violations(bad, &decl).len(), 3);
        // A pre-5.9 kernel has no `Seccomp_filters`: nothing to count.
        let old = "CapEff:\t00000000a80425fb\nNoNewPrivs:\t1\nSeccomp:\t2\n";
        assert_eq!(privilege_violations(old, &decl), Vec::<String>::new());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_directory_handle_outside_the_root_escapes_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let md = std::fs::metadata(&root).unwrap();
        let id = (md.dev(), md.ino());
        assert_eq!(escapes_root(&root.join("a/b"), id), Some(false));
        assert_eq!(escapes_root(dir.path(), id), Some(true));
        assert_eq!(
            escapes_root(Path::new("/proc/self/exe"), id),
            None,
            "not a directory"
        );
    }
}
