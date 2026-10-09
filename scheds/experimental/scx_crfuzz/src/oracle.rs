// SPDX-License-Identifier: GPL-2.0
//
// The oracle: a lightweight object diff.
//
// For every path the victim's held syscalls resolved (the window paths, which
// the engine collects), take an object token before the attacker runs and
// again after it, and report any path whose token changed. That is the whole
// oracle. It knows nothing about OCI, mounts, capabilities or the attacker's
// actions -- a change to the underlying object is the finding.
//
// The token is a cheap, randomly keyed hash of the object's identity and
// metadata (`statx`-equivalent fields: dev, ino, mode, uid, gid, nlink, size,
// mtime and ctime with nanoseconds). One syscall per path, no reads. With
// `content` opted in, a regular file's first 64 KiB (or a symlink's target) is
// folded into the hash; ctime already witnesses every userspace write, so this
// is belt-and-suspenders, not the default.
//
// What this deliberately does not see is documented in the crate README as a
// coverage reminder: reads (a canary-style leak leaves no object change),
// mount-table additions that touch no watched object, cwd/dir-fd escapes, and
// privilege changes. It is a minimal, lightweight subset of a large bug space.

use serde::Deserialize;
use serde::Serialize;
use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::hash::BuildHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

/// The oracle's only option: fold object content into the token too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleDecl {
    #[serde(default)]
    pub content: bool,
}

/// How many bytes of a regular file the content hash reads.
const CONTENT_MAX: u64 = 64 << 10;

/// Most immediate children of a watched directory the content hash visits.
const TREE_MAX: usize = 4096;

/// A snapshot of the watched objects: path -> token. `None` means the path did
/// not resolve to an object (absent, or unreadable) at snapshot time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest(BTreeMap<PathBuf, Option<u64>>);

impl Manifest {
    /// The paths whose object changed between this snapshot and `after`.
    pub fn diff(&self, after: &Manifest) -> Vec<String> {
        let mut out = Vec::new();
        for (path, before) in &self.0 {
            match (*before, after.0.get(path).copied().flatten()) {
                (None, None) => {}
                (None, Some(_)) => out.push(format!("`{}`: created", path.display())),
                (Some(_), None) => out.push(format!("`{}`: removed", path.display())),
                (Some(b), Some(a)) if b == a => {}
                (Some(_), Some(_)) => out.push(format!("`{}`: changed", path.display())),
            }
        }
        // Keys only in `after`: a child that appeared under a watched directory.
        for (path, value) in &after.0 {
            if !self.0.contains_key(path) && value.is_some() {
                out.push(format!("`{}`: created", path.display()));
            }
        }
        out
    }
}

/// Snapshots one run's window paths.
pub struct Oracle {
    content: bool,
    /// One key for the whole run, so tokens from the before and after snapshots
    /// are comparable, and so an attacker who does not know the key cannot
    /// craft a colliding object.
    key: RandomState,
    watched: BTreeSet<PathBuf>,
}

impl Oracle {
    pub fn new(decl: OracleDecl) -> Self {
        Oracle {
            content: decl.content,
            key: RandomState::new(),
            watched: BTreeSet::new(),
        }
    }

    /// Record a path the victim's held syscall resolved. Deduped.
    pub fn watch(&mut self, path: impl Into<PathBuf>) {
        self.watched.insert(path.into());
    }

    /// Tokenise every watched object. One `statx`-equivalent per path, plus a
    /// bounded read per regular file only when `content` is on. With `content`
    /// on, the immediate children of a watched directory are recorded too, so a
    /// file planted inside a swapped directory (a canary) surfaces by name.
    pub fn snapshot(&self) -> Manifest {
        let mut map = BTreeMap::new();
        for p in &self.watched {
            map.insert(p.clone(), self.token(p));
            if self.content {
                self.add_children(p, &mut map);
            }
        }
        Manifest(map)
    }

    /// Record a watched directory's immediate children, tokenised by *content*
    /// (kind, size, bytes, link target) and not identity: a faithful copy of a
    /// tree compares equal, so only a real content difference -- a canary file
    /// the attacker dropped in -- changes a descendant's token.
    fn add_children(&self, dir: &Path, map: &mut BTreeMap<PathBuf, Option<u64>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten().take(TREE_MAX) {
            let child = entry.path();
            map.insert(child.clone(), self.content_token(&child));
        }
    }

    fn content_token(&self, path: &Path) -> Option<u64> {
        let md = std::fs::symlink_metadata(path).ok()?;
        let mut h = self.key.build_hasher();
        md.file_type().is_dir().hash(&mut h);
        md.file_type().is_symlink().hash(&mut h);
        md.size().hash(&mut h);
        if md.file_type().is_symlink() {
            if let Ok(target) = std::fs::read_link(path) {
                target.to_string_lossy().hash(&mut h);
            }
        } else if md.is_file() && md.size() <= CONTENT_MAX {
            if let Some(bytes) = read_prefix(path, CONTENT_MAX) {
                bytes.hash(&mut h);
            }
        }
        Some(h.finish())
    }

    fn token(&self, path: &Path) -> Option<u64> {
        let md = std::fs::symlink_metadata(path).ok()?;
        let mut h = self.key.build_hasher();
        md.dev().hash(&mut h);
        md.ino().hash(&mut h);
        md.mode().hash(&mut h);
        md.uid().hash(&mut h);
        md.gid().hash(&mut h);
        md.nlink().hash(&mut h);
        md.size().hash(&mut h);
        md.mtime().hash(&mut h);
        md.mtime_nsec().hash(&mut h);
        md.ctime().hash(&mut h);
        md.ctime_nsec().hash(&mut h);
        if self.content {
            if md.file_type().is_symlink() {
                if let Ok(target) = std::fs::read_link(path) {
                    target.to_string_lossy().hash(&mut h);
                }
            } else if md.is_file() && md.size() <= CONTENT_MAX {
                if let Some(bytes) = read_prefix(path, CONTENT_MAX) {
                    bytes.hash(&mut h);
                }
            }
        }
        Some(h.finish())
    }
}

/// Up to `limit` bytes of a regular file, opened without following a symlink or
/// blocking, so a path swapped for a FIFO or a link to `/dev/zero` cannot hang
/// the oracle.
fn read_prefix(path: &Path, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle() -> (tempfile::TempDir, PathBuf, Oracle) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obj");
        std::fs::write(&path, b"BENIGN").unwrap();
        let mut o = Oracle::new(OracleDecl::default());
        o.watch(&path);
        (dir, path, o)
    }

    #[test]
    fn an_unchanged_object_diffs_clean() {
        let (_dir, _path, o) = oracle();
        let before = o.snapshot();
        assert!(before.diff(&o.snapshot()).is_empty());
    }

    #[test]
    fn a_replaced_object_is_reported() {
        let (_dir, path, o) = oracle();
        let before = o.snapshot();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &path).unwrap();
        let diff = before.diff(&o.snapshot());
        assert_eq!(diff.len(), 1, "{diff:?}");
        assert!(diff[0].contains("changed"), "{diff:?}");
    }

    #[test]
    fn a_removed_object_is_reported() {
        let (_dir, path, o) = oracle();
        let before = o.snapshot();
        std::fs::remove_file(&path).unwrap();
        let diff = before.diff(&o.snapshot());
        assert_eq!(diff.len(), 1, "{diff:?}");
        assert!(diff[0].contains("removed"), "{diff:?}");
    }

    #[test]
    fn a_metadata_change_is_caught_without_content() {
        // mode + ctime move; the identity/metadata token alone sees it.
        let (_dir, path, o) = oracle();
        let before = o.snapshot();
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o600);
        std::fs::set_permissions(&path, perm).unwrap();
        assert_eq!(before.diff(&o.snapshot()).len(), 1);
    }

    #[test]
    fn content_names_a_canary_planted_in_a_watched_directory() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::fs::write(tree.join("keep"), b"same").unwrap();
        let mut o = Oracle::new(OracleDecl { content: true });
        o.watch(&tree);
        let before = o.snapshot();
        std::fs::write(tree.join("crfuzz-canary"), b"SECRET").unwrap();
        let diff = before.diff(&o.snapshot());
        assert!(
            diff.iter().any(|d| d.contains("crfuzz-canary") && d.contains("created")),
            "{diff:?}"
        );
    }

    #[test]
    fn content_can_be_opted_in() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obj");
        std::fs::write(&path, b"BENIGN").unwrap();
        let mut o = Oracle::new(OracleDecl { content: true });
        o.watch(&path);
        let before = o.snapshot();
        std::fs::write(&path, b"CHANGED").unwrap();
        assert_eq!(before.diff(&o.snapshot()).len(), 1);
    }

    #[test]
    fn only_watched_paths_are_snapshotted() {
        let (_dir, _path, mut o) = oracle();
        o.watch("/definitely/not/here");
        let m = o.snapshot();
        assert_eq!(m.0.len(), 2, "one real object, one absent");
        assert!(m.0[&PathBuf::from("/definitely/not/here")].is_none());
    }
}
