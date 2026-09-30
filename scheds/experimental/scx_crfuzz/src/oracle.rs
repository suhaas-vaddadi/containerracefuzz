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
// `observe` is the first real oracle: it compares the identity of the object at the use path as it was
// just before the attacker acted with its identity just after -- i.e. *did
// anything change the object in the frozen window?* Either a type change (a
// regular file becomes a symlink) or a same-type identity change (a directory
// exchanged for another directory, a file rewritten as another inode). The
// full identity / containment / anchor / integrity battery (attacker
// brainstorm) grows here without touching the engine or the attacker.

use crate::checkpoint::CheckpointId;
use std::path::Path;
use std::path::PathBuf;

/// What the engine hands the oracle about the window it is ruling on.
///
/// Deliberately keyed on the *use* side only: the checkpoint the victim was
/// held at, the path that syscall resolved (when the backend captured it), and
/// the canonical step index of the release, so a finding can be tied back to a
/// replayable log entry.
///
/// `before` and `after` are the object's identity on either side of the
/// attacker's turn: taken while only the attacker could run (the victim is
/// frozen), so any difference is the window's substitution -- not the victim's
/// own syscall, which has not run yet. That matters: a legitimate `mount`
/// changes the object its target resolves to, so a post-use diff would read
/// every mount as a finding.
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
/// to, following nothing, so an attacker swapping a regular file for a symlink
/// shows up as a device/inode/mode change rather than being resolved away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}

impl PathIdentity {
    /// The identity of `path`, or `None` if nothing is there to stat.
    pub fn of(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::symlink_metadata(path).ok()?;
            Some(PathIdentity {
                device: md.dev(),
                inode: md.ino(),
                mode: md.mode(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }

    /// The POSIX file-type bits (`S_IFMT`), the part a leaf substitution most
    /// often flips.
    pub fn file_type(&self) -> u32 {
        self.mode & 0o170000
    }
}

/// The oracle's ruling on one window.
///
/// A richer taxonomy (VIOLATION / TOLERATED / ACTION-FAILED / CRASH, one per
/// invariant battery) is future work; the placeholder needs only "clean" and
/// "something the spec forbids happened".
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

/// The first real oracle: did anything change the object at the use path
/// during the frozen window?
///
/// A check-then-use bug is exactly this: the victim resolved a path, and by the
/// time it used it, the name referred to a different object. The engine hands
/// over the identity on either side of the attacker's turn, so this fires on
/// either a type change (regular file -> symlink) or a same-type identity
/// change (directory -> another directory, file -> another inode). Comparing
/// pre/post *attacker* rather than pre/post *use* is what keeps a legitimate
/// `mount` -- which changes the object its target resolves to -- from reading
/// as a finding: the victim's own syscall has not run when `after` is taken.
pub fn observe(ctx: &WindowContext) -> OracleVerdict {
    let (Some(path), Some(before), Some(after)) = (&ctx.path, &ctx.before, &ctx.after) else {
        // No path captured, or nothing existed on one side of the window:
        // there is no identity to have changed. A `symlinkat` window
        // legitimately starts from "nothing here", so it is not a
        // substitution.
        return OracleVerdict::Clean;
    };
    if before == after {
        return OracleVerdict::Clean;
    }
    let what = if before.file_type() != after.file_type() {
        format!("type {:#o} -> {:#o}", before.mode, after.mode)
    } else {
        format!(
            "identity {}:{} -> {}:{}",
            before.device, before.inode, after.device, after.inode
        )
    };
    OracleVerdict::Violation(format!(
        "`{}` changed under the victim in this window ({what}): the use resolved \
         an object other than the one the check accepted",
        path.display(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_violation_reports_as_one() {
        assert!(OracleVerdict::Violation("mount escaped root".into()).is_violation());
        assert!(!OracleVerdict::Clean.is_violation());
    }

    #[test]
    fn a_type_change_across_the_window_is_a_violation() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let secret = dir.path().join("secret");
        std::fs::write(&target, b"BENIGN").unwrap();
        std::fs::write(&secret, b"SECRET").unwrap();

        // What the check saw: a regular file.
        let before = PathIdentity::of(&target).unwrap();

        // What the attacker left: a symlink in its place.
        std::fs::remove_file(&target).unwrap();
        symlink(&secret, &target).unwrap();
        let after = PathIdentity::of(&target).unwrap();

        let ctx = WindowContext {
            checkpoint: CheckpointId::new("openat"),
            path: Some(target),
            before: Some(before),
            after: Some(after),
            step_idx: 7,
        };
        let verdict = observe(&ctx);
        assert!(
            verdict.is_violation(),
            "type change must fire, got {verdict:?}"
        );
    }

    #[test]
    fn a_same_type_identity_change_is_a_violation() {
        // Directory exchanged for another directory: the type is unchanged,
        // so only the inode tells them apart. This is the case the type-only
        // oracle missed.
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one");
        let two = dir.path().join("two");
        std::fs::create_dir(&one).unwrap();
        std::fs::create_dir(&two).unwrap();

        let before = PathIdentity::of(&one).unwrap();
        let after = PathIdentity::of(&two).unwrap();
        assert_eq!(
            before.file_type(),
            after.file_type(),
            "the test needs two objects of the same type"
        );

        let ctx = WindowContext {
            checkpoint: CheckpointId::new("mount"),
            path: Some(one),
            before: Some(before),
            after: Some(after),
            step_idx: 1,
        };
        let verdict = observe(&ctx);
        assert!(
            verdict.is_violation(),
            "a same-type identity change must fire, got {verdict:?}"
        );
    }

    #[test]
    fn an_unchanged_object_is_clean() {
        // The legitimate case: the attacker did nothing (or only the victim's
        // own syscall will run, which is not part of the window), so the
        // identity is identical on both sides.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"BENIGN").unwrap();
        let before = PathIdentity::of(&target).unwrap();

        let ctx = WindowContext {
            checkpoint: CheckpointId::new("mount"),
            path: Some(target),
            before: Some(before),
            after: Some(before),
            step_idx: 0,
        };
        assert_eq!(observe(&ctx), OracleVerdict::Clean);
    }

    #[test]
    fn a_missing_identity_on_either_side_is_clean() {
        // `symlinkat` creates a name that did not exist; that is not a
        // substitution and must not fire.
        let dir = tempfile::tempdir().unwrap();
        let created = dir.path().join("created");
        std::fs::write(&created, b"x").unwrap();
        let after = PathIdentity::of(&created).unwrap();

        let ctx = WindowContext {
            checkpoint: CheckpointId::new("symlinkat"),
            path: Some(created),
            before: None,
            after: Some(after),
            step_idx: 0,
        };
        assert_eq!(observe(&ctx), OracleVerdict::Clean);
    }
}
