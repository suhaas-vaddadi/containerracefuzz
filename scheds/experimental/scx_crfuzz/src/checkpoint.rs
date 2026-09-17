// SPDX-License-Identifier: GPL-2.0
//
// Checkpoints: named points at which a role can be held.
//
// Design doc: Background ("Checkpoint"), and section 4 (placement for
// discovery mode).

use serde::Deserialize;
use serde::Serialize;
use std::fmt;

/// A checkpoint's declared name, as it appears in `checkpoints[]`, in a
/// replay schedule's `steps[]`, and in the canonical log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckpointId(pub String);

impl CheckpointId {
    pub fn new(s: impl Into<String>) -> Self {
        CheckpointId(s.into())
    }

    /// The reserved id for the `exit` stop condition.
    ///
    /// A step may name `exit` instead of a checkpoint ("run until the role
    /// naturally exits or blocks" -- Background, "Schedule and the three-phase
    /// state machine"). The engine turns a role's task-exit into a synthetic
    /// ready-set entry carrying this id, so a policy sees one uniform kind of
    /// thing to decide over and does not need a second code path for exits.
    pub fn exit() -> Self {
        CheckpointId::new("exit")
    }

    pub fn is_exit(&self) -> bool {
        self.0 == "exit"
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a checkpoint is attached.
///
/// All four give the same synchronous-holding guarantee by different
/// constructions; see Background, "Checkpoint". The engine never branches on
/// the kind -- attaching is the backend's job (see `backend::CheckpointBackend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    /// seccomp in user-notification mode (`SECCOMP_RET_USER_NOTIF`).
    Syscall,
    /// Userspace probe on a function in the target binary.
    Uprobe,
    /// Kernel probe.
    Kprobe,
    /// LSM hook.
    Lsm,
}

/// Structural category of a path-touching syscall (design doc section 4.2).
///
/// This tag exists *only* so a human writing up a finding can say "these two
/// syscalls were the check and the act". Nothing in the engine reads it, and
/// nothing may start to: section 4.1 is explicit that check-vs-act is not a
/// property of a syscall in isolation (`openat` is either, depending on flags
/// and on what the caller does with the fd), and that the label is assignable
/// only in hindsight. Instrumentation treats both categories identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCategory {
    /// Resolves a path without changing it ("check-shaped" in most known
    /// instances).
    Resolving,
    /// Mutates or commits to a path ("act-shaped" in most known instances).
    Mutating,
}

/// One entry of the scenario's `checkpoints[]` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointDecl {
    pub id: CheckpointId,
    pub kind: CheckpointKind,
    /// What to attach to: a syscall name, a `binary:symbol`, a kernel symbol,
    /// or an LSM hook name, depending on `kind`. Interpreting this is the
    /// backend's job.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<PathCategory>,
}

/// The structural syscall set from design doc section 4.2.
///
/// Chosen by syscall *structure* -- does this call resolve or mutate a
/// filesystem path? -- rather than by semantic role, for the reasons in
/// section 4.1. Bounded to path-touching calls rather than "everything" per
/// section 4.2: a Class A (TOCTOU-on-files) race that touches neither a
/// path-resolving nor a path-mutating syscall on either side is not an
/// instance of the bug class at all, so there is nothing here to miss.
///
/// Known-open boundary questions, deliberately NOT resolved here (section 12,
/// and section 14-E): plain `open` (only the `*at` variants are listed);
/// `link`/`linkat`/`chdir`/`fchdir`; and, more structurally, races that hinge
/// on which directory fd a relative path resolves against (`dirfd` plus
/// `AT_FDCWD`) rather than on the path string itself. Adding these is a design
/// decision the doc has not made, so the scaffold does not make it either.
pub const STRUCTURAL_SYSCALLS: &[(&str, PathCategory)] = &[
    // Path-resolving.
    ("stat", PathCategory::Resolving),
    ("lstat", PathCategory::Resolving),
    ("fstatat", PathCategory::Resolving),
    ("access", PathCategory::Resolving),
    ("faccessat", PathCategory::Resolving),
    ("faccessat2", PathCategory::Resolving),
    ("readlink", PathCategory::Resolving),
    ("readlinkat", PathCategory::Resolving),
    // Path-mutating / path-committing.
    ("mount", PathCategory::Mutating),
    ("umount", PathCategory::Mutating),
    ("umount2", PathCategory::Mutating),
    ("openat", PathCategory::Mutating),
    ("rename", PathCategory::Mutating),
    ("renameat", PathCategory::Mutating),
    ("renameat2", PathCategory::Mutating),
    ("symlink", PathCategory::Mutating),
    ("symlinkat", PathCategory::Mutating),
    ("unlink", PathCategory::Mutating),
    ("unlinkat", PathCategory::Mutating),
    ("mknod", PathCategory::Mutating),
    ("mknodat", PathCategory::Mutating),
];

/// The default `checkpoints[]` for a discovery-mode scenario (section 8).
///
/// Populated so an operator need not type out the whole structural set by
/// hand. The field stays explicit in the schema, though: supplying
/// `checkpoints[]` overrides this entirely, which is how a campaign
/// deliberately narrows its overhead (section 4.4).
pub fn default_discovery_checkpoints() -> Vec<CheckpointDecl> {
    STRUCTURAL_SYSCALLS
        .iter()
        .map(|(name, category)| CheckpointDecl {
            id: CheckpointId::new(*name),
            kind: CheckpointKind::Syscall,
            target: (*name).to_string(),
            category: Some(*category),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_covers_both_structural_categories() {
        let set = default_discovery_checkpoints();
        assert_eq!(set.len(), STRUCTURAL_SYSCALLS.len());
        assert!(set
            .iter()
            .any(|c| c.category == Some(PathCategory::Resolving)));
        assert!(set
            .iter()
            .any(|c| c.category == Some(PathCategory::Mutating)));
    }

    #[test]
    fn default_set_has_unique_ids_and_is_all_syscalls() {
        let set = default_discovery_checkpoints();
        let mut ids: Vec<_> = set.iter().map(|c| c.id.as_str().to_string()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate checkpoint id in default set");
        assert!(set.iter().all(|c| c.kind == CheckpointKind::Syscall));
    }

    #[test]
    fn exit_id_is_reserved_and_recognised() {
        assert!(CheckpointId::exit().is_exit());
        assert!(!CheckpointId::new("openat").is_exit());
        // The reserved id must not collide with a real checkpoint.
        assert!(!STRUCTURAL_SYSCALLS.iter().any(|(n, _)| *n == "exit"));
    }
}
