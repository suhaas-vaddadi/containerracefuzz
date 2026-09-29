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
/// Nothing in the engine reads this tag at run time; it is for a human
/// writing up a finding, and for `structural_category`. What it records is
/// not "was this the check or the act in some race" -- section 4.1 is
/// explicit that nobody can know that before the fact -- but a narrower,
/// structural question: *can* this syscall be the resolution that has to see
/// the swapped path? Only `Mutating` syscalls can, which is why only they are
/// in the default set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCategory {
    /// Resolves a path and returns only data -- metadata, a link target, an
    /// access verdict. Check-shaped. Never in the default set (section 4.2):
    /// a hold at its entry lies *before* the check, outside every check-to-use
    /// window. Still declarable by hand, e.g. by a replay schedule that wants
    /// to name the check as a step.
    Resolving,
    /// Resolves a path and acts on, or commits to, what it finds: opens it,
    /// executes it, changes it, mounts it, or keeps it as the cwd or root.
    /// Use-shaped. The only kind that can be the second resolution in a
    /// check-then-use race, and the only kind in the default set.
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

/// The structural syscall set from design doc section 4.2: every syscall that
/// can be the *second* resolution of a path in a check-then-use race.
///
/// The argument, in full in section 4.2: a `syscall` checkpoint holds a
/// thread at syscall *entry*, so it is a decision point just before that
/// syscall runs. A check-then-use race needs one decision point after the
/// check has returned and before the use resolves the path again -- and the
/// use's own entry is exactly that. So the set is the syscalls that can be
/// the use, and only those. A check-shaped syscall (`CHECK_SHAPED_SYSCALLS`)
/// contributes a hold on the wrong side of the window, and every hit on one
/// would only add to the run's decision count `k`.
///
/// Scope, stated so it is a decision and not an accident: this covers races
/// in which the check comes before the use. Races that need a check to run
/// *after* the attacker's change -- verify-after-use (`open(p)` then
/// `lstat(p)`), or two checks that must see different objects -- need
/// checkpoints on check-shaped syscalls too, and are out of scope.
///
/// x86_64 spellings are listed alongside the `*at` forms. The legacy names
/// have no syscall number on aarch64; the backend declines to attach them
/// there and says so (`backend_seccomp`, `oci_preflight`), and the `*at` form
/// covers the same operation.
///
/// Deliberately absent:
/// - fd-only calls (`fchmod`, `fchown`, `ftruncate`, `fchdir`, `fsetxattr`,
///   `read`/`write`): the fd already pins the object, so nothing is resolved
///   again. The use was the call that produced the fd.
/// - `bind`/`connect`: a unix-socket path is resolvable, but seccomp cannot
///   see the address family (it is behind a pointer), so these would also
///   hold every TCP connect. Declare them by hand for a target that needs it.
/// - `fsconfig`: it can carry a path (`FSCONFIG_SET_PATH`), but only as the
///   value for a filesystem that `fsmount` + `move_mount` then attaches, and
///   `move_mount` is here.
/// - `setxattrat`/`removexattrat` (Linux 6.13): too new for the libseccomp
///   this is built against. Section 12's maintenance note covers adding them.
pub const STRUCTURAL_SYSCALLS: &[&str] = &[
    // Open.
    "openat",
    "openat2",
    "open",
    "creat",
    // Execute. The backend lets its own launch exec through unreported
    // (`backend_seccomp`, `poll`); every later exec is a checkpoint.
    "execve",
    "execveat",
    // Directory-entry mutation.
    "mkdirat",
    "unlinkat",
    "renameat",
    "renameat2",
    "linkat",
    "symlinkat",
    "mknodat",
    "mkdir",
    "rmdir",
    "unlink",
    "rename",
    "link",
    "symlink",
    "mknod",
    // Metadata mutation.
    "fchmodat",
    "fchmodat2",
    "fchownat",
    "truncate",
    "setxattr",
    "lsetxattr",
    "removexattr",
    "lremovexattr",
    "utimensat",
    "chmod",
    "chown",
    "lchown",
    "utime",
    "utimes",
    "futimesat",
    // Mount and root.
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "open_tree",
    "move_mount",
    "mount_setattr",
    "fspick",
    // Working directory: it keeps the resolution, and later relative lookups
    // reuse it, so the swap has to land before it just as before an open.
    "chdir",
];

/// Path-resolving syscalls that can only be the *check*: they return data,
/// and any harm is realised by a later syscall that resolves the path again
/// -- which is in `STRUCTURAL_SYSCALLS`.
///
/// Not attached by default (see `STRUCTURAL_SYSCALLS` for why). Listed so a
/// hand-declared checkpoint on one of them still gets its `Resolving` tag,
/// and so the two lists can be checked for overlap.
pub const CHECK_SHAPED_SYSCALLS: &[&str] = &[
    "newfstatat",
    "statx",
    "faccessat",
    "faccessat2",
    "readlinkat",
    "stat",
    "lstat",
    "access",
    "readlink",
];

/// The structural category of a syscall name, if it is a path-touching one
/// this crate knows about.
///
/// `fstatat` is the design doc's spelling; kernels and strace say
/// `newfstatat`. Both get the same answer.
pub fn structural_category(name: &str) -> Option<PathCategory> {
    let name = if name == "fstatat" { "newfstatat" } else { name };
    if STRUCTURAL_SYSCALLS.contains(&name) {
        Some(PathCategory::Mutating)
    } else if CHECK_SHAPED_SYSCALLS.contains(&name) {
        Some(PathCategory::Resolving)
    } else {
        None
    }
}

/// The default `checkpoints[]` for a discovery-mode scenario (section 8).
///
/// Populated so an operator need not type out the whole structural set by
/// hand. The field stays explicit in the schema, though: supplying
/// `checkpoints[]` overrides this entirely, which is how a campaign
/// deliberately narrows its overhead (section 4.4).
pub fn default_discovery_checkpoints() -> Vec<CheckpointDecl> {
    STRUCTURAL_SYSCALLS
        .iter()
        .map(|name| CheckpointDecl {
            id: CheckpointId::new(*name),
            kind: CheckpointKind::Syscall,
            target: (*name).to_string(),
            category: Some(PathCategory::Mutating),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_is_use_shaped_only() {
        let set = default_discovery_checkpoints();
        assert_eq!(set.len(), STRUCTURAL_SYSCALLS.len());
        assert!(set
            .iter()
            .all(|c| c.category == Some(PathCategory::Mutating)));
    }

    #[test]
    fn no_check_shaped_syscall_is_attached_by_default() {
        for name in CHECK_SHAPED_SYSCALLS {
            assert!(
                !STRUCTURAL_SYSCALLS.contains(name),
                "`{name}` is on both lists"
            );
        }
        let set = default_discovery_checkpoints();
        assert!(!set.iter().any(|c| c.target == "fstatat"));
    }

    #[test]
    fn category_lookup_knows_both_lists_and_the_doc_spelling() {
        assert_eq!(structural_category("openat"), Some(PathCategory::Mutating));
        assert_eq!(structural_category("chdir"), Some(PathCategory::Mutating));
        assert_eq!(structural_category("execve"), Some(PathCategory::Mutating));
        assert_eq!(
            structural_category("newfstatat"),
            Some(PathCategory::Resolving)
        );
        assert_eq!(
            structural_category("fstatat"),
            Some(PathCategory::Resolving)
        );
        assert_eq!(structural_category("fchmod"), None);
    }

    /// `umount` was once on this list. It has no syscall number on x86_64 or
    /// aarch64 -- only `umount2` exists -- so a checkpoint on it could never
    /// fire.
    #[test]
    fn umount_is_not_listed() {
        assert!(!STRUCTURAL_SYSCALLS.contains(&"umount"));
        assert!(STRUCTURAL_SYSCALLS.contains(&"umount2"));
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
        assert!(!STRUCTURAL_SYSCALLS.contains(&"exit"));
    }
}
