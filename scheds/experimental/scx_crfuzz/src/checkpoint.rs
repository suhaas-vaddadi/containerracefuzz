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
/// Only `syscall` is implemented. The design doc also names `uprobe`,
/// `kprobe` and `lsm` (Background, "Checkpoint"); add them here with a backend
/// that attaches them, so a config naming one fails at parse time until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    /// seccomp in user-notification mode (`SECCOMP_RET_USER_NOTIF`).
    Syscall,
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

impl CheckpointDecl {
    /// A `syscall` checkpoint named after the syscall it sits on, tagged with
    /// its structural category when it has one.
    pub fn syscall(name: &str) -> Self {
        CheckpointDecl {
            id: CheckpointId::new(name),
            kind: CheckpointKind::Syscall,
            target: name.to_string(),
            category: structural_category(name),
        }
    }
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
/// - `setxattrat`/`removexattrat`, and the check-shaped `getxattrat`/
///   `listxattrat` (Linux 6.13): too new for the libseccomp this is built
///   against. Section 12's maintenance note covers adding them.
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
    "getxattr",
    "lgetxattr",
    "listxattr",
    "llistxattr",
    "statfs",
];

/// The kernel's spelling of a syscall name.
///
/// `fstatat` is the design doc's spelling; libseccomp, the kernel and strace
/// say `newfstatat`, and `fstatat` resolves to nothing on x86_64 or aarch64.
pub fn canonical_syscall(name: &str) -> &str {
    if name == "fstatat" {
        "newfstatat"
    } else {
        name
    }
}

/// The structural category of a syscall name, if it is a path-touching one
/// this crate knows about. Accepts either spelling of `fstatat`.
pub fn structural_category(name: &str) -> Option<PathCategory> {
    let name = canonical_syscall(name);
    if STRUCTURAL_SYSCALLS.contains(&name) {
        Some(PathCategory::Mutating)
    } else if CHECK_SHAPED_SYSCALLS.contains(&name) {
        Some(PathCategory::Resolving)
    } else {
        None
    }
}

/// Which syscall argument holds the primary path a use-shaped syscall resolves.
///
/// The attacker/oracle orchestration hands the attacker "the path the syscall
/// uses" (attacker brainstorm, "The window model"). A `syscall` checkpoint sees
/// the raw register arguments; the path is a userspace pointer in one of them,
/// and which register that is depends on the syscall's signature. This table
/// names the register index (0-based) of the *primary* path for every syscall
/// in `STRUCTURAL_SYSCALLS`.
///
/// "Primary" is a deliberate narrowing: several syscalls carry two paths
/// (`renameat2` old/new, `linkat` old/new, `mount` source/target,
/// `move_mount` from/to). This returns the one the victim is acting *on* -- the
/// object whose identity a check-then-use race turns on -- which is the old /
/// target / from side. Capturing the secondary path is a documented follow-up;
/// for the depth-2, single-path window it is not needed.
///
/// `None` means the syscall resolves no path we can point the attacker at (it
/// should not appear for a `STRUCTURAL_SYSCALLS` name, but the mapping is total
/// so a hand-declared checkpoint on an unlisted syscall degrades to "no path"
/// rather than a wrong register).
pub fn path_arg_index(name: &str) -> Option<usize> {
    let idx = match name {
        // path is the first argument.
        "open" | "creat" | "execve" | "mkdir" | "rmdir" | "unlink" | "rename" | "link"
        | "mknod" | "truncate" | "setxattr" | "lsetxattr" | "removexattr" | "lremovexattr"
        | "chmod" | "chown" | "lchown" | "utime" | "utimes" | "umount2" | "pivot_root"
        | "chroot" | "chdir" => 0,
        // dirfd-relative `*at` forms: path is the second argument.
        "openat" | "openat2" | "execveat" | "mkdirat" | "unlinkat" | "renameat" | "renameat2"
        | "linkat" | "mknodat" | "fchmodat" | "fchmodat2" | "fchownat" | "utimensat"
        | "futimesat" | "open_tree" | "move_mount" | "mount_setattr" | "fspick" => 1,
        // The created name is the third argument; the first is the (unresolved)
        // link contents.
        "symlink" => 1,
        "symlinkat" => 2,
        // `mount(source, target, ...)`: the target is the mount point resolved
        // against the tree the race is on.
        "mount" => 1,
        _ => return None,
    };
    Some(idx)
}

/// Which syscall arguments hold *every* path a syscall resolves, not just the
/// primary one (plan Phase 1).
///
/// The single-path `path_arg_index` exists for the depth-2 `auto_attack` window,
/// which points one attacker at the one object the victim acts on. POS needs
/// all of them: a `renameat2` that moves `old` onto `new` conflicts on both
/// paths, and `mount` source and target are each separately swappable. The
/// result is a slice so the common one-path case stays allocation-free.
///
/// Accepts either spelling of `fstatat`. `&[]` means the syscall resolves no
/// path this crate knows how to name.
pub fn path_arg_indices(name: &str) -> &'static [usize] {
    let name = canonical_syscall(name);
    match name {
        // path is the first argument.
        "open" | "creat" | "execve" | "mkdir" | "rmdir" | "unlink" | "mknod" | "truncate"
        | "setxattr" | "lsetxattr" | "removexattr" | "lremovexattr" | "chmod" | "chown"
        | "lchown" | "utime" | "utimes" | "umount2" | "chroot" | "chdir" => &[0],
        // Legacy two-path forms: (old, new).
        "rename" | "link" => &[0, 1],
        // `symlink(target, linkpath)`: `target` is the link's *contents*, not
        // a path the call resolves.
        "symlink" => &[1],
        // `pivot_root(new_root, put_old)`.
        "pivot_root" => &[0, 1],
        // dirfd-relative `*at` forms: path is the second argument.
        "openat" | "openat2" | "execveat" | "mkdirat" | "unlinkat" | "mknodat" | "fchmodat"
        | "fchmodat2" | "fchownat" | "utimensat" | "futimesat" | "open_tree" | "mount_setattr"
        | "fspick" => &[1],
        // Two-dirfd `*at` forms: (olddirfd, oldpath, newdirfd, newpath).
        "renameat" | "renameat2" | "linkat" => &[1, 3],
        // `symlinkat(target, newdirfd, linkpath)`: as `symlink`.
        "symlinkat" => &[2],
        // `mount(source, target, ...)`: both sides resolve against the tree.
        "mount" => &[0, 1],
        // `move_mount(from_dfd, from_pathname, to_dfd, to_pathname, flags)`.
        "move_mount" => &[1, 3],
        // Check-shaped path-resolving calls (plan Phase 4 attaches these only
        // for `pos`).
        "newfstatat" | "statx" | "faccessat" | "faccessat2" | "readlinkat" => &[1],
        "stat" | "lstat" | "access" | "readlink" | "getxattr" | "lgetxattr" | "listxattr"
        | "llistxattr" | "statfs" => &[0],
        _ => &[],
    }
}

/// `O_CREAT` and `O_TRUNC` (asm-generic; the same on x86_64 and aarch64).
/// Spelled out because this module builds without `libc`.
pub const O_CREAT: u64 = 0o100;
pub const O_TRUNC: u64 = 0o1000;

/// Whether the call *rebinds* the path at `path_arg_indices(name)[slot]`, as
/// opposed to only resolving it. `open_flags` is the open-family flags word
/// (ignored for every other call).
///
/// POS's read-only relaxation depends on this being per argument: a
/// read-only `openat` that is keyed as a rebind conflicts with every other
/// open of the same file and orders events that commute.
pub fn arg_rebinds(name: &str, slot: usize, open_flags: u64) -> bool {
    match canonical_syscall(name) {
        "open" | "openat" | "openat2" => open_flags & (O_CREAT | O_TRUNC) != 0,
        // Running, or entering a directory, resolves a path and binds nothing.
        "execve" | "execveat" | "chdir" | "chroot" => false,
        // The existing name is only resolved; the new one is bound.
        "link" | "linkat" => slot == 1,
        // The source is a device, an fs type or a bind source: resolved only.
        "mount" => slot == 1,
        other => structural_category(other) == Some(PathCategory::Mutating),
    }
}

/// The default `checkpoints[]` for a POS discovery run (plan Phase 4).
///
/// The union of the use-shaped structural set and the check-shaped resolving
/// set. Check-shaped calls were excluded from the depth-2 default because a
/// hold at their entry lies *before* the check, outside every check-to-use
/// window -- but POS does not need check/use labels: it orders a check against
/// a later rebind by conflict key, which is exactly the read-only relaxation.
pub fn default_pos_checkpoints() -> Vec<CheckpointDecl> {
    STRUCTURAL_SYSCALLS
        .iter()
        .chain(CHECK_SHAPED_SYSCALLS.iter())
        .map(|name| CheckpointDecl::syscall(name))
        .collect()
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
        .map(|name| CheckpointDecl::syscall(name))
        .collect()
}

/// Whether `name` follows a symlink in the *last* component of its path.
///
/// Calls that name the entry itself (remove, rename, create, `l*`) do not.
// ponytail: flag-controlled cases (`AT_SYMLINK_NOFOLLOW`, `O_NOFOLLOW`,
// `AT_SYMLINK_FOLLOW` on linkat) use the default; following when the kernel
// would not only adds objects, i.e. more conflicts, never fewer.
pub fn follows_final_symlink(name: &str) -> bool {
    !matches!(
        canonical_syscall(name),
        "unlink" | "unlinkat" | "rmdir" | "rename" | "renameat" | "renameat2"
            | "link" | "linkat" | "symlink" | "symlinkat" | "mkdir" | "mkdirat"
            | "mknod" | "mknodat" | "lstat" | "readlink" | "readlinkat" | "lchown"
            | "lsetxattr" | "lremovexattr" | "lgetxattr" | "llistxattr"
    )
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
    fn pos_holds_every_path_based_check() {
        let pos: Vec<String> = default_pos_checkpoints()
            .into_iter()
            .map(|c| c.target)
            .collect();
        for name in ["getxattr", "lgetxattr", "listxattr", "llistxattr", "statfs"] {
            assert!(pos.iter().any(|t| t == name), "`{name}` is not held under pos");
            assert_eq!(path_arg_indices(name), &[0], "`{name}` keys its path");
            assert!(!arg_rebinds(name, 0, 0), "`{name}` is a check, not a rebind");
        }
        assert!(!default_discovery_checkpoints()
            .iter()
            .any(|c| c.target == "getxattr"));
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
        assert!(follows_final_symlink("umount2"));
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
    fn every_structural_syscall_has_a_primary_path_argument() {
        for name in STRUCTURAL_SYSCALLS {
            assert!(
                path_arg_index(name).is_some(),
                "`{name}` is use-shaped but has no path-argument index"
            );
        }
    }

    #[test]
    fn path_argument_index_matches_the_syscall_signature() {
        assert_eq!(path_arg_index("open"), Some(0));
        assert_eq!(path_arg_index("openat"), Some(1)); // (dirfd, PATH, ...)
        assert_eq!(path_arg_index("execve"), Some(0));
        assert_eq!(path_arg_index("renameat2"), Some(1)); // old path is primary
        assert_eq!(path_arg_index("mount"), Some(1)); // target, not source
        assert_eq!(path_arg_index("symlink"), Some(1)); // linkpath, not target
        assert_eq!(path_arg_index("symlinkat"), Some(2)); // (target, dirfd, LINKPATH)
        assert_eq!(path_arg_index("chdir"), Some(0));
        // A syscall we do not resolve a path for degrades to None.
        assert_eq!(path_arg_index("fchmod"), None);
    }

    #[test]
    fn every_known_path_syscall_has_a_nonempty_index_set() {
        for name in STRUCTURAL_SYSCALLS
            .iter()
            .chain(CHECK_SHAPED_SYSCALLS.iter())
        {
            assert!(
                !path_arg_indices(name).is_empty(),
                "`{name}` has no path-argument index in either set"
            );
        }
        assert!(
            !path_arg_indices("fstatat").is_empty(),
            "the doc spelling works"
        );
        assert!(
            path_arg_indices("fchmod").is_empty(),
            "unknown degrades to no path"
        );
    }

    #[test]
    fn two_path_syscalls_name_both_sides() {
        assert_eq!(path_arg_indices("renameat2").to_vec(), vec![1, 3]);
        assert_eq!(path_arg_indices("linkat").to_vec(), vec![1, 3]);
        assert_eq!(path_arg_indices("mount").to_vec(), vec![0, 1]);
        assert_eq!(path_arg_indices("move_mount").to_vec(), vec![1, 3]);
    }

    #[test]
    fn only_the_arguments_a_call_rebinds_are_rebinds() {
        assert!(!arg_rebinds("openat", 0, 0), "a plain open only resolves");
        assert!(arg_rebinds("openat", 0, O_CREAT));
        assert!(arg_rebinds("openat", 0, O_TRUNC));
        assert!(arg_rebinds("creat", 0, 0));
        assert!(!arg_rebinds("execve", 0, 0));
        assert!(!arg_rebinds("chdir", 0, 0));
        assert!(!arg_rebinds("linkat", 0, 0), "the existing name is only resolved");
        assert!(arg_rebinds("linkat", 1, 0), "the new name is bound");
        assert!(!arg_rebinds("mount", 0, 0), "the source is only resolved");
        assert!(arg_rebinds("mount", 1, 0));
        assert!(arg_rebinds("renameat2", 0, 0) && arg_rebinds("renameat2", 1, 0));
        assert!(!arg_rebinds("newfstatat", 0, 0));
    }

    #[test]
    fn symlink_contents_are_not_a_path_argument() {
        assert_eq!(path_arg_indices("symlinkat").to_vec(), vec![2]);
        assert_eq!(path_arg_indices("symlink").to_vec(), vec![1]);
    }

    #[test]
    fn pos_default_set_is_the_structural_union_check_shaped() {
        let set = default_pos_checkpoints();
        assert_eq!(
            set.len(),
            STRUCTURAL_SYSCALLS.len() + CHECK_SHAPED_SYSCALLS.len()
        );
        assert!(set.iter().any(|c| c.id.as_str() == "openat"));
        assert!(set
            .iter()
            .any(|c| c.id.as_str() == "newfstatat" && c.category == Some(PathCategory::Resolving)));
    }
}
