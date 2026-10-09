// SPDX-License-Identifier: GPL-2.0
//
// Checkpoints: named points at which a role can be held.
//
// Design doc: Background ("Checkpoint"), and section 4 (placement).

use serde::Deserialize;
use serde::Serialize;
use std::fmt;

/// A checkpoint's declared name, as it appears in `checkpoints[]` and in a
/// window key (`<checkpoint>#<n>`).
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

/// One entry of the scenario's `checkpoints[]` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointDecl {
    pub id: CheckpointId,
    pub kind: CheckpointKind,
    /// What to attach to: a syscall name, a `binary:symbol`, a kernel symbol,
    /// or an LSM hook name, depending on `kind`. Interpreting this is the
    /// backend's job.
    pub target: String,
}

impl CheckpointDecl {
    /// A `syscall` checkpoint named after the syscall it sits on.
    pub fn syscall(name: &str) -> Self {
        CheckpointDecl {
            id: CheckpointId::new(name),
            kind: CheckpointKind::Syscall,
            target: name.to_string(),
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
/// the use, and only those. A check-shaped syscall (`stat`, `readlink`, ...)
/// contributes a hold on the wrong side of the window, so attacking there
/// can only waste a run.
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

/// The default `checkpoints[]`: the whole structural set. Supplying
/// `checkpoints[]` overrides it, which is how a scenario narrows its windows.
pub fn default_checkpoints() -> Vec<CheckpointDecl> {
    STRUCTURAL_SYSCALLS
        .iter()
        .map(|name| CheckpointDecl::syscall(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let set = default_checkpoints();
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
}
