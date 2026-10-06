// SPDX-License-Identifier: GPL-2.0
//
// POS event identity and conflict keys.
//
// Plan: `docs/superpowers/plans/2026-10-01-crfuzz-pos-policy.md`, section 3.1.
//
// POS (Partial Order Aware Concurrency Sampling, Yuan et al., CAV 2018) reasons
// about *events* and the *objects* they touch. This module fixes both for this
// engine before any policy exists:
//
// - an event's identity is `(actor, checkpoint, occurrence)` -- the nth time
//   this `(actor, checkpoint)` pair has been seen this run, so a syscall hit
//   twice (e.g. `openat` during startup) is two distinct POS events with
//   independent priorities;
// - a conflict key is the *resolution* key, not the resolved inode. Keying on
//   the resolved object makes a `rename`/`symlink` swap look independent --
//   which is exactly the bug POS is here to order -- so the file token is the
//   full resolution chain `(anchor, [component...])`, and two keys
//   conflict when one's acted-on object lies on the other's path (a leaf, an
//   ancestor directory, or a symlink prefix).
//
// The key type is a namespace-tagged union from day one (`Namespace`, `Token`)
// even though only `File` is captured; `docs/brainstorm/pos_discussion.md` §9
// argues the holding mechanism generalises to fd/PID/IPC/socket namespaces for
// free while the oracle does not, so the type is generic early and the capture
// is file-only.

use crate::checkpoint::CheckpointId;
use crate::role::RoleRef;
use std::fmt;
use std::str::FromStr;

/// Stable identity of one POS event within a run.
///
/// `occurrence` is run-history-dependent: two runs can disagree on it once
/// control flow diverges, which is acceptable under the partial-order metric
/// but means byte-identity tests must never be built on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId {
    pub actor: ActorId,
    pub checkpoint: CheckpointId,
    pub occurrence: u32,
}

impl EventId {
    pub fn new(actor: ActorId, checkpoint: CheckpointId, occurrence: u32) -> Self {
        EventId {
            actor,
            checkpoint,
            occurrence,
        }
    }
}

/// The scheduling actor: a role, plus the thread within it for thread-level
/// drivers (`pos`, replay). A policy must never see a raw pid or tid: `thread`
/// is a path assigned by the engine, never a kernel id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActorId {
    pub role: RoleRef,
    pub thread: Option<ThreadPath>,
}

impl ActorId {
    /// The role-level actor: one thread group, the granularity of the first
    /// (role-level) POS pass.
    pub fn role(role: RoleRef) -> Self {
        ActorId { role, thread: None }
    }
}

/// A thread's identity within its thread group: the leader is `t0`, and the
/// n-th thread a thread creates (0-based) extends its creator's path with `n`.
/// Rendered `t0`, `t0.1`, `t0.1.0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadPath(pub Vec<u32>);

impl fmt::Display for ThreadPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.0.iter().map(u32::to_string).collect();
        write!(f, "t{}", parts.join("."))
    }
}

impl FromStr for ThreadPath {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        s.strip_prefix('t')
            .and_then(|rest| rest.split('.').map(|n| n.parse().ok()).collect())
            .map(ThreadPath)
            .ok_or_else(|| format!("`{s}` is not a thread path (e.g. `t0`, `t0.1`)"))
    }
}

/// A kernel-managed namespace an object token belongs to.
///
/// Scope is per-namespace: a path is global (shared mount namespace) while an
/// fd slot is per-process, which is exactly why the namespace is part of the
/// key and not implied by the token's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Namespace {
    File,
    Fd,
    Pid,
    Ipc,
    Socket,
}

/// The namespace-specific payload of an object token. Only `File` is captured.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Token {
    File(FileToken),
}

/// A namespace-tagged conflict token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjToken {
    pub ns: Namespace,
    pub token: Token,
}

impl ObjToken {
    pub fn file(token: FileToken) -> Self {
        ObjToken {
            ns: Namespace::File,
            token: Token::File(token),
        }
    }
}

/// A file token: the *resolution* key, not the resolved inode.
///
/// `(anchor_dev, anchor_ino)` is the referent the path resolves against (the
/// dirfd's object, or the cwd/root for `AT_FDCWD`/absolute paths); `chain` is
/// every traversed component, in resolution order, leaf last.
///
/// The backend walks the path as the target's kernel would, inside the
/// target's root. A followed symlink contributes the link component *and* its
/// target's components, and a name that does not exist (yet) is recorded as an
/// entry with no object. Each component carries the directory it was looked up
/// in, so a rebind is keyed on the directory entry it changes
/// (`Obj::Entry`) as well as on inodes: that catches ancestor and
/// symlink-prefix swaps (brainstorm §11) and a create racing a lookup of the
/// same name, without making siblings conflict.
///
/// `FileToken` and `ConflictKey` are shaped so a VFS-kprobe swap (plan Phase 6)
/// is a backend detail rather than an event-model change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileToken {
    pub anchor_dev: u64,
    pub anchor_ino: u64,
    pub chain: Vec<ComponentKey>,
}

/// One object a path resolution touches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Obj {
    /// An inode.
    Inode(u64, u64),
    /// A directory entry: `name` in directory `dir`. What a rebind changes,
    /// and the only identity a not-yet-existing name has.
    Entry { dir: (u64, u64), name: Vec<u8> },
}

impl FileToken {
    pub fn new(anchor_dev: u64, anchor_ino: u64, chain: Vec<ComponentKey>) -> Self {
        FileToken {
            anchor_dev,
            anchor_ino,
            chain,
        }
    }

    /// A single-leaf resolution key: anchor + one existing component.
    pub fn leaf(
        anchor_dev: u64,
        anchor_ino: u64,
        name: impl Into<Vec<u8>>,
        dev: u64,
        ino: u64,
    ) -> Self {
        FileToken {
            anchor_dev,
            anchor_ino,
            chain: vec![ComponentKey {
                name: name.into(),
                parent: (anchor_dev, anchor_ino),
                obj: Some((dev, ino)),
            }],
        }
    }

    /// Every object this resolution touches: the anchor, and for each
    /// component the directory entry it looked up and what that resolved to.
    pub fn objects(&self) -> Vec<Obj> {
        let mut out = vec![Obj::Inode(self.anchor_dev, self.anchor_ino)];
        for c in &self.chain {
            out.extend(c.objects());
        }
        out
    }

    /// What this event acts on: the last component's entry and object, or
    /// the anchor when the path is the anchor itself.
    pub fn acts_on(&self) -> Vec<Obj> {
        match self.chain.last() {
            Some(c) => c.objects(),
            None => vec![Obj::Inode(self.anchor_dev, self.anchor_ino)],
        }
    }

    /// Whether either side's acted-on objects lie on the other's resolution.
    pub fn shares_resolution(&self, other: &FileToken) -> bool {
        overlaps(&self.acts_on(), &other.objects()) || overlaps(&other.acts_on(), &self.objects())
    }
}

/// One traversed path component: its name, the directory it was looked up in
/// and what it resolved to (`None` if it does not exist yet).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentKey {
    pub name: Vec<u8>,
    /// The directory the name was looked up in, `(dev, ino)`.
    pub parent: (u64, u64),
    /// What the name resolved to, or `None` if it does not exist (yet).
    pub obj: Option<(u64, u64)>,
}

impl ComponentKey {
    fn objects(&self) -> Vec<Obj> {
        let mut out = Vec::with_capacity(2);
        // `..` names no entry anyone can rebind; only where it lands counts.
        if self.name != b".." {
            out.push(Obj::Entry {
                dir: self.parent,
                name: self.name.clone(),
            });
        }
        if let Some((dev, ino)) = self.obj {
            out.push(Obj::Inode(dev, ino));
        }
        out
    }
}

fn overlaps(a: &[Obj], b: &[Obj]) -> bool {
    a.iter().any(|x| b.contains(x))
}

/// Which side of POS's read-only relaxation an event is on.
///
/// Per argument, from `checkpoint::arg_rebinds`. Two resolves never conflict; a rebind against
/// either a resolve or another rebind does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction {
    Resolve,
    Rebind,
}

/// One token an event touches, tagged with the direction it touches it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConflictKey {
    pub obj: ObjToken,
    pub dir: Direction,
}

impl ConflictKey {
    pub fn file(token: FileToken, dir: Direction) -> Self {
        ConflictKey {
            obj: ObjToken::file(token),
            dir,
        }
    }

    pub fn is_rebind(&self) -> bool {
        self.dir == Direction::Rebind
    }

    /// Whether this key conflicts with `other`.
    ///
    /// At least one side must be a rebind (two resolves stay independent, POS's
    /// read-only relaxation), and a rebind conflicts when its acted-on object
    /// lies on the other's resolution path -- the same leaf, an ancestor
    /// directory, or a symlink prefix. See `FileToken::shares_resolution`.
    pub fn conflicts_with(&self, other: &ConflictKey) -> bool {
        let (Token::File(a), Token::File(b)) = (&self.obj.token, &other.obj.token);
        (self.is_rebind() && overlaps(&a.acts_on(), &b.objects()))
            || (other.is_rebind() && overlaps(&b.acts_on(), &a.objects()))
    }
}

/// Whether any key in `a` conflicts with any key in `b`.
pub fn keys_conflict(a: &[ConflictKey], b: &[ConflictKey]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x.conflicts_with(y)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::RoleId;

    fn ft(anchor_ino: u64, leaf: &str) -> FileToken {
        FileToken::leaf(10, anchor_ino, leaf.as_bytes().to_vec(), 10, anchor_ino)
    }

    /// A resolution chain: anchor `(10, 1)` then the named components, each
    /// looked up in the previous one.
    fn chain(items: &[(&str, u64)]) -> FileToken {
        let mut parent = (10, 1);
        let chain = items
            .iter()
            .map(|(name, ino)| {
                let c = ComponentKey {
                    name: name.as_bytes().to_vec(),
                    parent,
                    obj: Some((10, *ino)),
                };
                parent = (10, *ino);
                c
            })
            .collect();
        FileToken::new(10, 1, chain)
    }

    #[test]
    fn two_resolves_do_not_conflict() {
        let a = ConflictKey::file(ft(1, "p"), Direction::Resolve);
        let b = ConflictKey::file(ft(1, "p"), Direction::Resolve);
        assert!(!a.conflicts_with(&b));
    }

    #[test]
    fn a_rebind_conflicts_with_a_resolve_and_with_a_rebind() {
        let r = ConflictKey::file(ft(1, "p"), Direction::Resolve);
        let w = ConflictKey::file(ft(1, "p"), Direction::Rebind);
        assert!(r.conflicts_with(&w));
        assert!(w.conflicts_with(&r));
        assert!(w.conflicts_with(&w));
    }

    fn missing(mut t: FileToken, name: &str) -> FileToken {
        let parent = t
            .chain
            .last()
            .and_then(|c| c.obj)
            .unwrap_or((t.anchor_dev, t.anchor_ino));
        t.chain.push(ComponentKey {
            name: name.into(),
            parent,
            obj: None,
        });
        t
    }

    #[test]
    fn creating_a_name_does_not_conflict_with_a_sibling() {
        let create = ConflictKey::file(missing(chain(&[("a", 2)]), "new"), Direction::Rebind);
        let sibling = ConflictKey::file(chain(&[("a", 2), ("other", 9)]), Direction::Resolve);
        assert!(!create.conflicts_with(&sibling));
    }

    #[test]
    fn a_lookup_of_a_missing_name_conflicts_with_its_later_rebind() {
        let check = ConflictKey::file(missing(chain(&[("a", 2)]), "f"), Direction::Resolve);
        let unlink = ConflictKey::file(chain(&[("a", 2), ("f", 7)]), Direction::Rebind);
        assert!(check.conflicts_with(&unlink));
        assert!(unlink.conflicts_with(&check));
    }

    #[test]
    fn creating_a_name_conflicts_with_a_lookup_of_it() {
        let create = ConflictKey::file(missing(chain(&[("a", 2)]), "x"), Direction::Rebind);
        let lookup = ConflictKey::file(missing(chain(&[("a", 2)]), "x"), Direction::Resolve);
        assert!(create.conflicts_with(&lookup));
    }

    #[test]
    fn different_anchors_do_not_conflict() {
        let a = ConflictKey::file(ft(1, "p"), Direction::Rebind);
        let b = ConflictKey::file(ft(2, "p"), Direction::Rebind);
        assert!(!a.conflicts_with(&b));
    }

    #[test]
    fn a_rebind_of_an_ancestor_conflicts_with_a_deeper_path() {
        // The ancestor/symlink-prefix case: the victim resolves `/a/b/file`,
        // the attacker rebinds `/a/b`. Leaf-only keying missed this.
        let victim = ConflictKey::file(
            chain(&[("a", 2), ("b", 3), ("file", 4)]),
            Direction::Resolve,
        );
        let attacker = ConflictKey::file(chain(&[("a", 2), ("b", 3)]), Direction::Rebind);
        assert!(victim.conflicts_with(&attacker));
        assert!(attacker.conflicts_with(&victim));
    }

    #[test]
    fn a_rebind_of_a_sibling_does_not_conflict() {
        // Sharing an ancestor is not enough: the attacker's acted-on object is
        // not on the victim's path.
        let victim = ConflictKey::file(
            chain(&[("a", 2), ("b", 3), ("file", 4)]),
            Direction::Resolve,
        );
        let attacker = ConflictKey::file(
            chain(&[("a", 2), ("b", 3), ("other", 9)]),
            Direction::Rebind,
        );
        assert!(!victim.conflicts_with(&attacker));
    }

    #[test]
    fn a_rebind_of_the_leaf_conflicts() {
        let victim = ConflictKey::file(
            chain(&[("a", 2), ("b", 3), ("file", 4)]),
            Direction::Resolve,
        );
        let attacker =
            ConflictKey::file(chain(&[("a", 2), ("b", 3), ("file", 4)]), Direction::Rebind);
        assert!(victim.conflicts_with(&attacker));
    }

    #[test]
    fn a_hardlink_alias_conflicts() {
        // The same object (dev 10, ino 4) reached by two different names: the
        // attacker rebinds one name, the victim resolves the other.
        let victim = ConflictKey::file(chain(&[("a", 2), ("one", 4)]), Direction::Resolve);
        let attacker = ConflictKey::file(chain(&[("a", 2), ("two", 4)]), Direction::Rebind);
        assert!(victim.conflicts_with(&attacker));
    }

    #[test]
    fn two_resolves_sharing_an_ancestor_do_not_conflict() {
        let a = ConflictKey::file(chain(&[("a", 2), ("x", 3)]), Direction::Resolve);
        let b = ConflictKey::file(chain(&[("a", 2), ("y", 4)]), Direction::Resolve);
        assert!(!a.conflicts_with(&b));
    }

    #[test]
    fn event_identity_includes_occurrence() {
        let actor = ActorId::role(RoleRef::one(RoleId(0)));
        let a = EventId::new(actor.clone(), CheckpointId::new("openat"), 0);
        let b = EventId::new(actor, CheckpointId::new("openat"), 1);
        assert_ne!(a, b);
        assert!(a < b, "occurrence orders the two hits");
    }

    #[test]
    fn a_thread_path_renders_and_parses_back() {
        for (path, text) in [
            (vec![0], "t0"),
            (vec![0, 1], "t0.1"),
            (vec![0, 1, 0], "t0.1.0"),
        ] {
            assert_eq!(ThreadPath(path.clone()).to_string(), text);
            assert_eq!(text.parse::<ThreadPath>(), Ok(ThreadPath(path)));
        }
        for bad in ["", "t", "0", "t0.", "t.1", "tx", "t-1"] {
            assert!(bad.parse::<ThreadPath>().is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn thread_paths_order_a_creator_before_its_clones_and_their_siblings_after() {
        let p = |v: &[u32]| ThreadPath(v.to_vec());
        assert!(p(&[0]) < p(&[0, 0]));
        assert!(p(&[0, 0]) < p(&[0, 1]));
        assert!(p(&[0, 1, 5]) < p(&[0, 2]));
        assert!(p(&[0, 9]) < p(&[1]));
    }

    #[test]
    fn empty_key_sets_never_conflict() {
        assert!(!keys_conflict(&[], &[]));
        let k = vec![ConflictKey::file(ft(1, "p"), Direction::Rebind)];
        assert!(!keys_conflict(&k, &[]));
        assert!(keys_conflict(&k, &k));
    }
}
