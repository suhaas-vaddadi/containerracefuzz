// SPDX-License-Identifier: GPL-2.0
//
// The conflict key: the *resolution* chain a path walk takes, not the object
// it ends at, and the conflict relation POS orders events by.
//
// Keying on the resolved object makes an ancestor swap (the attacker rebinds
// `foo` while the victim resolves `foo/bar`) or a dirfd-anchor swap look
// independent of the victim. So a file token is `(anchor, [component...])`:
// the referent the path resolves against, then every traversed component, leaf
// last. Two keys conflict when at least one side rebinds and what it acts on
// lies on the other's resolution path (the leaf, an ancestor, a symlink
// prefix, or the anchor).
//
// Every object is recorded as `(mount id, dev, ino)`, so two bind mounts of one
// filesystem give different keys. The conflict relation compares `(dev, ino)`
// only: a name binding lives in the filesystem, not the mount, so a rename
// through one mount changes what a walk through another sees. Container
// runtimes and their containers see shared objects through different mounts
// (each mount namespace has its own copies), so comparing mount ids would hide
// exactly the cross-boundary races this key exists to order.
//
// Pure: no kernel, runtime or OCI dependency. The walk that fills it is the
// backend's.

/// `(mount id, dev, ino)` of one object as the walk saw it.
pub type ObjId = (u64, u64, u64);

/// One traversed path component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentKey {
    /// The component as written.
    pub name: Vec<u8>,
    /// The directory the name was looked up in.
    pub parent: ObjId,
    /// What the name resolved to, or `None` if it does not exist (yet). The
    /// walk stops at an absent component: nothing past it resolves.
    pub obj: Option<ObjId>,
}

/// A file token: the resolution anchor (the dirfd's object, or the cwd/root
/// for `AT_FDCWD`/absolute paths) and every component walked from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileToken {
    pub anchor: ObjId,
    pub chain: Vec<ComponentKey>,
}

/// An object a resolution touches, as the conflict relation compares it:
/// mount-free, `(dev, ino)`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Obj {
    Inode(u64, u64),
    /// `name` in directory `dir`: what a rebind changes, and the only identity
    /// a not-yet-existing name has.
    Entry { dir: (u64, u64), name: Vec<u8> },
}

fn fs((_mnt, dev, ino): ObjId) -> (u64, u64) {
    (dev, ino)
}

impl ComponentKey {
    fn objects(&self) -> Vec<Obj> {
        let mut out = vec![Obj::Entry {
            dir: fs(self.parent),
            name: self.name.clone(),
        }];
        if let Some(o) = self.obj {
            let (dev, ino) = fs(o);
            out.push(Obj::Inode(dev, ino));
        }
        out
    }
}

impl FileToken {
    fn anchor_obj(&self) -> Obj {
        let (dev, ino) = fs(self.anchor);
        Obj::Inode(dev, ino)
    }

    /// Every object this resolution touches: the anchor, then each component's
    /// entry and what it resolved to.
    fn objects(&self) -> Vec<Obj> {
        let mut out = vec![self.anchor_obj()];
        out.extend(self.chain.iter().flat_map(ComponentKey::objects));
        out
    }

    /// What a rebind of this path acts on: the leaf's entry and object, or the
    /// anchor when the path is the anchor itself.
    fn acts_on(&self) -> Vec<Obj> {
        match self.chain.last() {
            Some(c) => c.objects(),
            None => vec![self.anchor_obj()],
        }
    }
}

/// Which side of POS's read-only relaxation an event's use of a token is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction {
    Resolve,
    Rebind,
}

/// A namespace-tagged object token. Only `File` is captured; the others are
/// reserved so capturing them later is not an event-model change, and they
/// get a payload when they do.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjToken {
    File(FileToken),
    Fd,
    Pid,
    Ipc,
    Socket,
}

/// One token an event touches, and the direction it touches it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConflictKey {
    pub obj: ObjToken,
    pub dir: Direction,
}

impl ConflictKey {
    // ponytail: a mount op (`mount`/`umount`) rebinds only within the mount trees
    // it reaches, so comparing without the mount id over-approximates it across
    // mount namespaces (a redraw too many, never a missed race). Upgrade: a
    // distinct mount-op direction compared on mount id plus propagation peer group
    // (`/proc/<pid>/mountinfo` `shared:`/`master:`), if the extra redraws matter.
    /// At least one side rebinds, and its acted-on objects lie on the other's
    /// resolution path. Two resolves never conflict. Uncaptured namespaces
    /// conflict with nothing.
    pub fn conflicts_with(&self, other: &ConflictKey) -> bool {
        let (ObjToken::File(a), ObjToken::File(b)) = (&self.obj, &other.obj) else {
            return false;
        };
        let on = |x: &FileToken, y: &FileToken| {
            let path = y.objects();
            x.acts_on().iter().any(|o| path.contains(o))
        };
        (self.dir == Direction::Rebind && on(a, b)) || (other.dir == Direction::Rebind && on(b, a))
    }
}

/// Whether any key of one event conflicts with any key of another.
pub fn keys_conflict(a: &[ConflictKey], b: &[ConflictKey]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x.conflicts_with(y)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: ObjId = (1, 10, 1);

    /// A walk from `anchor` through `items`, each looked up in the previous
    /// one; `None` is an absent component, and the chain stops there.
    fn walk(anchor: ObjId, items: &[(&str, Option<ObjId>)]) -> FileToken {
        let mut parent = anchor;
        let mut chain = Vec::new();
        for &(name, obj) in items {
            chain.push(ComponentKey { name: name.into(), parent, obj });
            match obj {
                Some(o) => parent = o,
                None => break,
            }
        }
        FileToken { anchor, chain }
    }

    /// A present component on mount 1 of dev 10.
    fn p(name: &str, ino: u64) -> (&str, Option<ObjId>) {
        (name, Some((1, 10, ino)))
    }

    fn key(t: FileToken, dir: Direction) -> ConflictKey {
        ConflictKey { obj: ObjToken::File(t), dir }
    }

    fn both(a: &ConflictKey, b: &ConflictKey) -> bool {
        let ab = a.conflicts_with(b);
        assert_eq!(ab, b.conflicts_with(a), "conflict is symmetric");
        ab
    }

    use Direction::Rebind;
    use Direction::Resolve;

    #[test]
    fn two_resolves_never_conflict() {
        let t = walk(ROOT, &[p("a", 2), p("f", 3)]);
        assert!(!both(&key(t.clone(), Resolve), &key(t, Resolve)));
    }

    #[test]
    fn a_leaf_rebind_conflicts_with_a_resolve_of_the_leaf() {
        let t = walk(ROOT, &[p("a", 2), p("f", 3)]);
        assert!(both(&key(t.clone(), Rebind), &key(t, Resolve)));
    }

    #[test]
    fn independent_paths_do_not_conflict() {
        let x = walk(ROOT, &[p("x", 2)]);
        let y = walk(ROOT, &[p("y", 3)]);
        assert!(!both(&key(x, Rebind), &key(y, Rebind)));
    }

    #[test]
    fn an_ancestor_rebind_conflicts_with_a_deeper_path() {
        let victim = walk(ROOT, &[p("a", 2), p("b", 3), p("f", 4)]);
        let attacker = walk(ROOT, &[p("a", 2), p("b", 3)]);
        assert!(both(&key(victim, Resolve), &key(attacker, Rebind)));
    }

    #[test]
    fn a_sibling_rebind_does_not_conflict() {
        let victim = walk(ROOT, &[p("a", 2), p("b", 3), p("f", 4)]);
        let attacker = walk(ROOT, &[p("a", 2), p("b", 3), p("g", 9)]);
        assert!(!both(&key(victim, Resolve), &key(attacker, Rebind)));
    }

    #[test]
    fn a_symlink_prefix_rebind_conflicts() {
        // `a/l/f` with `l -> b`: the walk records the link, then splices `b`.
        let victim = walk(ROOT, &[p("a", 2), p("l", 5), p("b", 3), p("f", 4)]);
        let swap_link = walk(ROOT, &[p("a", 2), p("l", 5)]);
        let swap_target = walk(ROOT, &[p("a", 2), p("b", 3)]);
        assert!(both(&key(victim.clone(), Resolve), &key(swap_link, Rebind)));
        assert!(both(&key(victim, Resolve), &key(swap_target, Rebind)));
    }

    #[test]
    fn an_anchor_swap_conflicts() {
        // The victim resolves `../x` from a dirfd on `a/b`; renaming `a/b`
        // changes where `..` lands.
        let b = (1, 10, 3);
        let victim = walk(b, &[("..", Some((1, 10, 2))), p("x", 7)]);
        let attacker = walk(ROOT, &[p("a", 2), ("b", Some(b))]);
        assert!(both(&key(victim, Resolve), &key(attacker, Rebind)));
    }

    #[test]
    fn a_rebind_of_the_anchor_itself_conflicts_with_a_path_through_it() {
        // `umount` of `openat(fd, ".")`: an empty chain acts on the anchor.
        let x = (1, 10, 2);
        let attacker = walk(x, &[]);
        let victim = walk(ROOT, &[("x", Some(x)), p("f", 4)]);
        assert!(both(&key(attacker, Rebind), &key(victim, Resolve)));
    }

    #[test]
    fn an_absent_component_keys_on_its_entry_and_stops_the_chain() {
        let check = walk(ROOT, &[p("a", 2), ("f", None), p("never", 9)]);
        assert_eq!(check.chain.len(), 2, "nothing past an absent name");

        let create = walk(ROOT, &[p("a", 2), ("f", None)]);
        let unlink = walk(ROOT, &[p("a", 2), p("f", 7)]);
        let sibling = walk(ROOT, &[p("a", 2), p("g", 8)]);
        assert!(both(&key(check.clone(), Resolve), &key(create.clone(), Rebind)));
        assert!(both(&key(check, Resolve), &key(unlink, Rebind)));
        assert!(!both(&key(create, Rebind), &key(sibling, Resolve)));
    }

    #[test]
    fn bind_mounts_give_different_keys_but_share_conflicts() {
        // `/x` bind-mounted at `/y`: one directory (dev 10, ino 2) seen
        // through mounts 1 and 2.
        let via_x = walk(ROOT, &[p("x", 2), p("f", 4)]);
        let via_y = walk(ROOT, &[("y", Some((2, 10, 2))), ("f", Some((2, 10, 4)))]);
        assert_ne!(via_x, via_y, "the mount id separates the keys");
        assert!(
            both(&key(via_x, Rebind), &key(via_y, Resolve)),
            "a rename through one mount changes the other's walk"
        );
    }

    #[test]
    fn uncaptured_namespaces_conflict_with_nothing() {
        let f = key(walk(ROOT, &[p("f", 2)]), Rebind);
        let fd = ConflictKey { obj: ObjToken::Fd, dir: Rebind };
        assert!(!both(&f, &fd));
        assert!(!both(&fd, &fd.clone()));
    }

    #[test]
    fn an_event_conflicts_if_any_of_its_keys_do() {
        let rename = [
            key(walk(ROOT, &[p("src", 2)]), Rebind),
            key(walk(ROOT, &[("dst", None)]), Rebind),
        ];
        let open_dst = [key(walk(ROOT, &[("dst", None)]), Resolve)];
        let open_other = [key(walk(ROOT, &[p("other", 5)]), Resolve)];
        assert!(keys_conflict(&rename, &open_dst));
        assert!(!keys_conflict(&rename, &open_other));
    }
}
