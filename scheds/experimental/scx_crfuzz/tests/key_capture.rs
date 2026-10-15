// SPDX-License-Identifier: GPL-2.0
//
// The resolution key an `openat` hit is captured with: the chain the walk
// takes from the target's own root, cwd or dirfd, resolved by the kernel.
//
// One target script opens every case in turn, each under a distinct leaf name
// the test finds its hit by. One test per binary on purpose: `reap` calls
// `waitpid(None)`, which is process-wide. See tests/exit_observation.rs.
//
// Requires root (the seccomp listener, bind mounts, chroot, a pid namespace)
// and Linux, with a static busybox at /usr/bin/busybox.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::key::ConflictKey;
use scx_crfuzz::key::Direction;
use scx_crfuzz::key::FileToken;
use scx_crfuzz::key::ObjId;
use scx_crfuzz::key::ObjToken;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

const BUSYBOX: &str = "/usr/bin/busybox";

/// `(mount id, dev, ino)` of `p` as this process sees it.
fn id(p: &Path) -> ObjId {
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: an all-zero statx is a valid out-buffer.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_INO | libc::STATX_MNT_ID;
    // SAFETY: `c` is NUL-terminated and `sx` is a valid buffer.
    let r = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            mask,
            &mut sx,
        )
    };
    assert_eq!(r, 0, "statx {}", p.display());
    (
        sx.stx_mnt_id,
        libc::makedev(sx.stx_dev_major, sx.stx_dev_minor),
        sx.stx_ino,
    )
}

fn fs((_, dev, ino): ObjId) -> (u64, u64) {
    (dev, ino)
}

/// Lazily unmounts the bind mount when the test ends, pass or fail, so the
/// tempdir can be removed.
struct Unmount(PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg("-l").arg(&self.0).status();
    }
}

fn token(k: &ConflictKey) -> &FileToken {
    let ObjToken::File(t) = &k.obj else {
        panic!("capture is file-only")
    };
    t
}

/// A hit as captured: who, the path as written, its keys.
type Hit = (i32, Option<PathBuf>, Vec<ConflictKey>);

/// The token of the one hit whose chain passes through a component `name`.
fn hit<'a>(hits: &'a [Hit], name: &str) -> &'a FileToken {
    let found: Vec<_> = hits
        .iter()
        .flat_map(|(_, _, keys)| keys.iter().map(token))
        .filter(|t| t.chain.iter().any(|c| c.name == name.as_bytes()))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one hit walks through `{name}`: {hits:#?}"
    );
    found[0]
}

fn leaf(t: &FileToken) -> ObjId {
    t.chain.last().and_then(|c| c.obj).expect("a resolved leaf")
}

#[test]
fn an_openat_hit_keys_on_the_chain_the_target_walks() {
    if skip_unless_root("an_openat_hit_keys_on_the_chain_the_target_walks") {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let t = dir.path().canonicalize().unwrap();
    let tp = t.display();
    for d in ["a/b", "src", "dst", "root"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    for f in [
        "a/b/nested",
        "indep",
        "a/b/viafd",
        "a/b/viarel",
        "a/b/viaabs",
        "nullmark",
        "a/b/inns",
        "src/bound",
        "root/marker",
        "marker",
    ] {
        std::fs::write(t.join(f), f).unwrap();
    }
    std::fs::copy(BUSYBOX, t.join("root/busybox")).unwrap();
    let ok = Command::new("mount")
        .arg("--bind")
        .arg(t.join("src"))
        .arg(t.join("dst"))
        .status()
        .unwrap();
    assert!(ok.success(), "bind mount");
    let _unmount = Unmount(t.join("dst"));
    std::os::unix::fs::symlink("a/b", t.join("rel")).unwrap();
    std::os::unix::fs::symlink(t.join("a"), t.join("abs")).unwrap();

    // Inside a new pid namespace with its own /proc, which the engine's pid
    // is not in: `self` must still name the target.
    std::fs::write(
        t.join("inner.sh"),
        format!("exec 3<{tp}/a/b\nexec {BUSYBOX} cat /proc/self/fd/3/inns\n"),
    )
    .unwrap();
    // `openat(AT_FDCWD, NULL, 0)`: a missing path argument. Python's next
    // openat after opening `nullmark` is this one: nothing between opens a file.
    std::fs::write(
        t.join("null.py"),
        format!(
            "import ctypes, os, platform\n\
             nr = {{'aarch64': 56, 'x86_64': 257}}[platform.machine()]\n\
             libc = ctypes.CDLL(None)\n\
             os.open('{tp}/nullmark', os.O_RDONLY)\n\
             libc.syscall(nr, -100, None, 0)\n"
        ),
    )
    .unwrap();
    std::fs::write(
        t.join("main.sh"),
        format!(
            "B={BUSYBOX}\n\
             $B cat {tp}/a/b/nested\n\
             $B cat {tp}/indep\n\
             $B cat {tp}/a/missing/gone\n\
             exec 3<{tp}/a\n\
             $B cat /proc/self/fd/3/b/viafd\n\
             exec 3<&-\n\
             $B cat {tp}/dst/bound\n\
             $B cat {tp}/rel/viarel\n\
             $B cat {tp}/abs/b/viaabs\n\
             /usr/bin/chroot {tp}/root /busybox cat /../marker\n\
             /usr/bin/unshare -pf --mount-proc $B sh {tp}/inner.sh\n\
             /usr/bin/python3 -I {tp}/null.py\n\
             exit 0\n"
        ),
    )
    .unwrap();

    let spec =
        scx_crfuzz::backend_seccomp::ProcessSpec::parse(&format!("{BUSYBOX} sh {tp}/main.sh"))
            .expect("spec");
    let mut backend =
        scx_crfuzz::backend_seccomp::SeccompNotifyBackend::new(vec![spec], "/crfuzz/keycapture");
    backend
        .attach(&[CheckpointDecl::syscall("openat")])
        .expect("attach");

    let mut hits = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "the target did not finish");
        match backend.poll().expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {}
            Poll::Events(events) => {
                for e in events {
                    if let BackendEvent::CheckpointHit {
                        pid,
                        handle,
                        path,
                        keys,
                        ..
                    } = e
                    {
                        hits.push((pid, path, keys));
                        backend.release(handle).expect("release");
                    }
                }
            }
        }
    }

    // The full prefix, not just the leaf: every component from the target's
    // root, each keyed on what this process sees at that prefix.
    let nested = hit(&hits, "nested");
    assert_eq!(nested.anchor, id(Path::new("/")));
    let want = t.join("a/b/nested");
    let prefixes: Vec<_> = want.ancestors().filter(|p| p.parent().is_some()).collect();
    assert_eq!(nested.chain.len(), prefixes.len(), "{nested:#?}");
    for (c, p) in nested.chain.iter().zip(prefixes.iter().rev()) {
        assert_eq!(c.name, p.file_name().unwrap().as_bytes());
        assert_eq!(c.obj, Some(id(p)), "component {}", p.display());
    }

    // Two independent paths.
    let indep = hit(&hits, "indep");
    assert_ne!(indep, nested);
    assert_ne!(leaf(indep), leaf(nested));

    // An absent component records its entry and stops the chain.
    let missing = hit(&hits, "missing");
    let last = missing.chain.last().unwrap();
    assert_eq!(last.name, b"missing");
    assert_eq!(last.obj, None);
    assert_eq!(last.parent, id(&t.join("a")));

    // Through the target's `/proc/self/fd/3`: the target's directory, not
    // whatever this process has at fd 3.
    let viafd = hit(&hits, "viafd");
    assert!(viafd
        .chain
        .iter()
        .any(|c| c.name == b"3" && c.obj == Some(id(&t.join("a")))));
    assert_eq!(leaf(viafd), id(&t.join("a/b/viafd")));

    // Through the bind: the same file, on the bind's mount.
    let bound = hit(&hits, "bound");
    assert_eq!(leaf(bound), id(&t.join("dst/bound")));
    assert_ne!(
        leaf(bound).0,
        id(&t.join("src/bound")).0,
        "the mount id separates the bind"
    );

    // `..` at a chrooted target's root stays there, as the kernel does for it.
    let marker = hit(&hits, "marker");
    assert_eq!(marker.anchor, id(&t.join("root")));
    assert_eq!(
        leaf(marker),
        id(&t.join("root/marker")),
        "not the decoy above the root"
    );

    // `self` in a pid namespace's own procfs. The new mount namespace gives
    // every mount a new id, so compare the filesystem object.
    let inns = hit(&hits, "inns");
    assert_eq!(fs(leaf(inns)), fs(id(&t.join("a/b/inns"))));

    // A relative symlink in the prefix: the link's own entry, then its target
    // spliced in, resolved from the link's directory.
    let viarel = hit(&hits, "viarel");
    let rel = viarel.chain.iter().find(|c| c.name == b"rel").unwrap();
    assert_eq!(rel.obj, Some(id(&t.join("rel"))), "keys on the link itself");
    assert_eq!(leaf(viarel), id(&t.join("a/b/viarel")));
    // An absolute one restarts at the target's root.
    let viaabs = hit(&hits, "viaabs");
    assert!(viaabs.chain.iter().any(|c| c.name == b"abs"));
    assert_eq!(leaf(viaabs), id(&t.join("a/b/viaabs")));

    // A NULL path yields no key: python's openat right after `nullmark`.
    let mark = hits
        .iter()
        .position(|(_, p, _)| p.as_deref() == Some(&t.join("nullmark")))
        .expect("python opened nullmark");
    let (null_pid, null_path, null_keys) = hits[mark + 1..]
        .iter()
        .find(|(pid, _, _)| *pid == hits[mark].0)
        .expect("the NULL openat hit");
    assert_eq!((null_path, null_keys.len()), (&None, 0), "pid {null_pid}");
    assert!(hits.iter().all(|(_, p, k)| p.is_some() || k.is_empty()));
    // A plain open resolves.
    assert!(hits
        .iter()
        .flat_map(|(_, _, k)| k)
        .all(|k| k.dir == Direction::Resolve));
}
