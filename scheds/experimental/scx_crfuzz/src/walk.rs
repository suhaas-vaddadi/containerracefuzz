// SPDX-License-Identifier: GPL-2.0
//
// The resolution walk: the `FileToken` of a held task's path, found by walking
// it one component at a time with `openat(O_PATH|O_NOFOLLOW)` from the task's
// own `/proc/<tid>/{root,cwd,fd/N}`.
//
// Those anchors are magic links into the task's mount namespace, so the kernel
// does mount crossing, `..` and magic links as it would for the task -- no
// string join, no `setns`. Two things the kernel gets wrong for us, because
// the engine and not the task is the one calling `openat`:
//
// - `..` is clamped at the *caller's* root. From a container's root it would
//   climb into the host's bundle directory, so the walk stays put at the
//   task's root itself.
// - procfs `self` and `thread-self` name the reader: the engine, or nothing in
//   a procfs of a pid namespace the engine is not in. The walk rewrites them
//   to the task's own numbers.
//
// A procfs link below the procfs root (`fd/N`, `cwd`, `root`, `exe`) is a
// magic link: its readlink text is display (`pipe:[123]`, `/x (deleted)`, a
// path in another mount namespace), so the kernel follows it instead.
//
// Spec: docs/superpowers/specs/2026-10-14-crfuzz-resolution-key-design.md.

use crate::key::ComponentKey;
use crate::key::FileToken;
use crate::key::ObjId;
use crate::role::Pid;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

/// The kernel's symlink budget for one resolution.
const MAXSYMLINKS: u32 = 40;
/// The inode number of every procfs root.
const PROC_ROOT_INO: u64 = 1;

/// Walk `path` as task `tid` would resolve it against `dirfd` (`None` or
/// `AT_FDCWD` for its cwd; ignored for an absolute path). `follow_final`
/// follows a symlink in the last component.
///
/// The chain stops at an absent component (recorded with no object) and at any
/// other lookup error (a real prefix still conflicts correctly). `None` only
/// when the anchor itself cannot be opened -- the task is gone, or the dirfd
/// is not open.
pub fn file_token(
    tid: Pid,
    dirfd: Option<i32>,
    path: &[u8],
    follow_final: bool,
) -> Option<FileToken> {
    let proc = |rest: &str| {
        open_at(
            libc::AT_FDCWD,
            format!("/proc/{tid}/{rest}").as_bytes(),
            libc::O_PATH,
        )
        .ok()
    };
    let root = proc("root")?;
    let root_id = stat(&root)?.0;
    let mut cursor = match dirfd {
        _ if path.first() == Some(&b'/') => root.try_clone().ok()?,
        None | Some(libc::AT_FDCWD) => proc("cwd")?,
        Some(n) => proc(&format!("fd/{n}"))?,
    };
    let anchor = stat(&cursor)?.0;
    // `link/` and `link/.` follow the link whatever the flags say; `components`
    // drops the `/` and `.` that make the kernel do so.
    let follow_final = follow_final || path.ends_with(b"/") || path.ends_with(b"/.");

    let mut at = anchor;
    let mut todo = components(path);
    let mut chain = Vec::new();
    let mut hops = 0;
    while let Some(mut name) = todo.pop_front() {
        if name == b".." {
            if at == root_id {
                continue;
            }
            let Some((fd, id)) = open_id(cursor.as_raw_fd(), b"..") else {
                break;
            };
            (cursor, at) = (fd, id);
            continue;
        }
        if (name == b"self" || name == b"thread-self") && proc_root(&cursor, at) {
            let Some((tgid, own)) = proc_self(tid, &cursor) else {
                break;
            };
            if name == b"thread-self" {
                todo.push_front(own);
                todo.push_front(b"task".to_vec());
            }
            name = tgid;
        }

        let fd = match open_at(cursor.as_raw_fd(), &name, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(libc::ENOENT) => {
                chain.push(ComponentKey {
                    name,
                    parent: at,
                    obj: None,
                });
                break;
            }
            Err(_) => break,
        };
        let Some((obj, link)) = stat(&fd) else {
            break;
        };
        if !link || (todo.is_empty() && !follow_final) {
            chain.push(ComponentKey {
                name,
                parent: at,
                obj: Some(obj),
            });
            (cursor, at) = (fd, obj);
            continue;
        }
        hops += 1;
        if hops > MAXSYMLINKS {
            chain.push(ComponentKey {
                name,
                parent: at,
                obj: Some(obj),
            });
            break;
        }

        if on_procfs(&cursor) && !proc_root(&cursor, at) {
            // A magic link: the kernel follows it, and the component keys on
            // what it lands on, not on the link's own procfs inode.
            let Some((fd, obj)) = open_id(cursor.as_raw_fd(), &name) else {
                break;
            };
            chain.push(ComponentKey {
                name,
                parent: at,
                obj: Some(obj),
            });
            (cursor, at) = (fd, obj);
            continue;
        }

        let Some(target) = read_link(cursor.as_raw_fd(), &name) else {
            break;
        };
        chain.push(ComponentKey {
            name,
            parent: at,
            obj: Some(obj),
        });
        for c in components(&target).into_iter().rev() {
            todo.push_front(c);
        }
        if target.first() == Some(&b'/') {
            let Ok(fresh) = root.try_clone() else {
                break;
            };
            (cursor, at) = (fresh, root_id);
        }
    }
    Some(FileToken { anchor, chain })
}

/// The components of `path`, without empty ones (`//`, a leading `/`) and `.`.
fn components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|b| *b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(<[u8]>::to_vec)
        .collect()
}

/// `openat(dir, name, flags | O_CLOEXEC)`, or the errno.
fn open_at(dir: RawFd, name: &[u8], flags: i32) -> Result<OwnedFd, i32> {
    let name = CString::new(name).map_err(|_| libc::EINVAL)?;
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    // SAFETY: the kernel just returned this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `(mount id, dev, ino)` of the object `fd` refers to, and whether it is a
/// symlink.
fn stat(fd: &OwnedFd) -> Option<(ObjId, bool)> {
    // SAFETY: an all-zero statx is a valid out-buffer.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_TYPE | libc::STATX_INO | libc::STATX_MNT_ID;
    // SAFETY: the path is a static empty C string and `sx` is a valid buffer.
    if unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            mask,
            &mut sx,
        )
    } != 0
    {
        return None;
    }
    let dev = libc::makedev(sx.stx_dev_major, sx.stx_dev_minor);
    let link = u32::from(sx.stx_mode) & libc::S_IFMT == libc::S_IFLNK;
    Some(((sx.stx_mnt_id, dev, sx.stx_ino), link))
}

/// `O_PATH` (following a final symlink) open of `name` in `dir`, with its id.
fn open_id(dir: RawFd, name: &[u8]) -> Option<(OwnedFd, ObjId)> {
    let fd = open_at(dir, name, libc::O_PATH).ok()?;
    let (id, _) = stat(&fd)?;
    Some((fd, id))
}

fn on_procfs(fd: &OwnedFd) -> bool {
    // SAFETY: an all-zero statfs is a valid out-buffer.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid buffer for the call.
    unsafe {
        libc::fstatfs(fd.as_raw_fd(), &mut st) == 0
            && st.f_type as i64 == libc::PROC_SUPER_MAGIC as i64
    }
}

fn proc_root(fd: &OwnedFd, at: ObjId) -> bool {
    at.2 == PROC_ROOT_INO && on_procfs(fd)
}

/// The target of the symlink `name` in `dir`.
fn read_link(dir: RawFd, name: &[u8]) -> Option<Vec<u8>> {
    let name = CString::new(name).ok()?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `name` is NUL-terminated and `buf` is writable for its length.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// `(tgid, tid)` of task `tid` as the procfs at `proc` numbers them.
///
/// That procfs may belong to any pid namespace on the task's chain -- a
/// `runc init` that has not yet remounted `/proc` still sees the host's -- so
/// each level is tried, and the one whose `<tgid>/status` there carries the
/// same `NStgid` from that level down is the task itself (a pid is unique
/// within its namespace).
fn proc_self(tid: Pid, proc: &OwnedFd) -> Option<(Vec<u8>, Vec<u8>)> {
    let ours = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    let (tgids, tids) = (ns_field(&ours, "NStgid:")?, ns_field(&ours, "NSpid:")?);
    (0..tgids.len()).find_map(|i| {
        let mut theirs = String::new();
        open_at(
            proc.as_raw_fd(),
            format!("{}/status", tgids[i]).as_bytes(),
            libc::O_RDONLY,
        )
        .ok()
        .map(std::fs::File::from)?
        .read_to_string(&mut theirs)
        .ok()?;
        if ns_field(&theirs, "NStgid:")? != tgids[i..] {
            return None;
        }
        Some((
            tgids[i].clone().into_bytes(),
            tids.get(i)?.clone().into_bytes(),
        ))
    })
}

/// The per-namespace pids on a `status` line, outermost first.
fn ns_field(status: &str, field: &str) -> Option<Vec<String>> {
    let line = status.lines().find_map(|l| l.strip_prefix(field))?;
    Some(line.split_whitespace().map(str::to_string).collect())
}
