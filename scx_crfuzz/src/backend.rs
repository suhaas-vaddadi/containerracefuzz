//! GateBackend: park SUT threads at watched syscalls (seccomp user-notify) and
//! stop the whole SUT tree with the gate (spec §3.3, L:Seccomp, L:Gate).

use crate::pos::{Key, Keys};
use anyhow::{bail, Context, Result};
use scx_crfuzz_gate::GateMap;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::Error;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const SCHED_EXT: i32 = 7;

/// Syscalls that create a task; always watched, to name threads (D4).
#[cfg(target_arch = "aarch64")]
const CLONES: &[i64] = &[libc::SYS_clone, libc::SYS_clone3];
#[cfg(target_arch = "x86_64")]
const CLONES: &[i64] = &[libc::SYS_clone, libc::SYS_clone3, libc::SYS_fork, libc::SYS_vfork];
/// A released clone with no child in the cgroup by then failed.
const CLONE_WAIT: Duration = Duration::from_millis(100);
const CGROUP_ROOT: &str = "/sys/fs/cgroup/crfuzz";

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;

/// One syscall held by seccomp-notify.
#[derive(Debug, Clone)]
pub struct Event {
    /// Seccomp notification id.
    pub id: u64,
    pub tid: u32,
    pub tgid: u32,
    /// The thread's place in the creation tree (D4): the root is `0`, the
    /// k-th task a thread creates is `<its name>/k`. `?<tid>` if unknown.
    pub thread: String,
    pub nr: i64,
    /// Best-effort: a running sibling can rewrite it after the read.
    pub path: Option<PathBuf>,
    /// Conflict keys (D3); as best-effort as `path`.
    pub keys: Keys,
}

#[derive(Debug)]
pub enum Poll {
    Events(Vec<Event>),
    Idle,
    /// Every task carrying the filter is gone.
    Closed,
}

pub struct GateBackend {
    gate: GateMap,
    child: Child,
    notify: OwnedFd,
    cgroup: PathBuf,
    tree_gated: BTreeSet<u32>,
    /// tid -> (name, tasks it has created so far).
    names: HashMap<u32, (String, u32)>,
    /// Held clones, (notification id, parent tid), released one at a time.
    clones: VecDeque<(u64, u32)>,
    /// The released clone: its child's name (None: unknown parent), the
    /// cgroup's tids before, released at.
    in_flight: Option<(Option<String>, BTreeSet<u32>, Instant)>,
}

impl GateBackend {
    /// Spawn `cmd` as the SUT: in the run cgroup, enrolled in SCHED_EXT, with
    /// `watched` syscalls trapping to us. Fails if the gate daemon isn't up
    /// (never fall back to seccomp-only: L:Gate).
    pub fn spawn(mut cmd: Command, watched: &[i64]) -> Result<Self> {
        let exec_watched = watched.contains(&libc::SYS_execve);
        let watched: Vec<i64> = CLONES.iter().chain(watched).copied().collect::<BTreeSet<_>>().into_iter().collect();
        // A bare name makes execvp try one execve per PATH entry, and we can't
        // tell which try will succeed, so the helper below can't stop on it.
        if exec_watched && !cmd.get_program().as_bytes().contains(&b'/') {
            bail!("watching execve needs a program path, not a bare name: {:?}", cmd.get_program());
        }
        let gate = GateMap::open()?;
        let cgroup = PathBuf::from(format!("{CGROUP_ROOT}/run-{}", gate.epoch));
        fs::create_dir_all(&cgroup).with_context(|| cgroup.display().to_string())?;
        let procs = File::options().write(true).open(cgroup.join("cgroup.procs"))?;
        let filter = notify_filter(&watched);

        let mut socks = [0; 2];
        let flags = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
        if unsafe { libc::socketpair(libc::AF_UNIX, flags, 0, socks.as_mut_ptr()) } < 0 {
            return Err(Error::last_os_error().into());
        }
        let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(socks[0]), OwnedFd::from_raw_fd(socks[1])) };
        let (procs_fd, sock_fd) = (procs.as_raw_fd(), theirs.as_raw_fd());

        // Between fork and exec: raw syscalls only, no allocation.
        unsafe {
            cmd.pre_exec(move || {
                // Order matters (L:Seccomp): cgroup first, filter last.
                if libc::write(procs_fd, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(Error::last_os_error());
                }
                let param = libc::sched_param { sched_priority: 0 };
                if libc::sched_setscheduler(0, SCHED_EXT, &param) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(Error::last_os_error());
                }
                let prog = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
                // WAIT_KILLABLE_RECV: once received, a notification yields only
                // to SIGKILL, so a signal can't restart it under a fresh id.
                let fd = libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
                    &prog,
                );
                if fd < 0 {
                    return Err(Error::last_os_error());
                }
                send_fd(sock_fd, fd as RawFd)?;
                libc::close(fd as RawFd);
                Ok(())
            });
        }
        // spawn() returns only once the child's exec completes, and with execve
        // watched that exec traps. Take the listener before spawning and let the
        // child's own exec through: nothing of the SUT has run yet, so it orders
        // against nothing (same as a different starting layout). Later execs trap
        // normally. Closing `theirs` unblocks the helper if the child dies first.
        // ponytail: glibc's ENOEXEC retry via /bin/sh is a second execve, which
        // then traps unanswered; unsupported (give scripts a #!).
        let helper = std::thread::spawn(move || -> Result<OwnedFd> {
            let fd = recv_fd(ours.as_raw_fd()).context("receive seccomp listener")?;
            // Before the child's exec, anything trapped is spawn plumbing.
            if exec_watched {
                loop {
                    let req = notif_recv(fd.as_raw_fd())?;
                    notif_continue(fd.as_raw_fd(), req.id)?;
                    if req.data.nr as i64 == libc::SYS_execve {
                        break;
                    }
                }
            }
            Ok(fd)
        });
        let child = cmd.spawn();
        drop(theirs);
        let notify = helper.join().expect("listener helper panicked");
        let child = child.context("spawn SUT")?;
        let notify = notify?;
        let names = HashMap::from([(child.id(), ("0".into(), 0))]);
        Ok(Self {
            gate,
            child,
            notify,
            cgroup,
            tree_gated: BTreeSet::new(),
            names,
            clones: VecDeque::new(),
            in_flight: None,
        })
    }

    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn gate(&self) -> &GateMap {
        &self.gate
    }

    /// The run cgroup; the SUT tree lives in it and its children.
    pub fn cgroup(&self) -> &Path {
        &self.cgroup
    }

    /// A clone is held or awaiting its child. Its parent reads as asleep, but
    /// its next syscall isn't in the frontier yet.
    pub fn clones_pending(&self) -> bool {
        !self.clones.is_empty() || self.in_flight.is_some()
    }

    /// Tgids currently gated by `gate_tree`.
    pub fn tree(&self) -> &BTreeSet<u32> {
        &self.tree_gated
    }

    /// Wait up to `timeout` for held syscalls; returns every one ready now.
    /// Clones never show up: they touch no path, so they conflict with
    /// nothing and are released here, one at a time to name the child (D4).
    pub fn poll(&mut self, timeout: Duration) -> Result<Poll> {
        self.advance_clones()?;
        let mut events = Vec::new();
        // While a clone is in flight, come back soon to attribute its child.
        let mut wait = if self.in_flight.is_some() { 1 } else { timeout.as_millis() as i32 };
        loop {
            let mut pfd = libc::pollfd { fd: self.notify.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut pfd, 1, wait) } < 0 {
                let e = Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e.into());
            }
            if pfd.revents & libc::POLLIN != 0 {
                match self.recv() {
                    Ok(ev) => events.extend(ev),
                    // Received ids exist nowhere else: hand them back, or their
                    // threads stay parked for good. The error resurfaces next call.
                    Err(_) if !events.is_empty() => break,
                    Err(e) => return Err(e),
                }
                wait = 0;
                continue;
            }
            // POLLHUP stays set forever once the tree is gone: report it, don't spin.
            if pfd.revents & libc::POLLHUP != 0 && events.is_empty() {
                return Ok(Poll::Closed);
            }
            break;
        }
        self.advance_clones()?;
        Ok(if events.is_empty() { Poll::Idle } else { Poll::Events(events) })
    }

    /// Attribute the in-flight clone's child, then release the next held clone.
    fn advance_clones(&mut self) -> Result<()> {
        loop {
            if let Some((name, before, at)) = &self.in_flight {
                let new: Vec<u32> = self.cgroup_ids("cgroup.threads")?.difference(before).copied().collect();
                match new[..] {
                    [] if at.elapsed() < CLONE_WAIT => return Ok(()),
                    // Unknown parent: the child stays unknown too.
                    [child] => {
                        if let Some(name) = name {
                            self.names.insert(child, (name.clone(), 0));
                        }
                    }
                    // [] past CLONE_WAIT: failed, or the child already exited.
                    // Several: only clones make tasks and all are held, so
                    // none; leave them unnamed rather than guess.
                    // ponytail: a child that shows up after CLONE_WAIT lands
                    // in the next clone's window and, if that clone's child
                    // never shows, takes its name; track unseen clones if
                    // parents stall that long.
                    _ => {}
                }
                self.in_flight = None;
            }
            let Some((id, parent)) = self.clones.pop_front() else { return Ok(()) };
            let before = self.cgroup_ids("cgroup.threads")?;
            // A dead thread's tid can be reused by a new one; drop its name so
            // the newcomer never inherits it.
            self.names.retain(|t, _| before.contains(t));
            match notif_continue(self.notify.as_raw_fd(), id) {
                // The index counts clone attempts, child seen or not, so a
                // child that exits before we look still uses its index (D4).
                Ok(()) => {
                    let name = self.names.get_mut(&parent).map(|(name, kids)| {
                        *kids += 1;
                        format!("{name}/{}", *kids - 1)
                    });
                    self.in_flight = Some((name, before, Instant::now()));
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {} // parent died while held
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn recv(&mut self) -> Result<Option<Event>> {
        let req = match notif_recv(self.notify.as_raw_fd()) {
            Ok(req) => req,
            // ENOENT: the task died between poll and recv.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let (tid, nr) = (req.pid, req.data.nr as i64);
        if CLONES.contains(&nr) {
            self.clones.push_back((req.id, tid));
            return Ok(None);
        }
        // A child of the in-flight clone can trap before we've seen it appear.
        // Don't fail here: req.id exists nowhere else, so its thread would
        // stay parked for good. The error resurfaces at the next poll.
        if !self.names.contains_key(&tid) {
            let _ = self.advance_clones();
        }
        let (path, keys) = observe(tid, nr, &req.data.args);
        let tgid = read_tgid(tid);
        // Only a still-valid id proves tid and bytes belonged to the notifying
        // task (it may have died and its tid been reused).
        if !self.id_valid(req.id) {
            return Ok(None);
        }
        let thread = self.names.get(&tid).map_or_else(|| format!("?{tid}"), |n| n.0.clone());
        Ok(Some(Event { id: req.id, tid, tgid: tgid?, thread, nr, path, keys }))
    }

    fn id_valid(&self, id: u64) -> bool {
        unsafe { libc::ioctl(self.notify.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_ID_VALID as _, &id) == 0 }
    }

    /// Let a held syscall run as issued. Under a tree hold the thread stays
    /// gated until `ungate_tree`; answering first means a signal can't restart
    /// the syscall mid-release (L:Gate).
    pub fn release(&mut self, ev: &Event) -> Result<()> {
        // A non-leader's execve takes over the leader's tid.
        // ponytail: moved on release, so a failed execve misnames both;
        // move it once the old tid is gone if that matters.
        if ev.nr == libc::SYS_execve && ev.tid != ev.tgid {
            if let Some(n) = self.names.remove(&ev.tid) {
                self.names.insert(ev.tgid, n);
            }
        }
        match notif_continue(self.notify.as_raw_fd(), ev.id) {
            Err(e) if e.raw_os_error() != Some(libc::ENOENT) => Err(e.into()),
            _ => Ok(()), // ENOENT: task died while held
        }
    }

    /// Gate every process in the SUT tree (L:Seccomp: runc and runc init are
    /// two tgids), child cgroups included (runc init moves into the
    /// container's, placed under ours: §3.4). A gated process can't fork, so re-reading the cgroup until
    /// no new tgid shows up catches children forked mid-sweep.
    // ponytail: a tgid forking in the kick's IPI latency after the final read
    // escapes; same residual window as L:Gate's, close it with Gate phase 2.
    pub fn gate_tree(&mut self) -> Result<()> {
        loop {
            let new: Vec<u32> = self.cgroup_ids("cgroup.procs")?.into_iter().filter(|t| !self.tree_gated.contains(t)).collect();
            if new.is_empty() {
                return Ok(());
            }
            for t in new {
                self.gate.gate_tgid(t)?;
                self.tree_gated.insert(t);
            }
            self.gate.kick()?;
        }
    }

    pub fn ungate_tree(&mut self) -> Result<()> {
        for t in std::mem::take(&mut self.tree_gated) {
            self.gate.ungate_tgid(t)?;
        }
        self.gate.kick()?;
        Ok(())
    }

    /// Tgids (`cgroup.procs`) or tids (`cgroup.threads`) of the SUT tree. Each
    /// lists only its own cgroup's members, so read every cgroup in the subtree.
    fn cgroup_ids(&self, file: &str) -> Result<BTreeSet<u32>> {
        let mut ids = BTreeSet::new();
        for dir in cgroup_dirs(&self.cgroup) {
            match fs::read_to_string(dir.join(file)) {
                Ok(list) => ids.extend(list.lines().filter_map(|l| l.parse::<u32>().ok())),
                // A child cgroup removed mid-walk had no members left.
                Err(e) if dir != self.cgroup && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(ids)
    }
}

impl Drop for GateBackend {
    fn drop(&mut self) {
        // Ungate before killing: a gated task can't run to act on SIGKILL, and
        // would stall into the 30 s watchdog (L:Gate).
        let _ = self.gate.clear();
        let _ = fs::write(self.cgroup.join("cgroup.kill"), "1");
        let _ = self.child.wait();
        // Reparented descendants are reaped by init; wait for the cgroups to
        // drain. Children first: a cgroup with child cgroups can't be removed.
        for _ in 0..100 {
            for dir in cgroup_dirs(&self.cgroup).iter().rev() {
                let _ = fs::remove_dir(dir);
            }
            if !self.cgroup.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn notif_recv(fd: RawFd) -> std::io::Result<libc::seccomp_notif> {
    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV as _, &mut req) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(req)
}

/// Let the held syscall run as issued.
fn notif_continue(fd: RawFd, id: u64) -> std::io::Result<()> {
    let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
    resp.id = id;
    resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
    if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND as _, &mut resp) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// `root` and every cgroup below it, parents before children.
pub(crate) fn cgroup_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        if let Ok(rd) = fs::read_dir(&dirs[i]) {
            dirs.extend(rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()));
        }
        i += 1;
    }
    dirs
}

/// Classic BPF: USER_NOTIF for `watched` syscalls on our arch, ALLOW otherwise.
// ponytail: x32 syscall numbers (x86_64 | 0x40000000) are allowed unwatched.
fn notify_filter(watched: &[i64]) -> Vec<libc::sock_filter> {
    assert!(watched.len() < 255, "jump offsets are u8");
    let n = watched.len() as u8;
    let stmt = |code: u32, k: u32| libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let ld = |off| stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, off);
    let ret = |k| stmt(libc::BPF_RET | libc::BPF_K, k);

    // seccomp_data: nr at 0, arch at 4.
    let mut f = vec![ld(4), jeq(AUDIT_ARCH, 0, n + 1), ld(0)];
    for (i, &nr) in watched.iter().enumerate() {
        f.push(jeq(nr as u32, n - i as u8, 0));
    }
    f.push(ret(libc::SECCOMP_RET_ALLOW));
    f.push(ret(libc::SECCOMP_RET_USER_NOTIF));
    f
}

/// Path arguments of syscall `nr`: (dirfd arg, path arg, whether the syscall
/// rebinds that path). The first is the event's path.
fn path_args(nr: i64) -> &'static [(Option<usize>, usize, bool)] {
    match nr {
        libc::SYS_openat
        | libc::SYS_openat2
        | libc::SYS_newfstatat
        | libc::SYS_statx
        | libc::SYS_faccessat
        | libc::SYS_faccessat2
        | libc::SYS_readlinkat
        | libc::SYS_fchmodat
        | libc::SYS_fchownat => &[(Some(0), 1, false)],
        libc::SYS_unlinkat | libc::SYS_mkdirat | libc::SYS_mknodat => &[(Some(0), 1, true)],
        libc::SYS_renameat2 => &[(Some(0), 1, true), (Some(2), 3, true)],
        libc::SYS_linkat => &[(Some(0), 1, false), (Some(2), 3, true)],
        // The target string (arg 0) is stored, not resolved.
        libc::SYS_symlinkat => &[(Some(1), 2, true)],
        libc::SYS_chdir | libc::SYS_execve => &[(None, 0, false)],
        _ => &[],
    }
}

/// The event's path and its conflict keys (D3): every key a path walk passes
/// is read; a rebind writes the final name and object of each path it changes.
fn observe(tid: u32, nr: i64, args: &[u64; 6]) -> (Option<PathBuf>, Keys) {
    let mut k = Keys::default();
    // Undecoded: footprint unknown. chdir moves the base of every relative
    // path in the process, and a multithreaded execve kills the siblings, so
    // either is ordered against everything.
    k.all = matches!(nr, libc::SYS_chdir | libc::SYS_execve) || path_args(nr).is_empty();
    let mut first = None;
    for (i, &(dirfd, arg, rebind)) in path_args(nr).iter().enumerate() {
        let Some(path) = read_cstr(tid, args[arg]) else {
            k.all = true;
            continue;
        };
        let rebind = rebind
            || match nr {
                libc::SYS_openat => args[2] as i32 & libc::O_CREAT != 0,
                // ponytail: openat2's flags sit behind a pointer; assume O_CREAT
                // (over-conflicts, safe). Read open_how if it costs reduction.
                libc::SYS_openat2 => true,
                _ => false,
            };
        match walk(tid, dirfd.map(|d| args[d] as i32), &path, &mut k.reads) {
            Some(tail) if rebind => k.writes.extend(tail),
            Some(_) => {}
            None => k.all = true,
        }
        if i == 0 {
            first = Some(path);
        }
    }
    (first, k)
}

/// Resolve `path` as `tid` would (from its root, cwd, or `dirfd`), adding to
/// `reads` the (dev, ino) of each directory walked and of the target, and each
/// (parent, name) passed, through every symlink met (D3). Returns the final
/// name and object, of the link and of every target it chains to, whatever the
/// flags: `O_CREAT` through a dangling link creates the target's name. None:
/// the walk met a procfs magic link, whose target we can't resolve as tid.
// ponytail: a `..` that climbs above tid's root escapes into our mount
// namespace (the kernel stops it at the root); fine until the SUT runs in its
// own root (runc target), then clamp `..` at the root.
fn walk(tid: u32, dirfd: Option<i32>, path: &Path, reads: &mut BTreeSet<Key>) -> Option<Vec<Key>> {
    let at = PathBuf::from(match dirfd {
        _ if path.is_absolute() => format!("/proc/{tid}/root"),
        Some(fd) if fd != libc::AT_FDCWD => format!("/proc/{tid}/fd/{fd}"),
        _ => format!("/proc/{tid}/cwd"),
    });
    let mut links = 0;
    let tail = walk_at(tid, at, path, reads, &mut links)?.1;
    reads.extend(tail.iter().cloned());
    Some(tail)
}

/// Walk `path` from directory `at`, following each symlink by walking its
/// target (from tid's root if absolute, else from the link's directory), so
/// `at` never passes through a link but the /proc one. Returns where the walk
/// ended (None at a missing component or a loop) and the tail; None for a
/// procfs magic link.
fn walk_at(tid: u32, mut at: PathBuf, path: &Path, reads: &mut BTreeSet<Key>, links: &mut u32) -> Option<(Option<PathBuf>, Vec<Key>)> {
    let Ok(m) = fs::metadata(&at) else { return Some((None, Vec::new())) };
    let mut dir = (m.dev(), m.ino());
    reads.insert(Key::Ino(dir.0, dir.1));
    let names: Vec<_> = path.components().filter(|c| !matches!(c, Component::RootDir | Component::CurDir)).collect();
    let mut tail = Vec::new();
    for (i, c) in names.iter().enumerate() {
        let last = i + 1 == names.len();
        let name = Key::Name(dir.0, dir.1, c.as_os_str().to_os_string());
        reads.insert(name.clone());
        if last {
            tail.push(name);
        }
        at.push(c);
        let Ok(m) = fs::symlink_metadata(&at) else { return Some((None, tail)) };
        if last {
            tail.push(Key::Ino(m.dev(), m.ino()));
        }
        if !m.file_type().is_symlink() {
            dir = (m.dev(), m.ino());
            reads.insert(Key::Ino(dir.0, dir.1));
            continue;
        }
        // The kernel's limit (MAXSYMLINKS); past it the syscall fails ELOOP.
        *links += 1;
        let target = match fs::read_link(&at) {
            Ok(t) if *links <= 40 => proc_link(tid, &at, t)?,
            _ => return Some((None, tail)),
        };
        let from = if target.is_absolute() { PathBuf::from(format!("/proc/{tid}/root")) } else { at.parent().unwrap().into() };
        let (end, t) = walk_at(tid, from, &target, reads, links)?;
        if last {
            tail.extend(t);
        }
        let Some(end) = end else { return Some((None, tail)) };
        let Ok(m) = fs::metadata(&end) else { return Some((None, tail)) };
        dir = (m.dev(), m.ino());
        reads.insert(Key::Ino(dir.0, dir.1));
        at = end;
    }
    Some((Some(at), tail))
}

/// A symlink's target as tid would follow it. procfs links answer for the
/// reader: `self`/`thread-self` name our pid (rewritten to tid's). Any other
/// procfs link counts as magic (None): true of `fd/N`, `cwd`, `exe`, ...;
/// over-conflicts on plain ones like `/proc/mounts` -> `self/mounts`.
// ponytail: tid's ids are taken from its own pid namespace; wrong if the
// procfs mounted at its /proc belongs to another (runc init before it mounts
// the container's /proc).
fn proc_link(tid: u32, at: &Path, target: PathBuf) -> Option<PathBuf> {
    // The link's own filesystem is its directory's: statfs on the link would
    // follow it (/dev/fd is a devtmpfs link into procfs).
    let c = CString::new(at.parent()?.as_os_str().as_bytes()).ok()?;
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 || sf.f_type != libc::PROC_SUPER_MAGIC {
        return Some(target);
    }
    let ns = |key: &str| -> Option<String> {
        let status = fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
        status.lines().find_map(|l| l.strip_prefix(key))?.split_whitespace().last().map(String::from)
    };
    match at.file_name()?.to_str()? {
        "self" => Some(ns("NStgid:")?.into()),
        "thread-self" => Some(format!("{}/task/{}", ns("NStgid:")?, ns("NSpid:")?).into()),
        _ => None,
    }
}

/// NUL-terminated string at `addr` in `tid`'s memory.
fn read_cstr(tid: u32, addr: u64) -> Option<PathBuf> {
    const PAGE: u64 = 4096;
    let mem = File::open(format!("/proc/{tid}/mem")).ok()?;
    let mut out = Vec::new();
    let mut at = addr;
    while out.len() < libc::PATH_MAX as usize {
        let mut buf = [0u8; PAGE as usize];
        // Stop at the page boundary: the next page may be unmapped.
        let room = (PAGE - at % PAGE) as usize;
        let n = mem.read_at(&mut buf[..room], at).ok()?;
        if n == 0 {
            return None;
        }
        if let Some(z) = buf[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..z]);
            return Some(PathBuf::from(OsString::from_vec(out)));
        }
        out.extend_from_slice(&buf[..n]);
        at += n as u64;
    }
    None
}

fn read_tgid(tid: u32) -> Result<u32> {
    let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
    let line = status.lines().find_map(|l| l.strip_prefix("Tgid:")).context("no Tgid")?;
    Ok(line.trim().parse()?)
}

/// Async-signal-safe: runs between fork and exec.
fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    unsafe {
        let mut byte = 0u8;
        let mut iov = libc::iovec { iov_base: (&mut byte as *mut u8).cast(), iov_len: 1 };
        let mut cbuf = [0u64; 4]; // >= CMSG_SPACE(4), aligned
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        (libc::CMSG_DATA(c) as *mut RawFd).write_unaligned(fd);
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<OwnedFd> {
    unsafe {
        let mut byte = 0u8;
        let mut iov = libc::iovec { iov_base: (&mut byte as *mut u8).cast(), iov_len: 1 };
        let mut cbuf = [0u64; 4];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        if libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) <= 0 {
            bail!("SUT exited before handing over its listener: {}", Error::last_os_error());
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            bail!("no fd in SCM_RIGHTS message");
        }
        Ok(OwnedFd::from_raw_fd((libc::CMSG_DATA(c) as *const RawFd).read_unaligned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_jumps_land_on_ret() {
        let f = notify_filter(&[libc::SYS_openat, libc::SYS_unlinkat]);
        let notify = f.len() - 1;
        assert_eq!(f[notify].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(f[notify - 1].k, libc::SECCOMP_RET_ALLOW);
        // Arch mismatch -> ALLOW.
        assert_eq!(2 + f[1].jf as usize, notify - 1);
        // Each watched nr -> NOTIFY; last miss falls through to ALLOW.
        for (i, ins) in f.iter().enumerate().take(notify - 1).skip(3) {
            assert_eq!(i + 1 + ins.jt as usize, notify);
        }
    }

    #[test]
    fn walk_keys() {
        let d = std::env::temp_dir().join(format!("crfuzz_walk_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("a")).unwrap();
        fs::write(d.join("a/f"), "").unwrap();
        std::os::unix::fs::symlink("a", d.join("l")).unwrap();
        let tid = std::process::id();
        let ino = |p: &Path| {
            let m = fs::symlink_metadata(p).unwrap();
            Key::Ino(m.dev(), m.ino())
        };
        let name = |p: &Path, n: &str| {
            let m = fs::metadata(p).unwrap();
            Key::Name(m.dev(), m.ino(), n.into())
        };

        // Through a symlinked dir: the link's name, the dir it points at, the file.
        let mut r = BTreeSet::new();
        let tail = walk(tid, None, &d.join("l/f"), &mut r).unwrap();
        assert!(r.contains(&name(&d, "l")) && r.contains(&ino(&d.join("a"))) && r.contains(&ino(&d.join("a/f"))));
        assert_eq!(tail, vec![name(&d.join("a"), "f"), ino(&d.join("a/f"))]);

        // A rename of `a` writes what the open above read.
        let mut ren = Keys::default();
        ren.writes.extend(walk(tid, None, &d.join("a"), &mut ren.reads).unwrap());
        let open = Keys { reads: r, ..Keys::default() };
        assert!(ren.conflicts(&open));

        // Missing component: stops after its name; a create there writes it.
        let mut r = BTreeSet::new();
        let tail = walk(tid, None, &d.join("a/nope/x"), &mut r).unwrap();
        assert!(r.contains(&name(&d.join("a"), "nope")));
        assert!(!r.iter().any(|k| matches!(k, Key::Name(_, _, n) if n == "x")));
        assert!(tail.is_empty());

        // O_CREAT through a dangling link creates the target's name: a create
        // there and an open of the target must conflict.
        std::os::unix::fs::symlink(d.join("a/new"), d.join("dangle")).unwrap();
        let mut create = Keys::default();
        create.writes.extend(walk(tid, None, &d.join("dangle"), &mut create.reads).unwrap());
        assert!(create.writes.contains(&name(&d.join("a"), "new")));
        let mut open = Keys::default();
        walk(tid, None, &d.join("a/new"), &mut open.reads);
        assert!(create.conflicts(&open));

        // A chain: every link on the way and the final target, from the link's
        // directory for a relative target.
        std::os::unix::fs::symlink("l/f", d.join("l2")).unwrap();
        let mut r = BTreeSet::new();
        let tail = walk(tid, None, &d.join("l2"), &mut r).unwrap();
        assert!(r.contains(&name(&d, "l")) && r.contains(&name(&d, "a")));
        assert_eq!(tail, vec![name(&d, "l2"), ino(&d.join("l2")), name(&d.join("a"), "f"), ino(&d.join("a/f"))]);

        // A loop ends (the syscall would fail ELOOP).
        std::os::unix::fs::symlink("y", d.join("x")).unwrap();
        std::os::unix::fs::symlink("x", d.join("y")).unwrap();
        walk(tid, None, &d.join("x/f"), &mut BTreeSet::new());

        // Relative to a dirfd.
        let dirf = File::open(d.join("a")).unwrap();
        let mut r = BTreeSet::new();
        let tail = walk(tid, Some(dirf.as_raw_fd()), Path::new("f"), &mut r).unwrap();
        assert_eq!(tail, vec![name(&d.join("a"), "f"), ino(&d.join("a/f"))]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn walk_procfs() {
        let ino = |p: &str| {
            let m = fs::metadata(p).unwrap();
            Key::Ino(m.dev(), m.ino())
        };
        // /proc/self as another task resolves to its /proc entry, not ours.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let mut r = BTreeSet::new();
        walk(child.id(), None, Path::new("/proc/self"), &mut r).unwrap();
        assert!(r.contains(&ino(&format!("/proc/{}", child.id()))));
        assert!(!r.contains(&ino(&format!("/proc/{}", std::process::id()))));
        child.kill().unwrap();
        child.wait().unwrap();
        // /dev/stdin -> /proc/self/fd/0: a magic link, footprint unknown.
        assert!(walk(std::process::id(), None, Path::new("/dev/stdin"), &mut BTreeSet::new()).is_none());
    }

    #[test]
    fn observe_keys() {
        let d = std::env::temp_dir().join(format!("crfuzz_observe_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("f"), "").unwrap();
        let tid = std::process::id();
        let cs = |p: &Path| CString::new(p.as_os_str().as_bytes()).unwrap();
        let (f, new, tgt) = (cs(&d.join("f")), cs(&d.join("new")), cs(Path::new("anything")));
        let at = libc::AT_FDCWD as u64;
        let name = |n: &str| {
            let m = fs::metadata(&d).unwrap();
            Key::Name(m.dev(), m.ino(), n.into())
        };

        let (path, k) = observe(tid, libc::SYS_chdir, &[f.as_ptr() as u64, 0, 0, 0, 0, 0]);
        assert_eq!(path.as_deref(), Some(d.join("f").as_path()));
        assert!(k.all, "chdir orders against everything");
        assert!(observe(tid, libc::SYS_clone, &[0; 6]).1.all, "undecoded");

        // symlinkat(target, dirfd, linkpath): writes the link's name, never resolves the target.
        let (path, k) = observe(tid, libc::SYS_symlinkat, &[tgt.as_ptr() as u64, at, new.as_ptr() as u64, 0, 0, 0]);
        assert_eq!(path.as_deref(), Some(d.join("new").as_path()));
        assert!(!k.all && k.writes.contains(&name("new")));
        assert!(!k.reads.iter().any(|k| matches!(k, Key::Name(_, _, n) if n == "anything")));

        // linkat(olddirfd, old, newdirfd, new): reads old, writes new.
        let (_, k) = observe(tid, libc::SYS_linkat, &[at, f.as_ptr() as u64, at, new.as_ptr() as u64, 0, 0]);
        assert!(k.reads.contains(&name("f")) && !k.writes.contains(&name("f")));
        assert!(k.writes.contains(&name("new")));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn reads_own_cstr() {
        let s = b"/some/path\0";
        let got = read_cstr(std::process::id(), s.as_ptr() as u64).unwrap();
        assert_eq!(got, Path::new("/some/path"));
    }
}
