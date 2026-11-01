//! GateBackend: park SUT threads at watched syscalls (seccomp user-notify) and
//! stop the whole SUT tree with the gate (spec §3.3, L:Seccomp, L:Gate).
//! Becoming alice needs Linux 5.11 (close_range CLOEXEC) and openat2 (5.6);
//! older kernels fail every mutation and probe, so every judged run is invalid.

use crate::oracle::{self, Alice, Canary, Finding};
use crate::pos::{Key, Keys};
use anyhow::{bail, ensure, Context, Result};
use scx_crfuzz_gate::GateMap;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File};
use std::io::{Error, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
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
/// A trapped clone: (parent tid, instruction pointer, args).
type Call = (u32, u64, [u64; 6]);

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
    /// The dirfd a relative `path` resolves from; None: the cwd.
    pub dirfd: Option<i32>,
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
    /// Held clones, (notification id, call), released one at a time.
    clones: VecDeque<(u64, Call)>,
    /// The released clone: its call, its child's name (None: unknown
    /// parent), the cgroup's tids before, released at.
    in_flight: Option<(Call, Option<String>, BTreeSet<u32>, Instant)>,
    /// tid -> its last released clone, until it makes a child seen or the
    /// thread traps anything else: the same call next is that attempt again.
    retry: HashMap<u32, Call>,
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
            retry: HashMap::new(),
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
            if let Some((call, name, before, at)) = &self.in_flight {
                let new: Vec<u32> = self.cgroup_ids("cgroup.threads")?.difference(before).copied().collect();
                if !new.is_empty() {
                    self.retry.remove(&call.0);
                }
                match new[..] {
                    // The parent trapped another clone, so this one returned,
                    // without a child. Move on now: if it's a restart
                    // (ERESTARTNOINTR), holding it for CLONE_WAIT lets the next
                    // signal land too (Go's sysmon sends SIGURG every ~10 ms to
                    // a thread in its raw vfork) and the parent restarts forever.
                    [] if self.clones.iter().any(|c| c.1 .0 == call.0) => {}
                    [] if at.elapsed() < CLONE_WAIT => return Ok(()),
                    // Unknown parent: the child stays unknown too.
                    [child] => {
                        self.retry.remove(&child);
                        if let Some(name) = name {
                            self.names.insert(child, (name.clone(), 0));
                        }
                    }
                    // [] past CLONE_WAIT: failed, or the child already exited.
                    // Several: only clones make tasks and all are held, so
                    // none; leave them unnamed rather than guess.
                    // ponytail: a child that shows up after CLONE_WAIT lands
                    // in the next clone's window and, if that clone's child
                    // never shows, takes its name; and the parent's next
                    // identical clone reads as a redo, so its child reuses this
                    // index. Track unseen clones if parents stall that long.
                    _ => {}
                }
                self.in_flight = None;
            }
            let Some((id, call)) = self.clones.pop_front() else { return Ok(()) };
            let before = self.cgroup_ids("cgroup.threads")?;
            // A dead thread's tid can be reused by a new one; drop its name so
            // the newcomer never inherits it.
            self.names.retain(|t, _| before.contains(t));
            self.retry.retain(|t, _| before.contains(t));
            match notif_continue(self.notify.as_raw_fd(), id) {
                // The index counts clone attempts (D4), so a failed clone still
                // uses its index. A childless clone redone as the parent's very
                // next trap is the same attempt: a signal restart
                // (ERESTARTNOINTR) or a retry (EAGAIN). That is decided by
                // the parent's syscall order, not by when the redo traps, so
                // names stay stable.
                // ponytail: a child that exits before we look reads as no
                // child, so an identical clone right after it (no watched
                // syscall between) shares its index, e.g. a pthread_create
                // loop of short-lived compute threads (glibc's clone3 args
                // repeat; mmap isn't watched); watch exit to see it.
                Ok(()) => {
                    let again = self.retry.insert(call.0, call) == Some(call);
                    let name = self.names.get_mut(&call.0).map(|(name, kids)| {
                        *kids += !again as u32;
                        format!("{name}/{}", *kids - 1)
                    });
                    self.in_flight = Some((call, name, before, Instant::now()));
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
            self.clones.push_back((req.id, (tid, req.data.instruction_pointer, req.data.args)));
            return Ok(None);
        }
        self.retry.remove(&tid);
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
        let dirfd = path_args(nr).first().and_then(|a| a.0).map(|d| req.data.args[d] as i32).filter(|&fd| fd != libc::AT_FDCWD);
        Ok(Some(Event { id: req.id, tid, tgid: tgid?, thread, nr, path, dirfd, keys }))
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
            self.retry.remove(&ev.tgid);
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
        // A clone in flight couldn't run while gated: restart its wait, or a
        // long hold would make it look failed and leave its child unnamed (D4).
        if let Some((_, _, _, at)) = &mut self.in_flight {
            *at = Instant::now();
        }
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

/// Alice's credentials got past the canary gate (§4): the setup is wrong and
/// the run is invalid. Not a primitive failure. Check with
/// `err.is::<SelfCheckFailed>()`.
#[derive(Debug)]
pub struct SelfCheckFailed;

impl std::fmt::Display for SelfCheckFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("self-check: alice's credentials are not stopped by the canary gate")
    }
}

impl std::error::Error for SelfCheckFailed {}

/// The held task's root is a canary entry: the SUT put it there, so no view
/// alice could have starts from it. A primitive failure for the mutator; for
/// the probe, only the handle check judges it (§10.5).
#[derive(Debug)]
pub struct RootInCanary;

impl std::fmt::Display for RootInCanary {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("the held task's root is inside the canary")
    }
}

impl std::error::Error for RootInCanary {}

// No step before the self-check (setns, chroot, fchdir, setgroups, setres*id,
// capset, prctl) returns it, so from pre_exec it names the self-check alone.
const SELF_CHECK: i32 = libc::ENOTRECOVERABLE;

/// Who a child becomes in the held task's view.
pub enum As<'a> {
    /// The held task's own ids (D6): the mutator.
    Held,
    /// Alice's, mapped into the held task's user namespace, caps set to hers,
    /// NO_NEW_PRIVS: the judged mutator and the probes.
    Alice(&'a Alice),
}

/// The held task's view and the ids to take in it, read from /proc before the
/// fork; `enter` applies them in the child.
struct View {
    user: Option<File>,
    mnt: Option<File>,
    root: File,
    cwd: File,
    uid: Vec<u32>,
    gid: Vec<u32>,
    groups: Vec<u32>,
    /// Some: alice's CapEff, set as effective and permitted, then NO_NEW_PRIVS.
    caps: Option<u64>,
    /// §4: the canary path, whether root can't find it in this view either,
    /// whether root finds the gate itself there, and the gate's `(dev, ino)`.
    gate: Option<(CString, bool, bool, (u64, u64))>,
    /// The canary's `(dev, ino)`s: a root or cwd among them is the held
    /// task's way in, not alice's.
    ids: Vec<(u64, u64)>,
}

impl GateBackend {
    /// The held task's user and mount namespaces, its root, its cwd (or the
    /// dirfd its path is relative to), and the ids `who` takes there.
    fn view(&self, ev: &Event, canary: Option<&Canary>, who: As) -> Result<View> {
        let tid = ev.tid;
        // None: already ours (setns into our own user namespace fails).
        let ns = |n: &str| -> Result<Option<File>> {
            let theirs = format!("/proc/{tid}/ns/{n}");
            Ok((fs::metadata(&theirs)?.ino() != fs::metadata(format!("/proc/self/ns/{n}"))?.ino()).then(|| File::open(theirs)).transpose()?)
        };
        let (user, mnt) = (ns("user")?, ns("mnt")?);
        // O_PATH: no filesystem open callback runs (one on a FUSE mount served
        // by a gated task would block). O_DIRECTORY: a dirfd that isn't a
        // directory (a FIFO) fails here with ENOTDIR.
        let dir = |p: String| File::options().read(true).custom_flags(libc::O_PATH | libc::O_DIRECTORY).open(p);
        let root = dir(format!("/proc/{tid}/root"))?;
        let cwd = dir(match ev.dirfd {
            Some(fd) if ev.path.as_ref().is_some_and(|p| p.is_relative()) => format!("/proc/{tid}/fd/{fd}"),
            _ => format!("/proc/{tid}/cwd"),
        })?;
        let (mut uid, mut gid, mut groups, caps) = match who {
            As::Held => {
                let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
                let ids = |key: &str| -> Result<Vec<u32>> {
                    let line = status.lines().find_map(|l| l.strip_prefix(key)).with_context(|| format!("no {key}"))?;
                    Ok(line.split_whitespace().map(str::parse).collect::<Result<_, _>>()?)
                };
                (ids("Uid:")?, ids("Gid:")?, ids("Groups:")?, None)
            }
            As::Alice(a) => (vec![a.uid; 3], vec![a.gid; 3], a.groups.clone(), Some(a.cap_eff)),
        };
        if user.is_some() {
            // Host ids (status shows them as our namespace sees them); map them
            // into the task's. A map line is "<id inside> <id outside> <count>".
            let map = |file: &str, v: &mut [u32]| -> Result<()> {
                let m = fs::read_to_string(format!("/proc/{tid}/{file}"))?;
                for id in v {
                    *id = m
                        .lines()
                        .find_map(|l| match l.split_whitespace().filter_map(|x| x.parse().ok()).collect::<Vec<u32>>()[..] {
                            [inside, outside, n] if (outside..outside.saturating_add(n)).contains(id) => Some(inside + (*id - outside)),
                            _ => None,
                        })
                        .with_context(|| format!("id {id} unmapped in {file}"))?;
                }
                Ok(())
            };
            map("uid_map", &mut uid)?;
            map("gid_map", &mut gid)?;
            map("gid_map", &mut groups)?;
        }
        // §4: ENOENT passes only if root cannot find the canary in the task's
        // view either.
        let gate = match canary {
            Some(c) => {
                let gate = CString::new(c.dir.as_os_str().as_bytes())?;
                let id = c.before[Path::new("")].id;
                let at = open_in(&root, &gate, 0);
                let gone = matches!(&at, Err(e) if e.raw_os_error() == Some(libc::ENOENT));
                Some((gate, gone, at.is_ok_and(|f| cached_id(&f) == Some(id)), id))
            }
            None => None,
        };
        // The task may have died and its tid been reused since the trap: only a
        // still-valid id proves the /proc reads above were the held task's.
        if !self.id_valid(ev.id) {
            bail!("held task gone");
        }
        let view = View { user, mnt, root, cwd, uid, gid, groups, caps, gate, ids: canary.map(|c| c.ids().into_keys().collect()).unwrap_or_default() };
        if canary.is_some() && unsafe { view.inside(&view.root) } {
            bail!(RootInCanary);
        }
        Ok(view)
    }

    /// Run the mutator `prog` on held event `ev` in its task's view (`view`).
    /// Judged, as alice (§10.1): her ids mapped into the task's user namespace,
    /// her caps, NO_NEW_PRIVS, self-checked against the canary at the given
    /// path (§4); unjudged, with the task's own ids (D6). `prog` gets the path
    /// as issued; killed after `timeout`. CRFUZZ_CANARY names a fresh
    /// directory each run (and replay): choices must come from CRFUZZ_SEED,
    /// never from that name, or replay can't fire the same mutation (D6).
    // ponytail: `prog` is exec'd after the chroot, so it (and a script's
    // interpreter) must exist inside the task's root; exec it from an fd opened
    // beforehand once a target has its own root (runc).
    // ponytail: kill() reaches only `prog`, not processes it forked.
    pub fn mutate(&self, ev: &Event, prog: &Path, judge: Option<(&Alice, &Canary)>, seed: u64, timeout: Duration) -> Result<ExitStatus> {
        let path = ev.path.as_ref().context("event has no path")?;
        let view = match judge {
            Some((alice, canary)) => self.view(ev, Some(canary), As::Alice(alice))?,
            None => self.view(ev, None, As::Held)?,
        };
        let mut cmd = Command::new(prog);
        cmd.arg(path)
            .env("CRFUZZ_PATH", path)
            .env("CRFUZZ_SYSCALL", ev.nr.to_string())
            .env("CRFUZZ_SEED", seed.to_string())
            // Not crfuzz's own output (or root's tty): alice could forge a verdict line.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Only where that path is the canary in the task's view: its own root
        // or mounts can hide it or put something else there.
        if let (Some((_, canary)), Some((_, _, true, _))) = (judge, &view.gate) {
            cmd.env("CRFUZZ_CANARY", &canary.dir);
        }
        unsafe {
            cmd.pre_exec(move || view.enter());
        }
        let end = Instant::now() + timeout;
        // spawn() returns only once the exec is done, and the exec looks `prog`
        // up inside the task's root, where it can block on a lock a gated task
        // holds. So spawn on a thread and let the deadline cover it. The view's
        // fds go with `cmd`: pre_exec uses them until spawn returns.
        let (tx, rx) = mpsc::channel();
        let abandoned = Arc::new(Mutex::new(false));
        let flag = abandoned.clone();
        std::thread::spawn(move || {
            let r = cmd.spawn();
            drop(cmd);
            let gone = flag.lock().unwrap();
            match r {
                // Given up on: kill it once it exists, or it mutates after the hold.
                Ok(mut c) if *gone => {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                r => {
                    let _ = tx.send(r);
                }
            }
        });
        let mut child = match rx.recv_timeout(timeout) {
            Ok(Err(e)) if e.raw_os_error() == Some(SELF_CHECK) => return Err(SelfCheckFailed.into()),
            Ok(r) => r.with_context(|| format!("spawn mutator {}", prog.display()))?,
            Err(_) => {
                *abandoned.lock().unwrap() = true;
                // Sent just before we gave up: kill it here.
                if let Ok(Ok(mut c)) = rx.try_recv() {
                    let _ = c.kill();
                    std::thread::spawn(move || c.wait());
                }
                bail!("mutator not started after {timeout:?}; killed once it starts");
            }
        };
        loop {
            if let Some(st) = child.try_wait()? {
                return Ok(st);
            }
            if Instant::now() >= end {
                let _ = child.kill();
                // Don't wait: stuck unkillable on a lock a gated task holds, it
                // would never exit, and the tree hold would outlive sched_ext's
                // 30 s watchdog. Reap it whenever it does exit.
                std::thread::spawn(move || child.wait());
                bail!("mutator still running after {timeout:?}; killed");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The read half (§5) at the final hold `ev`: as alice in its view, `stat`
    /// the footprint and every mount point, and look for the token in each
    /// regular file she can open; then, as root, the task's own handles if it
    /// runs as alice. Killed after `timeout`; any failure makes the run invalid.
    pub fn probe(&self, ev: &Event, alice: &Alice, canary: &Canary, footprint: &BTreeSet<PathBuf>, timeout: Duration) -> Result<Vec<Finding>> {
        let mut found = 'view: {
            let view = match self.view(ev, Some(canary), As::Alice(alice)) {
                Err(e) if e.is::<RootInCanary>() => break 'view Vec::new(),
                r => r?,
            };
            let mut paths: Vec<PathBuf> = footprint.iter().cloned().collect();
            paths.extend(oracle::mount_points(&fs::read(format!("/proc/{}/mountinfo", ev.tid))?));
            let cpaths = paths.iter().map(|p| CString::new(p.as_os_str().as_bytes())).collect::<Result<Vec<_>, _>>()?;
            let token = canary.token.as_bytes();
            let mut buf = vec![0u8; 1 << 20];
            let mut fds = [0; 2];
            ensure!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0, "pipe: {}", Error::last_os_error());
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // Child: async-signal-safe only (we are multithreaded); everything
                // it touches was built before the fork. Records are 24 bytes,
                // [kind << 63 | path index, dev, ino]; kind 1: the token.
                unsafe {
                    libc::close(fds[0]);
                    if let Err(e) = view.enter() {
                        libc::_exit(if e.raw_os_error() == Some(SELF_CHECK) { 2 } else { 1 });
                    }
                    // Every fd but the pipe: opened as root (the view's, and all of
                    // crfuzz's, inherited across a fork with no exec), through
                    // /proc/self/fd they would be alice's. Fails closed.
                    let w = fds[1] as u32;
                    if (w > 0 && libc::syscall(libc::SYS_close_range, 0u32, w - 1, 0u32) != 0)
                        || libc::syscall(libc::SYS_close_range, w + 1, u32::MAX, 0u32) != 0
                    {
                        libc::_exit(1);
                    }
                    let rec = |kind: u64, i: usize, dev: u64, ino: u64| {
                        let r = [kind << 63 | i as u64, dev, ino];
                        libc::write(fds[1], r.as_ptr().cast(), 24);
                    };
                    for (i, p) in cpaths.iter().enumerate() {
                        let mut st: libc::stat = std::mem::zeroed();
                        if libc::stat(p.as_ptr(), &mut st) != 0 {
                            continue;
                        }
                        rec(0, i, st.st_dev, st.st_ino);
                        // Only regular files: never open a FIFO or a device.
                        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                            continue;
                        }
                        let fd = libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC);
                        if fd >= 0 {
                            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
                            if n > 0 && buf[..n as usize].windows(token.len()).any(|w| w == token) {
                                rec(1, i, 0, 0);
                            }
                            libc::close(fd);
                        }
                    }
                    libc::_exit(0);
                }
            }
            let forked = (pid > 0).then_some(()).ok_or_else(Error::last_os_error);
            unsafe { libc::close(fds[1]) };
            if let Err(e) = forked {
                unsafe { libc::close(fds[0]) };
                bail!("fork: {e}");
            }
            let mut rd = unsafe { File::from_raw_fd(fds[0]) };
            // ponytail: one blocking read loop under a poll deadline; a stuck stat (FUSE served by a gated task) is killed.
            let (mut out, end) = (Vec::new(), Instant::now() + timeout);
            let reap = || unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            };
            loop {
                let mut p = libc::pollfd { fd: fds[0], events: libc::POLLIN, revents: 0 };
                let left = end.saturating_duration_since(Instant::now()).as_millis() as i32;
                let n = if left == 0 { 0 } else { unsafe { libc::poll(&mut p, 1, left) } };
                if n == 0 {
                    reap();
                    bail!("probe still running after {timeout:?}; killed");
                }
                if n < 0 {
                    continue; // EINTR
                }
                let mut chunk = [0u8; 4096];
                match rd.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => out.extend_from_slice(&chunk[..n]),
                    Err(e) => {
                        reap();
                        return Err(e).context("probe pipe");
                    }
                }
            }
            let mut status = 0;
            // A failed wait leaves status 0, which would read as a pass.
            ensure!(unsafe { libc::waitpid(pid, &mut status, 0) } == pid, "waitpid: {}", Error::last_os_error());
            match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
                Some(0) => {}
                Some(2) => return Err(SelfCheckFailed.into()),
                _ => bail!("probe could not enter the view (status {status:#x})"),
            }

            // Not the gate: alice may always stat it; only what's below it is hers to miss.
            let mut ids = canary.ids();
            ids.retain(|_, k| !k.as_os_str().is_empty());
            let mut found = Vec::new();
            for r in out.chunks_exact(24) {
                let w = |k: usize| u64::from_ne_bytes(r[k * 8..k * 8 + 8].try_into().unwrap());
                let (kind, i) = (w(0) >> 63, (w(0) & !(1 << 63)) as usize);
                match kind {
                    0 => found.extend(ids.get(&(w(1), w(2))).map(|e| Finding::Reached { entry: e.clone(), at: paths[i].clone() })),
                    _ => found.push(Finding::Copy { at: paths[i].clone() }),
                }
            }
            found
        };
        // The task's own handles, as root: only a task running as alice makes
        // them hers. The gate counts here: a root or cwd at it reaches all below.
        let ids = canary.ids();
        if oracle::euid(ev.tid)? == alice.uid {
            // stat follows each handle: one on a FUSE mount served by a gated
            // task blocks, so the stats run on a thread under the deadline.
            // ponytail: a blocked thread is leaked; the run is invalid anyway.
            let (tid, tgid) = (ev.tid, ev.tgid);
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let handles = || -> Result<Vec<(PathBuf, (u64, u64))>> {
                    let fd_dir = fs::read_dir(format!("/proc/{tgid}/fd"))?.filter_map(|e| e.ok().map(|e| e.path()));
                    let all = ["cwd", "root"].map(|h| PathBuf::from(format!("/proc/{tid}/{h}"))).into_iter().chain(fd_dir);
                    Ok(all.filter_map(|at| fs::metadata(&at).ok().map(|m| (at, (m.dev(), m.ino())))).collect())
                };
                let _ = tx.send(handles());
            });
            // Its own deadline: the forked probe may have used most of the first.
            let handles = rx.recv_timeout(timeout).map_err(|_| anyhow::anyhow!("probe: a handle still blocked after {timeout:?}"))??;
            for (at, id) in handles {
                if let Some(e) = ids.get(&id) {
                    found.push(Finding::Reached { entry: e.clone(), at });
                }
            }
        }
        found.sort();
        found.dedup();
        Ok(found)
    }
}

/// `path` opened O_PATH as root in the view rooted at `root`. RESOLVE_IN_ROOT:
/// absolute symlinks stay inside that root, as they will for the chrooted child.
fn open_in(root: &File, path: &CStr, flags: i32) -> std::io::Result<File> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC | flags) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT;
    let fd = unsafe { libc::syscall(libc::SYS_openat2, root.as_raw_fd(), path.as_ptr(), &how, std::mem::size_of::<libc::open_how>()) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

/// `f`'s `(dev, ino)` from cached attributes: no FS callback (a FUSE getattr
/// served by a gated task would block).
fn cached_id(f: &File) -> Option<(u64, u64)> {
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statx(f.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC, libc::STATX_INO, &mut st) };
    (r == 0).then(|| (libc::makedev(st.stx_dev_major, st.stx_dev_minor), st.stx_ino))
}

/// §4's root-side look: true iff `path` is not in the view rooted at `root`
/// at all. Any other error counts as present, so alice must then get EACCES.
fn absent(root: &File, path: &CStr, flags: i32) -> bool {
    matches!(open_in(root, path, flags), Err(e) if e.raw_os_error() == Some(libc::ENOENT))
}

/// §5 read before: before the SUT, alice must be stopped at every canary
/// entry: EACCES, or ENOENT where root can't find it in this view either.
/// Catches a gate she can search but not read, which §4's open passes.
pub fn read_before(canary: &Canary, alice: &Alice) -> Result<()> {
    let dir = |p: &str| File::options().read(true).custom_flags(libc::O_PATH | libc::O_DIRECTORY).open(p);
    let root = dir("/")?;
    let entries = canary
        .before
        .keys()
        .filter(|k| !k.as_os_str().is_empty()) // the gate: §4's check, in enter()
        .map(|k| {
            let p = CString::new(canary.dir.join(k).as_os_str().as_bytes())?;
            // O_NOFOLLOW: a symlink entry is checked itself, not its target.
            let gone = absent(&root, &p, libc::O_NOFOLLOW);
            Ok((p, gone))
        })
        .collect::<Result<Vec<_>>>()?;
    let gate = CString::new(canary.dir.as_os_str().as_bytes())?;
    let gate_gone = absent(&root, &gate, 0);
    // crfuzz's own view: nothing to setns into, ids need no mapping.
    let view = View {
        user: None,
        mnt: None,
        cwd: dir(".")?,
        root,
        uid: vec![alice.uid; 3],
        gid: vec![alice.gid; 3],
        groups: alice.groups.clone(),
        caps: Some(alice.cap_eff),
        gate: Some((gate, gate_gone, false, canary.before[Path::new("")].id)),
        ids: canary.ids().into_keys().collect(),
    };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: async-signal-safe only; everything it reads was built before the fork.
        unsafe {
            if let Err(e) = view.enter() {
                libc::_exit(if e.raw_os_error() == Some(SELF_CHECK) { 2 } else { 1 });
            }
            for (p, gone) in &entries {
                let mut st: libc::stat = std::mem::zeroed();
                let stopped = libc::lstat(p.as_ptr(), &mut st) != 0
                    && match Error::last_os_error().raw_os_error() {
                        Some(libc::EACCES) => true,
                        Some(libc::ENOENT) => *gone,
                        _ => false,
                    };
                if !stopped {
                    libc::_exit(2);
                }
            }
            libc::_exit(0);
        }
    }
    ensure!(pid > 0, "fork: {}", Error::last_os_error());
    let mut status = 0;
    // ponytail: no deadline; lstat under a local root-owned dir doesn't block. Add one if /var/lib can be NFS.
    // A failed wait leaves status 0, which would read as a pass.
    ensure!(unsafe { libc::waitpid(pid, &mut status, 0) } == pid, "waitpid: {}", Error::last_os_error());
    match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
        Some(0) => Ok(()),
        Some(2) => Err(SelfCheckFailed.into()),
        _ => bail!("read before: could not become alice (status {status:#x})"),
    }
}

impl View {
    /// Between fork and exec (or _exit): raw syscalls only, no allocation.
    /// User namespace first: it grants the capabilities to enter the mount
    /// namespace it owns. The §4 self-check last, with the final credentials.
    unsafe fn enter(&self) -> std::io::Result<()> {
        let ok = |r: i32| if r < 0 { Err(Error::last_os_error()) } else { Ok(()) };
        // An fd crfuzz inherited without CLOEXEC would reach the mutator.
        // CLOEXEC, not close: std's spawn reports exec errors over one.
        ok(libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) as i32)?;
        // Groups cleared here, as root in our own namespace: a user namespace
        // whose setgroups is "deny" refuses it after setns.
        ok(libc::setgroups(0, std::ptr::null()))?;
        if let Some(f) = &self.user {
            ok(libc::setns(f.as_raw_fd(), libc::CLONE_NEWUSER))?;
        }
        if let Some(f) = &self.mnt {
            ok(libc::setns(f.as_raw_fd(), libc::CLONE_NEWNS))?;
        }
        ok(libc::fchdir(self.root.as_raw_fd()))?;
        ok(libc::chroot(b".\0".as_ptr().cast()))?;
        // A cwd (or dirfd) inside the canary is the held task's: resolve from
        // the root instead, which can only miss (§9).
        // ponytail: fchdir runs as root, so outside the canary alice may start
        // in a directory she could not reach by path (a 0777 dir under a 0700
        // one): a mutator there exceeds her. Check she can reach it, falling
        // back to the root, if false findings show up there (§9).
        if !self.inside(&self.cwd) {
            ok(libc::fchdir(self.cwd.as_raw_fd()))?;
        }
        if !self.groups.is_empty() {
            ok(libc::setgroups(self.groups.len(), self.groups.as_ptr()))?;
        }
        ok(libc::setresgid(self.gid[0], self.gid[1], self.gid[2]))?;
        if let Some(c) = self.caps {
            // capset before setresuid would drop CAP_SETUID; without KEEPCAPS,
            // setresuid to nonzero clears the permitted set for good.
            ok(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0))?;
            ok(libc::setresuid(self.uid[0], self.uid[1], self.uid[2]))?;
            let hdr = CapHeader { version: CAP_V3, pid: 0 };
            let half = |v: u32| CapData { effective: v, permitted: v, inheritable: 0 };
            let data = [half(c as u32), half((c >> 32) as u32)];
            ok(libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) as i32)?;
            // The mutator execs: no setuid binary may lift it past alice.
            ok(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        } else {
            ok(libc::setresuid(self.uid[0], self.uid[1], self.uid[2]))?;
        }
        let Some((gate, gone, _, id)) = &self.gate else { return Ok(()) };
        // A root inside the canary hides the gate behind ENOENT. `view` refuses
        // one already; this keeps read_before's hand-built view honest too.
        if self.inside(&self.root) {
            return Err(Error::from_raw_os_error(SELF_CHECK));
        }
        // §4, last: with the final credentials the gate must stop us, or
        // nothing that runs from here is really alice.
        let fd = libc::open(gate.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC);
        if fd >= 0 {
            // Something else at the gate's path (a mount in the task's view)
            // says nothing about alice's credentials: the probe judges it.
            let mut st: libc::stat = std::mem::zeroed();
            let gate = libc::fstat(fd, &mut st) != 0 || (st.st_dev, st.st_ino) == *id;
            libc::close(fd);
            return if gate { Err(Error::from_raw_os_error(SELF_CHECK)) } else { Ok(()) };
        }
        match Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) => Ok(()),
            Some(libc::ENOENT) if *gone => Ok(()),
            _ => Err(Error::from_raw_os_error(SELF_CHECK)),
        }
    }

    /// Async-signal-safe. Fails closed: an fd that can't be stat'd counts as inside.
    unsafe fn inside(&self, f: &File) -> bool {
        let mut st: libc::stat = std::mem::zeroed();
        libc::fstat(f.as_raw_fd(), &mut st) != 0 || self.ids.contains(&(st.st_dev, st.st_ino))
    }
}

// libc has SYS_capset but not its structs.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_V3: u32 = 0x2008_0522;

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
