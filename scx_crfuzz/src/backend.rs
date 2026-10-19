//! GateBackend: park SUT threads at watched syscalls (seccomp user-notify) and
//! stop the whole SUT tree with the gate (spec §3.3, L:Seccomp, L:Gate).

use anyhow::{bail, Context, Result};
use scx_crfuzz_gate::GateMap;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Error;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

const SCHED_EXT: i32 = 7;
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
    pub nr: i64,
    /// Best-effort: a running sibling can rewrite it after the read.
    pub path: Option<PathBuf>,
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
}

impl GateBackend {
    /// Spawn `cmd` as the SUT: in the run cgroup, enrolled in SCHED_EXT, with
    /// `watched` syscalls trapping to us. Fails if the gate daemon isn't up
    /// (never fall back to seccomp-only: L:Gate).
    pub fn spawn(mut cmd: Command, watched: &[i64]) -> Result<Self> {
        let exec_watched = watched.contains(&libc::SYS_execve);
        // A bare name makes execvp try one execve per PATH entry, and we can't
        // tell which try will succeed, so the helper below can't stop on it.
        if exec_watched && !cmd.get_program().as_bytes().contains(&b'/') {
            bail!("watching execve needs a program path, not a bare name: {:?}", cmd.get_program());
        }
        let gate = GateMap::open()?;
        let cgroup = PathBuf::from(format!("{CGROUP_ROOT}/run-{}", gate.epoch));
        fs::create_dir_all(&cgroup).with_context(|| cgroup.display().to_string())?;
        let procs = File::options().write(true).open(cgroup.join("cgroup.procs"))?;
        let filter = notify_filter(watched);

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
        Ok(Self { gate, child, notify, cgroup, tree_gated: BTreeSet::new() })
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

    /// Tgids currently gated by `gate_tree`.
    pub fn tree(&self) -> &BTreeSet<u32> {
        &self.tree_gated
    }

    /// Wait up to `timeout` for held syscalls; returns every one ready now.
    pub fn poll(&mut self, timeout: Duration) -> Result<Poll> {
        let mut events = Vec::new();
        let mut wait = timeout.as_millis() as i32;
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
        Ok(if events.is_empty() { Poll::Idle } else { Poll::Events(events) })
    }

    fn recv(&self) -> Result<Option<Event>> {
        let req = match notif_recv(self.notify.as_raw_fd()) {
            Ok(req) => req,
            // ENOENT: the task died between poll and recv.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let (tid, nr) = (req.pid, req.data.nr as i64);
        let path = path_arg(nr).and_then(|i| read_cstr(tid, req.data.args[i]));
        let tgid = read_tgid(tid);
        // Only a still-valid id proves tid and bytes belonged to the notifying
        // task (it may have died and its tid been reused).
        if !self.id_valid(req.id) {
            return Ok(None);
        }
        Ok(Some(Event { id: req.id, tid, tgid: tgid?, nr, path }))
    }

    fn id_valid(&self, id: u64) -> bool {
        unsafe { libc::ioctl(self.notify.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_ID_VALID as _, &id) == 0 }
    }

    /// Let a held syscall run as issued. Under a tree hold the thread stays
    /// gated until `ungate_tree`; answering first means a signal can't restart
    /// the syscall mid-release (L:Gate).
    pub fn release(&self, ev: &Event) -> Result<()> {
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
            let new: Vec<u32> = self.cgroup_tgids()?.into_iter().filter(|t| !self.tree_gated.contains(t)).collect();
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

    /// cgroup.procs lists only a cgroup's own members, so read every cgroup
    /// in the subtree.
    fn cgroup_tgids(&self) -> Result<Vec<u32>> {
        let mut tgids = Vec::new();
        for dir in cgroup_dirs(&self.cgroup) {
            match fs::read_to_string(dir.join("cgroup.procs")) {
                Ok(procs) => tgids.extend(procs.lines().filter_map(|l| l.parse::<u32>().ok())),
                // A child cgroup removed mid-walk had no members left.
                Err(e) if dir != self.cgroup && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(tgids)
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

/// Which argument of syscall `nr` is its (first) path.
fn path_arg(nr: i64) -> Option<usize> {
    match nr {
        libc::SYS_openat
        | libc::SYS_openat2
        | libc::SYS_newfstatat
        | libc::SYS_statx
        | libc::SYS_faccessat
        | libc::SYS_faccessat2
        | libc::SYS_readlinkat
        | libc::SYS_unlinkat
        | libc::SYS_mkdirat
        | libc::SYS_mknodat
        | libc::SYS_renameat2
        | libc::SYS_fchmodat
        | libc::SYS_fchownat => Some(1),
        libc::SYS_chdir | libc::SYS_execve => Some(0),
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
    fn reads_own_cstr() {
        let s = b"/some/path\0";
        let got = read_cstr(std::process::id(), s.as_ptr() as u64).unwrap();
        assert_eq!(got, Path::new("/some/path"));
    }
}
