// SPDX-License-Identifier: GPL-2.0
//
// The seccomp user-notification backend: the first backend that actually holds
// a real process.
//
// Design doc: Background ("Checkpoint"). A `syscall` checkpoint stops a role at
// a syscall boundary via `seccomp` in user-notification mode: the kernel
// suspends the calling thread inside the kernel and delivers a notification
// here; the thread stays blocked until this code explicitly releases it. That
// is genuinely synchronous holding -- the target cannot execute a further
// instruction past the checkpointed syscall until released, because the kernel
// itself, not this program's reaction time, is what blocks it.
//
// This needs no eBPF and no `sched_ext` attach. All 21 entries of the section
// 4.2 structural set are `syscall` checkpoints, so this one mechanism covers
// the whole default discovery checkpoint set.
//
// WHAT THIS BACKEND DOES NOT DO, and why the design doc needs the second
// mechanism as well: seccomp user-notification holds the *thread* that made the
// syscall, not the thread group. Background, "Role", requires that holding a
// role hold every OS thread within it. For a single-threaded target the two
// coincide. For a Go binary -- runc, containerd -- they do not: sibling
// goroutine threads keep running while one thread sits in a notification. That
// is exactly why the base design also specifies `ops.dispatch` declining to
// place a task on a CPU. Until that lands, this backend is sound for
// single-threaded targets and unsound for multi-threaded ones.

use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::NotifyHandle;
use crate::backend::Poll;
use crate::checkpoint::CheckpointDecl;
use crate::checkpoint::CheckpointId;
use crate::event::ComponentKey;
use crate::event::ConflictKey;
use crate::event::Direction;
use crate::event::FileToken;
use crate::role::Pid;
use crate::role::TaskInfo;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libseccomp::ScmpAction;
use libseccomp::ScmpFilterContext;
use libseccomp::ScmpNotifReq;
use libseccomp::ScmpNotifResp;
use libseccomp::ScmpNotifRespFlags;
use libseccomp::ScmpSyscall;
use nix::poll::PollTimeout;
use nix::sys::epoll::Epoll;
use nix::sys::epoll::EpollCreateFlags;
use nix::sys::epoll::EpollEvent;
use nix::sys::epoll::EpollFlags;
use nix::sys::socket::recvmsg;
use nix::sys::socket::sendmsg;
use nix::sys::socket::socketpair;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::ControlMessage;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
use nix::unistd::ForkResult;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

/// Where the unified cgroup v2 hierarchy is mounted.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// One process the backend launches and instruments.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    /// argv. `argv[0]` is the program path; it is executed directly, not via a
    /// shell, so nothing here is word-split or glob-expanded.
    pub argv: Vec<String>,
}

impl ProcessSpec {
    /// Parse a `--spawn` argument. Whitespace-separated, no quoting: these are
    /// test scenarios, and a shell-grade parser here would be pretending to an
    /// interface this does not have.
    pub fn parse(s: &str) -> Result<Self> {
        let argv: Vec<String> = s.split_whitespace().map(str::to_string).collect();
        if argv.is_empty() {
            bail!("empty process spec");
        }
        Ok(ProcessSpec { argv })
    }
}

/// One instrumented process tree and its notification listener.
#[derive(Debug)]
struct Listener {
    /// The direct child. Its own fork/exec descendants inherit the filter and
    /// notify on this same fd, which is how a `runc` -> `runc init` re-exec
    /// stays instrumented without re-attaching.
    child: Pid,
    fd: OwnedFd,
    /// Readable once `child` has exited, so a waiting poll wakes to reap it.
    /// Dropped (and so out of the epoll set) once reaped.
    pidfd: Option<OwnedFd>,
    reaped: bool,
    /// The child's exit status in shell convention -- its exit code, or
    /// `128 + signo` if a signal killed it. `None` until it has been reaped.
    ///
    /// Kept because a wrapper standing in for the process it instruments has to
    /// report *its* status, not the engine's verdict on the scheduling run.
    exit_code: Option<i32>,
    /// No task holds the filter any more. Its fd reports EPOLLHUP, which is
    /// level-triggered and never clears, so it is taken out of the epoll set:
    /// left in, every wait would return at once.
    hung_up: bool,
    /// The child has made its first notified syscall. Until then, an `execve`
    /// from it is the backend's own launch (`child_setup` loads the filter and
    /// only then execs), not something the target did: the target does not
    /// exist yet, and the task still carries the engine's `comm`. See `poll`.
    launched: bool,
}

/// Holds real processes at real syscalls via `SECCOMP_RET_USER_NOTIF`.
#[derive(Debug)]
pub struct SeccompNotifyBackend {
    specs: Vec<ProcessSpec>,
    /// cgroup v2 path as it appears in `/proc/<pid>/cgroup`, e.g. `/crfuzz/run0`
    /// -- NOT the `/sys/fs/cgroup`-prefixed filesystem path.
    cgroup: String,
    listeners: Vec<Listener>,
    /// Syscall number -> the checkpoint id the config declared for it.
    ///
    /// The *config's* spelling wins over the kernel's canonical name, so a
    /// schedule stays matched to the checkpoints its author wrote. Without
    /// this, a config saying `fstatat` would never match an aarch64 kernel
    /// reporting `newfstatat`, and replay would diverge for a reason that has
    /// nothing to do with the scenario.
    watched: HashMap<i32, CheckpointId>,
    /// Notification id -> the held syscall, for `release` and `recapture`.
    pending: HashMap<u64, Pending>,
    /// pids already announced via `TaskAppeared`.
    announced: Vec<Pid>,
    /// Every listener fd and pidfd, plus `wake_fd`. Created by `attach`.
    epoll: Option<Epoll>,
    /// An fd the owner also wants a waiting poll to wake for (the gate's
    /// thread-state ringbuf).
    wake_fd: Option<RawFd>,
    /// Place each spawned target in `SCHED_EXT` before `exec`, so the gate's
    /// scheduler sees it. Off by default: with `SCX_OPS_SWITCH_PARTIAL` an
    /// un-enrolled task stays on CFS, which is what the integration tests that
    /// exercise seccomp alone want. The binary always turns it on.
    sched_ext: bool,
}

/// One held syscall: where to answer it, and what to recapture its keys from.
#[derive(Debug)]
struct Pending {
    fd: RawFd,
    pid: Pid,
    args: [u64; 6],
    name: String,
}

impl SeccompNotifyBackend {
    pub fn new(specs: Vec<ProcessSpec>, cgroup: impl Into<String>) -> Self {
        SeccompNotifyBackend {
            specs,
            cgroup: cgroup.into(),
            listeners: Vec::new(),
            watched: HashMap::new(),
            pending: HashMap::new(),
            announced: Vec::new(),
            epoll: None,
            wake_fd: None,
            sched_ext: false,
        }
    }

    pub fn with_sched_ext(mut self, yes: bool) -> Self {
        self.sched_ext = yes;
        self
    }

    /// Also wake a waiting `poll` when `fd` is readable. Call before `attach`.
    pub fn wake_on(&mut self, fd: RawFd) {
        self.wake_fd = Some(fd);
    }

    /// The run cgroup's directory under the cgroup v2 mount.
    pub fn cgroup_dir(&self) -> PathBuf {
        PathBuf::from(CGROUP_MOUNT).join(self.cgroup.trim_start_matches('/'))
    }

    /// Block until a listener, a child's exit or `wake_fd` is ready, or
    /// `timeout` passes (forever when `None`). A signal ends the wait early,
    /// so the engine can check its stop flag; that is the one `false`. Once
    /// the scenario is over, blocks only for `wake_fd`: nothing else could
    /// ever wake it.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<bool> {
        let Some(epoll) = &self.epoll else {
            return Ok(true);
        };
        if self.closed() && self.wake_fd.is_none() {
            return Ok(true);
        }
        let timeout = match timeout {
            None => PollTimeout::NONE,
            Some(d) => PollTimeout::try_from(d).unwrap_or(PollTimeout::MAX),
        };
        match epoll.wait(&mut [EpollEvent::empty()], timeout) {
            Ok(_) => Ok(true),
            Err(nix::errno::Errno::EINTR) => Ok(false),
            Err(e) => Err(e).context("waiting on the notify fds"),
        }
    }

    /// Resolve declared `syscall` checkpoints to numbers on this architecture.
    ///
    /// Returns the ids that could not be attached. This is not a corner case:
    /// the section 4.2 set is written in x86_64 vocabulary, and much of it does
    /// not exist as a syscall on other architectures. Two distinct failures
    /// have to be told apart, and getting them confused is how a checkpoint
    /// ends up looking attached while never firing:
    ///
    /// 1. **The name is spelled differently here.** libseccomp knows aarch64's
    ///    stat-family call as `newfstatat`, not `fstatat`, so the doc's own
    ///    spelling resolves to nothing at all. `ARCH_ALIASES` bridges that, so
    ///    a config can keep using the vocabulary the design doc uses.
    ///
    /// 2. **The syscall genuinely does not exist here.** `stat`, `lstat`,
    ///    `access`, `readlink`, `rename`, `symlink`, `unlink`, `mknod` and
    ///    `umount` have no aarch64 syscall number; userspace cannot issue them.
    ///    libseccomp still "resolves" these, to a *negative pseudo-syscall*
    ///    number, and `add_rule` on one silently installs a rewritten rule
    ///    against the modern equivalent instead (`readlink` becomes
    ///    `readlinkat` with `dirfd == AT_FDCWD`).
    ///
    ///    Accepting that rewrite would be a correctness bug, not a convenience:
    ///    the rule fires with the *modern* syscall number, which is not the key
    ///    this map stored it under, so the notification would be attributed to
    ///    a different checkpoint id or to none at all -- and a checkpoint that
    ///    reports itself attached but never fires is worse than one that says
    ///    it could not attach. So a negative number is refused outright.
    fn resolve_checkpoints(&mut self, checkpoints: &[CheckpointDecl]) -> Vec<CheckpointId> {
        let mut unresolved = Vec::new();
        for decl in checkpoints {
            // A hand-written config may declare `fstatat` by the design doc's
            // name; without canonicalising, that checkpoint would silently
            // never attach.
            let nr =
                match ScmpSyscall::from_name(crate::checkpoint::canonical_syscall(&decl.target)) {
                    // A negative number is a libseccomp pseudo-syscall: the
                    // call does not exist on this architecture. See above.
                    Ok(sys) if sys.as_raw_syscall() >= 0 => Some(sys.as_raw_syscall()),
                    _ => None,
                };

            let Some(nr) = nr else {
                unresolved.push(decl.id.clone());
                continue;
            };
            log::debug!("checkpoint `{}` -> syscall nr {}", decl.id, nr);
            if let Some(existing) = self.watched.get(&nr) {
                log::warn!(
                    "checkpoints `{}` and `{}` are the same syscall here; keeping `{existing}`",
                    existing,
                    decl.id
                );
                continue;
            }
            self.watched.insert(nr, decl.id.clone());
        }
        unresolved
    }

    fn spawn(&self, spec: &ProcessSpec) -> Result<Listener> {
        let (parent_sock, child_sock) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .context("socketpair for notify-fd handoff")?;

        let watched: Vec<i32> = self.watched.keys().copied().collect();
        let cgroup_procs = self.cgroup_dir().join("cgroup.procs");

        // SAFETY: the engine is single-threaded, and the child does a bounded
        // amount of work before `execve`. The one genuinely unsafe-for-fork
        // thing here is libseccomp's internal allocation, which is unavoidable
        // if the filter is to be installed by the process it applies to.
        match unsafe { nix::unistd::fork() }.context("fork")? {
            ForkResult::Child => {
                drop(parent_sock);
                let rc =
                    match child_setup(&cgroup_procs, &watched, &child_sock, spec, self.sched_ext) {
                        Ok(never) => match never {},
                        Err(e) => {
                            // Deliberately raw: the child must not touch the
                            // logger's mutex after fork.
                            let msg = format!("scx_crfuzz child setup failed: {e}\n");
                            unsafe {
                                libc::write(2, msg.as_ptr().cast(), msg.len());
                            }
                            127
                        }
                    };
                unsafe { libc::_exit(rc) }
            }
            ForkResult::Parent { child } => {
                drop(child_sock);
                let fd = recv_fd(&parent_sock).context("receiving the notify fd from the child")?;
                set_nonblocking(fd.as_raw_fd())?;
                Ok(Listener {
                    child: child.as_raw(),
                    fd,
                    pidfd: Some(pidfd_open(child.as_raw())?),
                    reaped: false,
                    exit_code: None,
                    hung_up: false,
                    launched: false,
                })
            }
        }
    }

    /// Reap every child that has exited, recording its exit status.
    fn reap(&mut self) {
        loop {
            let status = waitpid(None, Some(WaitPidFlag::WNOHANG));
            match status {
                Ok(WaitStatus::Exited(pid, _)) | Ok(WaitStatus::Signaled(pid, _, _)) => {
                    // Shell convention, so a wrapper can pass it straight to
                    // `exit` and have a caller read it the usual way.
                    let code = match status {
                        Ok(WaitStatus::Exited(_, c)) => c,
                        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                        _ => unreachable!("outer match admitted only these two"),
                    };
                    if let Some(l) = self.listeners.iter_mut().find(|l| l.child == pid.as_raw()) {
                        l.reaped = true;
                        l.exit_code = Some(code);
                        l.pidfd = None;
                    }
                }
                // StillAlive means nothing is ready; anything else (stopped,
                // continued) is not an exit.
                Ok(WaitStatus::StillAlive) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    }

    fn live(&self) -> bool {
        self.listeners.iter().any(|l| !l.reaped)
    }

    fn closed(&self) -> bool {
        !self.live() && self.pending.is_empty()
    }

    /// The `index`-th spawn's exit status, in shell convention, once reaped.
    ///
    /// For a wrapper that stands in for one process but launches others
    /// alongside it: `--exit-with-spawn [INDEX]` names which one to answer for
    /// (e.g. the `runc` among several attackers).
    pub fn child_exit_code_at(&self, index: usize) -> Option<i32> {
        self.listeners.get(index).and_then(|l| l.exit_code)
    }
}

/// The uninhabited return of a function that only ever execs or fails.
enum Never {}

/// Everything the child does between `fork` and `execve`.
///
/// Order is load-bearing:
///  1. join the cgroup -- before the filter exists, so the `openat`/`write`
///     this costs are not themselves notified, and before `exec`, so there is
///     no window in which the target runs outside the scenario's scope. This
///     is also what makes the arrangement work for `runc`: a process placed in
///     the cgroup before exec keeps its descendants there.
///  2. install the filter and take the listener fd.
///  3. hand the fd to the engine, and only then exec -- so the engine is
///     already able to answer notifications by the time the target can make
///     one.
fn child_setup(
    cgroup_procs: &Path,
    watched: &[i32],
    sock: &OwnedFd,
    spec: &ProcessSpec,
    sched_ext: bool,
) -> Result<Never> {
    std::fs::write(cgroup_procs, format!("{}\n", std::process::id()))
        .with_context(|| format!("joining cgroup via {}", cgroup_procs.display()))?;

    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).context("new seccomp filter")?;
    ctx.set_ctl_nnp(true).context("set NO_NEW_PRIVS")?;
    for nr in watched {
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_raw_syscall(*nr))
            .with_context(|| format!("adding notify rule for syscall {nr}"))?;
    }
    ctx.load().context("loading seccomp filter")?;
    let notify_fd = ctx.get_notify_fd().context("getting the notify fd")?;

    send_fd(sock, notify_fd).context("sending the notify fd to the engine")?;
    // The target has no use for the listener; the engine holds the only copy
    // that matters.
    unsafe { libc::close(notify_fd) };

    if sched_ext {
        // Policy is inherited across fork and CLONE_THREAD, so this one call
        // enrolls the whole tree the target goes on to build -- including
        // threads a Go runtime raises later -- and nothing else on the
        // machine. Same construction the seccomp filter uses: act between
        // fork and exec, then let inheritance do the rest.
        const SCHED_EXT: libc::c_int = 7;
        let param: libc::sched_param = unsafe { std::mem::zeroed() };
        // SAFETY: `param` is a zeroed sched_param, valid for SCHED_EXT, and
        // pid 0 means the calling thread.
        if unsafe { libc::sched_setscheduler(0, SCHED_EXT, &param) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("enrolling the target in SCHED_EXT -- is scx_crfuzz_gated running?");
        }
    }

    let argv: Vec<CString> = spec
        .argv
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<std::result::Result<_, _>>()
        .context("argv contained a NUL")?;
    nix::unistd::execv(&argv[0], &argv).with_context(|| format!("exec {}", spec.argv.join(" ")))?;
    unreachable!("execv returned without an error")
}

fn send_fd(sock: &OwnedFd, fd: RawFd) -> Result<()> {
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let iov = [IoSlice::new(b"1")];
    sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}

fn recv_fd(sock: &OwnedFd) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )?;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            if let Some(fd) = fds.first() {
                // SAFETY: the kernel just installed this descriptor in our
                // table and nothing else owns it.
                return Ok(unsafe { OwnedFd::from_raw_fd(*fd) });
            }
        }
    }
    Err(anyhow!(
        "child exited before handing over its notify fd (check its stderr)"
    ))
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    use nix::fcntl::fcntl;
    use nix::fcntl::FcntlArg;
    use nix::fcntl::OFlag;
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .context("making the notify fd non-blocking")?;
    Ok(())
}

/// Whether a notification is pending on `fd`, without waiting.
fn readable(fd: RawFd) -> bool {
    // SAFETY: `fd` is a live Listener's.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut p = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)];
    nix::poll::poll(&mut p, PollTimeout::ZERO).is_ok_and(|n| n > 0)
        && p[0]
            .revents()
            .is_some_and(|r| r.contains(nix::poll::PollFlags::POLLIN))
}

fn pidfd_open(pid: Pid) -> Result<OwnedFd> {
    // SAFETY: a plain syscall; a non-negative return is a new fd we own.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("pidfd_open");
    }
    // SAFETY: as above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// CPU time `tid` has run, in ns: field 1 of `/proc/<tid>/schedstat`.
pub fn cpu_ns(tid: Pid) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{tid}/schedstat"))
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Whether a thread the sensor last saw asleep will wake on its own: it is
/// not in an interruptible sleep any more (`D`: an I/O wait the device ends;
/// awake, or gone: its records are on their way), or `/proc/<tid>/syscall`
/// shows a sleep with a timeout -- `nanosleep`, `clock_nanosleep`, or a wait
/// whose timeout argument is set -- or a wait only the filesystem ends: a
/// page fault (no syscall, `-1`) or an `execve` loading its binary.
pub fn wakes_on_its_own(tid: Pid) -> bool {
    let state = std::fs::read_to_string(format!("/proc/{tid}/stat"))
        .ok()
        .and_then(|s| Some(s.get(s.rfind(')')? + 2..)?.chars().next()?));
    if state != Some('S') {
        return true;
    }
    // Unreadable: gone since the `stat` read.
    std::fs::read_to_string(format!("/proc/{tid}/syscall"))
        .map_or(true, |l| self_waking_syscall(&l))
}

/// The syscall half of `wakes_on_its_own`, on a `/proc/<tid>/syscall` line
/// (`nr arg0 .. arg5 sp pc`, hex arguments). Each timed wait names where its
/// timeout is and what "no timeout" looks like: a NULL pointer, or a negative
/// millisecond count.
fn self_waking_syscall(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    // `running`: awake again since the `stat` read.
    let Some(Ok(nr)) = fields.next().map(str::parse::<i64>) else {
        return true;
    };
    let args: Vec<u64> = fields
        .filter_map(|f| u64::from_str_radix(f.trim_start_matches("0x"), 16).ok())
        .collect();
    let set = |i: usize| args.get(i).is_some_and(|a| *a != 0);
    let ms = |i: usize| args.get(i).is_some_and(|a| (*a as i32) >= 0);
    match nr {
        // A page fault (no syscall), or an exec loading its binary: only the
        // filesystem ends these.
        -1 | libc::SYS_execve | libc::SYS_execveat => true,
        libc::SYS_nanosleep | libc::SYS_clock_nanosleep => true,
        // futex(uaddr, op, val, *timeout), epoll_pwait2(fd, ev, max, *timeout),
        // semtimedop(id, sops, n, *timeout)
        libc::SYS_futex | libc::SYS_epoll_pwait2 | libc::SYS_semtimedop => set(3),
        // ppoll(fds, n, *timeout), rt_sigtimedwait(set, info, *timeout)
        libc::SYS_ppoll | libc::SYS_rt_sigtimedwait => set(2),
        // pselect6(n, in, out, ex, *timeout), mq_timedreceive(q, msg, len,
        // prio, *timeout)
        libc::SYS_pselect6 | libc::SYS_mq_timedreceive => set(4),
        // epoll_pwait(fd, ev, max, timeout_ms): -1 is forever.
        libc::SYS_epoll_pwait => ms(3),
        // The legacy forms glibc still uses on x86_64; aarch64 has none.
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll => ms(2),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_epoll_wait => ms(3),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_select => set(4),
        _ => false,
    }
}

/// Read a task's identity from `/proc`.
///
/// `Tgid` and `Name` come straight out of `status`. `PPid` is the parent's pid,
/// which for role resolution is wanted as the parent's *thread group* -- but
/// resolution consults the task's own thread group first (Background, "Role
/// resolution"), precisely so that a `CLONE_THREAD` sibling never depends on
/// this field being exact.
fn read_task_info(pid: Pid) -> Result<TaskInfo> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("reading /proc/{pid}/status"))?;
    let field = |key: &str| -> Option<String> {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    };
    let tgid = field("Tgid:").and_then(|v| v.parse().ok()).unwrap_or(pid);
    let ppid = field("PPid:").and_then(|v| v.parse().ok()).unwrap_or(0);
    let comm = field("Name:").unwrap_or_default();

    // cgroup v2 unified: a single `0::/path` line, where the path is relative
    // to the cgroup root -- NOT prefixed with /sys/fs/cgroup.
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        .unwrap_or_default();

    Ok(TaskInfo {
        pid,
        tgid,
        parent_tgid: ppid,
        comm,
        cgroup,
    })
}

/// Capture the path a held use-shaped syscall resolved, for the attacker/oracle
/// orchestration (attacker brainstorm, "The window model").
///
/// The seccomp notification carries the syscall's raw register arguments; the
/// path is a userspace pointer in one of them (`checkpoint::path_arg_index`
/// names which). The pointer is into the *target's* address space, so it is read
/// from `/proc/<pid>/mem`. The target is parked in its notification, so the
/// memory is stable while it is held.
///
/// After reading, the notification id is revalidated: if the target was killed
/// between the notification and the read, the address space we read is
/// meaningless, so the path is dropped. Returns `None` for a syscall with no
/// path argument, a NULL pointer, or any read/validation failure -- the engine
/// treats a missing path as "no path", never as an error.
fn capture_path(
    pid: Pid,
    args: &[u64; 6],
    syscall_name: &str,
    fd: RawFd,
    id: u64,
) -> Option<PathBuf> {
    let idx = crate::checkpoint::path_arg_index(syscall_name)?;
    let addr = *args.get(idx)?;
    if addr == 0 {
        return None;
    }
    let bytes = read_cstr_from_mem(pid, addr)?;
    // The read above dereferenced the target's memory; only trust it if the
    // notification is still live (the kernel invalidates the id when the target
    // dies). This is the mandatory guard for reading a notified task's memory.
    if libseccomp::notify_id_valid(fd, id).is_err() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

/// Read one native-endian u64 from the target's memory.
fn read_u64_from_mem(pid: Pid, addr: u64) -> Option<u64> {
    use std::os::unix::fs::FileExt;

    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = [0u8; 8];
    f.read_exact_at(&mut buf, addr).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// Read a NUL-terminated C string from another process's memory, capped at
/// `PATH_MAX`. Reads are clipped to page boundaries so a string near the end of
/// a mapping does not fail the whole read by straddling into an unmapped page.
fn read_cstr_from_mem(pid: Pid, addr: u64) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;

    const PATH_MAX: usize = 4096;
    const PAGE: u64 = 4096;

    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut out: Vec<u8> = Vec::new();
    let mut off = addr;
    let mut buf = [0u8; 256];

    while out.len() < PATH_MAX {
        let to_page_end = (PAGE - (off % PAGE)) as usize;
        let want = to_page_end.min(buf.len()).min(PATH_MAX - out.len());
        let n = match f.read_at(&mut buf[..want], off) {
            Ok(0) => break,
            Ok(n) => n,
            // A partial string already read is better than nothing; a first-read
            // failure yields None.
            Err(_) => break,
        };
        if let Some(pos) = buf[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..pos]);
            return Some(out);
        }
        out.extend_from_slice(&buf[..n]);
        off += n as u64;
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `AT_FDCWD` from `fcntl.h`: resolve a relative path against the cwd.
const AT_FDCWD: i32 = -100;

/// Capture the *conflict keys* a held path syscall touches (plan Phase 1).
///
/// One key per path argument (`checkpoint::path_arg_indices`), each tagged
/// `Rebind` for a mutating syscall and `Resolve` for a check-shaped one. The key
/// is the resolution *chain* `(anchor, [component...])`, not the resolved
/// inode: keying on the resolved object would make a `rename`/`symlink` swap
/// look independent, which is the whole race. The chain additionally lets an
/// ancestor/symlink-prefix rebind conflict with a deeper path.
///
/// This is a userspace walk under `/proc/<pid>/root` and `/proc/<pid>/fd`,
/// performed while the task is parked in its notification, so it is race-free.
/// Magic links (`/proc/self/fd`, `open_by_handle_at`, detached mounts) are the
/// known fidelity gap; the key type is shaped so the VFS-kprobe backend (plan
/// Phase 6, deferred) can replace the capture without touching the policy.
///
/// `syscall_name` is the real syscall name (not the user's checkpoint id).
///
/// Best-effort, like `capture_path`: any unreadable argument is skipped, and an
/// empty result is "no keys", never an error. The notification id is
/// revalidated after the reads, since reading the target's filesystem through
/// `/proc` still depends on it being alive; `None` means it is not.
fn capture_keys(
    pid: Pid,
    args: &[u64; 6],
    syscall_name: &str,
    fd: RawFd,
    id: u64,
) -> Option<Vec<ConflictKey>> {
    let indices = crate::checkpoint::path_arg_indices(syscall_name);
    let open_flags = match crate::checkpoint::canonical_syscall(syscall_name) {
        "open" => args[1],
        "openat" => args[2],
        // `openat2(dirfd, path, struct open_how *how, size)`: `flags` is the
        // first u64 of `open_how`. Unreadable means assume it creates: a
        // spurious conflict costs exploration, a missed one costs a bug.
        "openat2" => read_u64_from_mem(pid, args[2]).unwrap_or(crate::checkpoint::O_CREAT),
        _ => 0,
    };

    let mut keys = Vec::new();
    for (slot, &idx) in indices.iter().enumerate() {
        let addr = *args.get(idx).unwrap_or(&0);
        if addr == 0 {
            continue;
        }
        let Some(path) = read_cstr_from_mem(pid, addr) else {
            continue;
        };
        let dirfd = dirfd_for(syscall_name, idx, args);
        let follow = crate::checkpoint::follows_final_symlink(syscall_name);
        let Some(token) = file_token_for(pid, dirfd, &path, follow) else {
            log::debug!("no conflict key for {syscall_name} arg {idx} of pid {pid}: /proc walk failed");
            continue;
        };
        let dir = if crate::checkpoint::arg_rebinds(syscall_name, slot, open_flags) {
            Direction::Rebind
        } else {
            Direction::Resolve
        };
        keys.push(ConflictKey::file(token, dir));
    }

    // The reads above walked the target's mounts; only trust them if the
    // notification is still live (the kernel invalidates the id when the target
    // dies). Same guard `capture_path` uses.
    libseccomp::notify_id_valid(fd, id).ok()?;
    Some(keys)
}

/// The dirfd argument for a path argument of `name`, or `AT_FDCWD`.
///
/// Most `*at` forms put the dirfd immediately before the path. The two-dirfd
/// forms (`renameat`, `renameat2`, `linkat`, `move_mount`) use arg 0 for the
/// old/from path and arg 2 for the new/to path. `symlinkat`'s first path (the
/// link *contents*) is not resolved against a dirfd.
fn dirfd_for(name: &str, path_idx: usize, args: &[u64; 6]) -> i32 {
    let raw = |i: usize| *args.get(i).unwrap_or(&(AT_FDCWD as u64)) as i32;
    match name {
        "renameat" | "renameat2" | "linkat" | "move_mount" => {
            if path_idx == 3 {
                raw(2)
            } else {
                raw(0)
            }
        }
        "symlinkat" => {
            if path_idx == 2 {
                raw(1)
            } else {
                AT_FDCWD
            }
        }
        // `mount`, `move_mount`'s source, `pivot_root` and the absolute-path
        // forms have no dirfd.
        "mount" | "pivot_root" | "symlink" | "rename" | "link" => AT_FDCWD,
        _ => {
            if path_idx >= 1 {
                raw(path_idx - 1)
            } else {
                AT_FDCWD
            }
        }
    }
}

/// A lexical path component, as the kernel walks it.
enum Lex {
    Name(Vec<u8>),
    Parent,
}

/// Most symlinks one resolution follows: the kernel's `MAXSYMLINKS`.
const MAX_SYMLINKS: u32 = 40;

/// Walk `path` as the target would resolve it, recording each component.
///
/// Symlinks are resolved here rather than by the kernel: an absolute target
/// must restart at the *target's* root, and a kernel walk through
/// `/proc/<pid>/root/...` would restart it at ours. `cur` therefore never
/// contains a symlink, which also makes `..` physical, as in the kernel.
///
/// The target's memory is read once by `capture_path` and again here; a
/// sibling thread can change the buffer between the two (inherent to
/// seccomp-notify).
fn file_token_for(pid: Pid, dirfd: i32, path: &[u8], follow_final: bool) -> Option<FileToken> {
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let root = PathBuf::from(format!("/proc/{pid}/root"));
    let id = |md: &std::fs::Metadata| (device_of(md), inode_of(md));
    let root_id = id(&std::fs::metadata(&root).ok()?);

    let mut cur = if path.first() == Some(&b'/') {
        root.clone()
    } else if dirfd == AT_FDCWD {
        PathBuf::from(format!("/proc/{pid}/cwd"))
    } else {
        PathBuf::from(format!("/proc/{pid}/fd/{dirfd}"))
    };
    let (anchor_dev, anchor_ino) = id(&std::fs::metadata(&cur).ok()?);
    let mut dir = (anchor_dev, anchor_ino);

    // Components still to walk; a followed symlink splices its target in
    // at the front.
    let mut todo: VecDeque<Lex> = lexical_components(path).into();
    let mut chain = Vec::new();
    let mut hops = 0;
    while let Some(comp) = todo.pop_front() {
        let name = match comp {
            // The kernel clamps `..` at the process's root.
            Lex::Parent if dir == root_id => continue,
            Lex::Parent => b"..".to_vec(),
            Lex::Name(n) => n,
        };
        let next = cur.join(OsStr::from_bytes(&name));
        let Ok(md) = std::fs::symlink_metadata(&next) else {
            // Does not exist (yet): record the entry it would bind and stop;
            // nothing past it resolves.
            chain.push(ComponentKey { name, parent: dir, obj: None });
            break;
        };
        let obj = id(&md);
        chain.push(ComponentKey { name, parent: dir, obj: Some(obj) });
        if md.file_type().is_symlink() && (!todo.is_empty() || follow_final) {
            hops += 1;
            let Ok(target) = std::fs::read_link(&next) else { break };
            if hops > MAX_SYMLINKS {
                break;
            }
            let target = target.as_os_str().as_bytes();
            if target.first() == Some(&b'/') {
                cur = root.clone();
                dir = root_id;
            }
            // A relative target resolves against the link's directory, which
            // is still `cur`/`dir`.
            for c in lexical_components(target).into_iter().rev() {
                todo.push_front(c);
            }
            continue;
        }
        cur = next;
        dir = obj;
    }

    Some(FileToken { anchor_dev, anchor_ino, chain })
}

/// Split a path into the components a lexical walk visits: `.` and empty
/// components (`//`) are skipped, `..` is a pop.
fn lexical_components(path: &[u8]) -> Vec<Lex> {
    let mut out = Vec::new();
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => out.push(Lex::Parent),
            name => out.push(Lex::Name(name.to_vec())),
        }
    }
    out
}

fn device_of(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.dev()
}

fn inode_of(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}

impl CheckpointBackend for SeccompNotifyBackend {
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()> {
        let unresolved = self.resolve_checkpoints(checkpoints);
        if !unresolved.is_empty() {
            log::warn!(
                "{} of {} declared checkpoints do not exist on this architecture and were \
                 not attached: {}",
                unresolved.len(),
                checkpoints.len(),
                unresolved
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if self.watched.is_empty() {
            bail!("no declared checkpoint resolved to a syscall on this architecture");
        }
        log::info!(
            "attached {} syscall checkpoint(s) to {} process(es) in cgroup {}",
            self.watched.len(),
            self.specs.len(),
            self.cgroup
        );

        std::fs::create_dir_all(self.cgroup_dir())
            .with_context(|| format!("creating cgroup {}", self.cgroup))?;

        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).context("epoll_create")?;
        let watch = |fd: RawFd| {
            // SAFETY: every fd here outlives its place in the set: a
            // Listener's are dropped with the backend, and `wake_fd`'s owner
            // drops it after this backend.
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            epoll
                .add(fd, EpollEvent::new(EpollFlags::EPOLLIN, fd.as_raw_fd() as u64))
                .context("adding an fd to the epoll set")
        };
        if let Some(fd) = self.wake_fd {
            watch(fd)?;
        }
        for spec in self.specs.clone().into_iter() {
            let l = self
                .spawn(&spec)
                .with_context(|| format!("spawning `{}`", spec.argv.join(" ")))?;
            log::debug!("spawned pid {} for `{}`", l.child, spec.argv.join(" "));
            watch(l.fd.as_raw_fd())?;
            watch(l.pidfd.as_ref().unwrap().as_raw_fd())?;
            self.listeners.push(l);
        }
        self.epoll = Some(epoll);
        Ok(())
    }

    fn spawned(&self) -> Vec<Pid> {
        self.listeners.iter().map(|l| l.child).collect()
    }

    fn poll(&mut self, timeout: Option<Duration>) -> Result<Poll> {
        self.wait(timeout)?;
        self.reap();
        // A thread that died parked never has its notification answered.
        // Once the children are gone, forget such ids, or the backend could
        // never close.
        if !self.live() {
            self.pending
                .retain(|id, p| libseccomp::notify_id_valid(p.fd, *id).is_ok());
        }

        let mut ready = vec![EpollEvent::empty(); 2 * self.listeners.len() + 1];
        let n = match &self.epoll {
            Some(epoll) => match epoll.wait(&mut ready, PollTimeout::ZERO) {
                Err(nix::errno::Errno::EINTR) => 0,
                r => r.context("polling the notify fds")?,
            },
            None => 0,
        };

        let mut events = Vec::new();
        for ev in &ready[..n] {
            // The data is the fd; a pidfd or `wake_fd` is matched by no
            // listener, and only had to end the wait.
            let fd = ev.data() as RawFd;
            let Some(spawn_idx) = self
                .listeners
                .iter()
                .position(|l| l.fd.as_raw_fd() == fd && !l.hung_up)
            else {
                continue;
            };
            if !ev.events().contains(EpollFlags::EPOLLIN) {
                // No notification, and nothing holds the filter: nothing will
                // ever arrive on this fd again.
                if ev.events().contains(EpollFlags::EPOLLHUP) {
                    self.listeners[spawn_idx].hung_up = true;
                    if let Some(epoll) = &self.epoll {
                        epoll.delete(&self.listeners[spawn_idx].fd)?;
                    }
                }
                continue;
            }
            // Every pending notification, not just one: the threads of a tree
            // share this fd, and a hit left unread would trail its thread's
            // records by a batch. Checked before each receive because receive
            // blocks when none is pending, whatever O_NONBLOCK says.
            while readable(fd) {
                let req = match ScmpNotifReq::receive(fd) {
                    Ok(r) => r,
                    // The task died between the readiness check and receive.
                    // Not an error.
                    Err(_) => continue,
                };
                let pid = req.pid as Pid;
                let nr = req.data.syscall.as_raw_syscall();
                log::debug!(
                    "notification: pid {} nr {} ({}) -> {:?}",
                    pid,
                    nr,
                    req.data.syscall.get_name().unwrap_or_else(|_| "?".into()),
                    self.watched.get(&nr).map(|c| c.as_str())
                );
                // The launch exec. `child_setup` makes no watched syscall
                // between loading the filter and `execv`, so the child's
                // first notification is that exec if `execve` is watched.
                // It is the backend's own action, not the target's: let it
                // through unreported, so it never reaches the engine under
                // the engine's own `comm`.
                let listener = &mut self.listeners[spawn_idx];
                if !listener.launched && pid == listener.child {
                    listener.launched = true;
                    if req.data.syscall == ScmpSyscall::from_name("execve")? {
                        let _ = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::CONTINUE)
                            .respond(fd);
                        continue;
                    }
                }

                let Some(checkpoint) = self.watched.get(&nr).cloned() else {
                    // Not ours to hold; let it through immediately.
                    let _ = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::CONTINUE)
                        .respond(fd);
                    continue;
                };

                if !self.announced.contains(&pid) {
                    self.announced.push(pid);
                    match read_task_info(pid) {
                        Ok(t) => events.push(BackendEvent::TaskAppeared(t)),
                        Err(e) => log::warn!("could not read /proc for pid {pid}: {e}"),
                    }
                }
                // After an exec the task is a different program, with a
                // different `comm`. A pid is announced once, from what
                // /proc says at its first notification -- which, for a
                // task that execs into a role binary from something that
                // is not a role (a shim forking and exec'ing `runc`), is
                // the *old* program, matching no role. Forget it, so its
                // next notification announces it again as what it now
                // is. A pid that already resolved to a role stays in the
                // role table's sticky cache, so this cannot move it.
                let name = req.data.syscall.get_name().unwrap_or_default();
                if name == "execve" || name == "execveat" {
                    self.announced.retain(|p| *p != pid);
                }
                // Capture the path this use-shaped syscall resolved, so the
                // orchestration can point the attacker at it. Best-effort:
                // a failure leaves `path` None and the run continues.
                let path = capture_path(pid, &req.data.args, &name, fd, req.id);
                // Capture every conflict key the syscall touches, for POS.
                // Best-effort and empty for a non-path syscall.
                let keys =
                    capture_keys(pid, &req.data.args, &name, fd, req.id).unwrap_or_default();
                self.pending.insert(
                    req.id,
                    Pending {
                        fd,
                        pid,
                        args: req.data.args,
                        name,
                    },
                );
                events.push(BackendEvent::CheckpointHit {
                    pid,
                    checkpoint,
                    handle: NotifyHandle(req.id),
                    path,
                    keys,
                });
            }
        }

        if !events.is_empty() {
            return Ok(Poll::Events(events));
        }
        if self.closed() {
            return Ok(Poll::Closed);
        }
        Ok(Poll::Idle)
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        let Some(Pending { fd, .. }) = self.pending.remove(&handle.0) else {
            log::warn!("release of unknown notification id {}", handle.0);
            return Ok(());
        };
        // CONTINUE, not a synthesised return value: this engine decides *when*
        // a syscall runs, never what it does. (For a security filter CONTINUE
        // would be the wrong answer, because the arguments can change between
        // the check and the call -- but that TOCTOU is the subject here, not a
        // hazard to avoid.)
        ScmpNotifResp::new_continue(handle.0, ScmpNotifRespFlags::CONTINUE)
            .respond(fd)
            .with_context(|| format!("releasing notification {}", handle.0))?;
        Ok(())
    }

    fn recapture(&mut self, handle: NotifyHandle) -> Result<Option<Vec<ConflictKey>>> {
        let Some(p) = self.pending.get(&handle.0) else {
            return Ok(None);
        };
        let keys = capture_keys(p.pid, &p.args, &p.name, p.fd, handle.0);
        if keys.is_none() {
            // Dead for good: interrupted by a signal, or its thread is gone.
            self.pending.remove(&handle.0);
        }
        Ok(keys)
    }

    fn freeze(&mut self, _tid: Pid) -> Result<()> {
        bail!("freezing a thread needs the sched_ext gate (GateBackend)")
    }

    fn thaw(&mut self, _tid: Pid) -> Result<()> {
        bail!("thawing a thread needs the sched_ext gate (GateBackend)")
    }

    fn gate_group(&mut self, _tgid: Pid) -> Result<()> {
        bail!("gating a thread group needs the sched_ext gate (GateBackend)")
    }

    fn ungate_group(&mut self, _tgid: Pid) -> Result<()> {
        bail!("ungating a thread group needs the sched_ext gate (GateBackend)")
    }

    fn cpu_ns(&self, tid: Pid) -> Option<u64> {
        cpu_ns(tid)
    }

    fn wakes_on_its_own(&self, tid: Pid) -> bool {
        wakes_on_its_own(tid)
    }

    /// No sensor, so nothing to lose.
    fn dropped(&self) -> Result<u64> {
        Ok(0)
    }

    /// Anything in the epoll set ready: a notification, a child's exit, or
    /// `wake_fd`.
    fn pending(&self) -> bool {
        let Some(epoll) = &self.epoll else {
            return false;
        };
        epoll
            .wait(&mut [EpollEvent::empty()], PollTimeout::ZERO)
            .is_ok_and(|n| n > 0)
    }
}

#[cfg(test)]
mod walk_tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    fn me() -> Pid {
        std::process::id() as Pid
    }
    fn names(t: &FileToken) -> Vec<String> {
        t.chain.iter().map(|c| String::from_utf8_lossy(&c.name).into_owned()).collect()
    }
    fn ino(p: &std::path::Path) -> u64 {
        inode_of(&std::fs::metadata(p).unwrap())
    }

    #[test]
    fn a_followed_symlink_records_both_the_link_and_its_target() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("f"), b"x").unwrap();
        symlink(&real, d.path().join("link")).unwrap(); // absolute target
        let p = d.path().join("link/f");
        let t = file_token_for(me(), AT_FDCWD, p.as_os_str().as_bytes(), true).unwrap();
        let n = names(&t);
        assert!(n.contains(&"link".to_string()), "{n:?}");
        assert!(n.contains(&"real".to_string()), "the target's own path is walked: {n:?}");
        assert_eq!(n.last().unwrap(), "f");
        assert!(t.chain.iter().any(|c| c.obj.map(|o| o.1) == Some(ino(&real))));
    }

    #[test]
    fn an_unfollowed_final_symlink_is_its_own_leaf() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("t"), b"x").unwrap();
        symlink("t", d.path().join("l")).unwrap();
        let p = d.path().join("l");
        let t = file_token_for(me(), AT_FDCWD, p.as_os_str().as_bytes(), false).unwrap();
        assert_eq!(names(&t).last().unwrap(), "l");
    }

    #[test]
    fn a_missing_name_is_recorded_without_an_object() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("new/deeper");
        let t = file_token_for(me(), AT_FDCWD, p.as_os_str().as_bytes(), true).unwrap();
        let last = t.chain.last().unwrap();
        assert_eq!(last.name, b"new");
        assert_eq!(last.obj, None);
        assert_eq!(last.parent.1, ino(d.path()));
    }

    #[test]
    fn dotdot_past_a_symlink_goes_to_the_targets_parent() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("x/y")).unwrap();
        symlink(d.path().join("x/y"), d.path().join("s")).unwrap();
        let p = d.path().join("s/..");
        let t = file_token_for(me(), AT_FDCWD, p.as_os_str().as_bytes(), true).unwrap();
        assert_eq!(t.chain.last().unwrap().obj.unwrap().1, ino(&d.path().join("x")));
    }

    #[test]
    fn dotdot_at_the_root_stays_at_the_root() {
        let t = file_token_for(me(), AT_FDCWD, b"/../..", true).unwrap();
        assert!(t.chain.is_empty(), "clamped at the root: {:?}", names(&t));
    }

    #[test]
    fn each_timed_wait_s_timeout_is_read_where_it_lives() {
        // A `/proc/<tid>/syscall` line for syscall `nr` with `args`.
        let line = |nr: libc::c_long, args: [u64; 6]| {
            let hex: Vec<String> = args.iter().map(|a| format!("{a:#x}")).collect();
            format!("{nr} {} 0xffff0000 0x400000", hex.join(" "))
        };
        const P: u64 = 0xffff_1234; // a timeout pointer
        const FOREVER: u64 = u64::MAX; // -1
        let cases: Vec<(libc::c_long, [u64; 6], bool)> = vec![
            (libc::SYS_nanosleep, [P, 0, 0, 0, 0, 0], true),
            (libc::SYS_clock_nanosleep, [1, 0, P, 0, 0, 0], true),
            (libc::SYS_futex, [P, 0, 1, P, 0, 0], true),
            (libc::SYS_futex, [P, 0, 1, 0, 0, 0], false),
            (libc::SYS_epoll_pwait2, [3, P, 8, P, 0, 8], true),
            (libc::SYS_epoll_pwait2, [3, P, 8, 0, 0, 8], false),
            (libc::SYS_semtimedop, [1, P, 1, P, 0, 0], true),
            (libc::SYS_semtimedop, [1, P, 1, 0, 0, 0], false),
            (libc::SYS_ppoll, [P, 1, P, 0, 8, 0], true),
            (libc::SYS_ppoll, [P, 1, 0, 0, 8, 0], false),
            (libc::SYS_rt_sigtimedwait, [P, 0, P, 8, 0, 0], true),
            (libc::SYS_rt_sigtimedwait, [P, 0, 0, 8, 0, 0], false),
            (libc::SYS_pselect6, [4, P, 0, 0, P, 0], true),
            (libc::SYS_pselect6, [4, P, 0, 0, 0, 0], false),
            (libc::SYS_mq_timedreceive, [3, P, 64, 0, P, 0], true),
            (libc::SYS_mq_timedreceive, [3, P, 64, 0, 0, 0], false),
            (libc::SYS_epoll_pwait, [3, P, 8, 10, 0, 8], true),
            (libc::SYS_epoll_pwait, [3, P, 8, FOREVER, 0, 8], false),
            (libc::SYS_read, [0, P, 1, 0, 0, 0], false),
            (libc::SYS_execve, [P, P, P, 0, 0, 0], true),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_poll, [P, 1, 10, 0, 0, 0], true),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_poll, [P, 1, FOREVER, 0, 0, 0], false),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_epoll_wait, [3, P, 8, 10, 0, 0], true),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_epoll_wait, [3, P, 8, FOREVER, 0, 0], false),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_select, [4, P, 0, 0, P, 0], true),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_select, [4, P, 0, 0, 0, 0], false),
        ];
        for (nr, args, timed) in cases {
            assert_eq!(self_waking_syscall(&line(nr, args)), timed, "{}", line(nr, args));
        }
        assert!(self_waking_syscall("-1 0xffff0000 0x400000"), "a page fault");
        assert!(self_waking_syscall("running"), "awake again");
    }

    #[test]
    fn timed_sleeps_are_told_from_untimed_waits() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (_hold, wait) = std::sync::mpsc::channel::<()>();
        let sleeper = std::thread::spawn({
            let tx = tx.clone();
            move || {
                // SAFETY: a plain syscall.
                tx.send(unsafe { libc::gettid() }).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });
        let waiter = std::thread::spawn(move || {
            // SAFETY: a plain syscall.
            tx.send(unsafe { libc::gettid() }).unwrap();
            let _ = wait.recv();
        });
        let (a, b) = (rx.recv().unwrap(), rx.recv().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(100));
        let timed: Vec<bool> = [a, b].iter().map(|t| wakes_on_its_own(*t)).collect();
        drop(_hold);
        sleeper.join().unwrap();
        waiter.join().unwrap();
        // One of the two is the sleeper; channel order is not fixed.
        let mut timed = timed;
        timed.sort();
        assert_eq!(timed, [false, true], "an untimed futex wait and a nanosleep");
    }

    #[test]
    fn a_symlink_loop_terminates() {
        let d = tempfile::tempdir().unwrap();
        symlink(d.path().join("b"), d.path().join("a")).unwrap();
        symlink(d.path().join("a"), d.path().join("b")).unwrap();
        let p = d.path().join("a/x");
        assert!(file_token_for(me(), AT_FDCWD, p.as_os_str().as_bytes(), true).is_some());
    }
}
