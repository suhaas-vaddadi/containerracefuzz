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
use crate::backend::EXIT_HANDLE;
use crate::checkpoint::CheckpointDecl;
use crate::checkpoint::CheckpointId;
use crate::checkpoint::CheckpointKind;
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
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

/// Where the unified cgroup v2 hierarchy is mounted.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// Checkpoint targets that libseccomp spells differently, tried as a fallback
/// when the declared spelling resolves to nothing.
///
/// Design doc section 4.2 names this one `fstatat`; libseccomp (and the aarch64
/// kernel) call it `newfstatat`. Without this the doc's own default checkpoint
/// set silently loses its entire path-*resolving* half on aarch64 -- which is
/// half of what a TOCTOU race is made of.
const ARCH_ALIASES: &[(&str, &str)] = &[("fstatat", "newfstatat")];

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
    reaped: bool,
    /// The child's exit status in shell convention -- its exit code, or
    /// `128 + signo` if a signal killed it. `None` until it has been reaped.
    ///
    /// Kept because a wrapper standing in for the process it instruments has to
    /// report *its* status, not the engine's verdict on the scheduling run.
    exit_code: Option<i32>,
    /// The child is gone but `waitpid` has not caught up yet. Its fd reports
    /// POLLHUP, which is level-triggered and never clears, so leaving it in the
    /// poll set turns every subsequent `poll` into a no-op that returns
    /// immediately. See `poll` for why that is a correctness bug and not just a
    /// busy-wait.
    hung_up: bool,
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
    /// Notification id -> the fd it must be answered on.
    pending: HashMap<u64, RawFd>,
    /// pids already announced via `TaskAppeared`.
    announced: Vec<Pid>,
    poll_timeout: Duration,
    /// Place each `--spawn` in its own `<cgroup>/spawn<i>` subdirectory rather
    /// than all of them in `cgroup` directly.
    ///
    /// Off by default, so the cgroup layout of an ordinary run is unchanged.
    /// `backend_freezer::FreezerBackend` needs it on: the freezer acts on
    /// whatever cgroup the held task is in, so with one shared cgroup the first
    /// role to reach a checkpoint freezes every other role along with it --
    /// measured, as a second role that then never reaches a checkpoint at all.
    ///
    /// Safe with role resolution because a role's cgroup matcher is a prefix
    /// test (`role.rs`, `resolve_role`), so a task in `<cgroup>/spawn0` still
    /// matches a role declaring `<cgroup>`.
    per_spawn_cgroups: bool,
    /// Place each spawned target in `SCHED_EXT` before `exec`, so the gate's
    /// scheduler sees it. Off by default: with `SCX_OPS_SWITCH_PARTIAL` an
    /// un-enrolled task stays on CFS, which is exactly what the non-`--gate`
    /// paths want.
    sched_ext: bool,
    /// Every notification, in the order it was received, as
    /// `<spawn index>:<checkpoint>`.
    ///
    /// This is the direct measurement for design doc section 14-A. Section 10.1
    /// claims ordering determinism "holds trivially if `decide()` is a pure
    /// function of `(seed, ready-set-sequence)`" -- but that constrains only
    /// `decide()`. 14-A points out it says nothing about whether the
    /// ready-set-sequence is itself reproducible, since arrival order is a
    /// function of real OS scheduling races between processes independently
    /// approaching their own checkpoints.
    ///
    /// Deliberately free of pids and timings, for the same reason the canonical
    /// log is (Background): they differ every run by construction, so including
    /// them would make two runs incomparable and answer nothing. The spawn
    /// index is stable because it is the position of the `--spawn` argument,
    /// and it is taken from the listener fd the notification arrived on, so a
    /// fork/exec descendant is attributed to the tree it belongs to.
    arrival: Vec<String>,
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
            poll_timeout: Duration::from_millis(50),
            per_spawn_cgroups: false,
            sched_ext: false,
            arrival: Vec::new(),
        }
    }

    pub fn with_per_spawn_cgroups(mut self, yes: bool) -> Self {
        self.per_spawn_cgroups = yes;
        self
    }

    pub fn with_sched_ext(mut self, yes: bool) -> Self {
        self.sched_ext = yes;
        self
    }

    /// The cgroup a given `--spawn` index is placed in, as it appears in
    /// `/proc/<pid>/cgroup`.
    pub fn spawn_cgroup(&self, idx: usize) -> String {
        if self.per_spawn_cgroups {
            format!("{}/spawn{idx}", self.cgroup.trim_end_matches('/'))
        } else {
            self.cgroup.clone()
        }
    }

    pub fn with_poll_timeout(mut self, d: Duration) -> Self {
        self.poll_timeout = d;
        self
    }

    /// The ready-set arrival order, for section 14-A. See `arrival`.
    pub fn arrival_trace(&self) -> &[String] {
        &self.arrival
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
            if decl.kind != CheckpointKind::Syscall {
                unresolved.push(decl.id.clone());
                continue;
            }
            let alias = ARCH_ALIASES
                .iter()
                .find(|(from, _)| *from == decl.target)
                .map(|(_, to)| *to);
            let nr = [Some(decl.target.as_str()), alias]
                .into_iter()
                .flatten()
                .find_map(|name| match ScmpSyscall::from_name(name) {
                    // A negative number is a libseccomp pseudo-syscall: the
                    // call does not exist on this architecture. See above.
                    Ok(sys) if sys.as_raw_syscall() >= 0 => Some(sys.as_raw_syscall()),
                    _ => None,
                });

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

    fn spawn(&self, spec: &ProcessSpec, idx: usize) -> Result<Listener> {
        let (parent_sock, child_sock) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .context("socketpair for notify-fd handoff")?;

        let watched: Vec<i32> = self.watched.keys().copied().collect();
        let cgroup_procs = PathBuf::from(CGROUP_MOUNT)
            .join(self.spawn_cgroup(idx).trim_start_matches('/'))
            .join("cgroup.procs");

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
                    reaped: false,
                    exit_code: None,
                    hung_up: false,
                })
            }
        }
    }

    /// Reap any child that has exited, newest state first.
    fn reap(&mut self, events: &mut Vec<BackendEvent>) {
        loop {
            let status = waitpid(None, Some(WaitPidFlag::WNOHANG));
            match status {
                Ok(WaitStatus::Exited(pid, _)) | Ok(WaitStatus::Signaled(pid, _, _)) => {
                    let raw = pid.as_raw();
                    // Shell convention, so a wrapper can pass it straight to
                    // `exit` and have a caller read it the usual way.
                    let code = match status {
                        Ok(WaitStatus::Exited(_, c)) => c,
                        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                        _ => unreachable!("outer match admitted only these two"),
                    };
                    if let Some(i) = self.listeners.iter().position(|l| l.child == raw) {
                        self.listeners[i].reaped = true;
                        self.listeners[i].exit_code = Some(code);
                        // An exit becomes a ready-set entry too (the engine
                        // turns it into a synthetic `exit` checkpoint), so
                        // section 14-A applies to exits exactly as it does to
                        // checkpoint hits -- and exits arrive by a completely
                        // separate channel (waitpid) from notifications, with
                        // no ordering relationship between the two.
                        self.arrival.push(format!("{i}:exit"));
                    }
                    events.push(BackendEvent::TaskExited(raw));
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

    /// The first spawn's exit status, in shell convention, once it has been
    /// reaped.
    ///
    /// The *first* specifically: this exists for the wrapper case, where
    /// `scx_crfuzz` stands in for a single binary and has to answer for it.
    /// With several spawns there is no single status to report, and the caller
    /// is expected not to ask -- `main` refuses the flag rather than picking.
    pub fn child_exit_code(&self) -> Option<i32> {
        self.listeners.first().and_then(|l| l.exit_code)
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
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        bail!(
            "making the notify fd non-blocking: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
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

        for idx in 0..self.specs.len() {
            let cg = self.spawn_cgroup(idx);
            std::fs::create_dir_all(PathBuf::from(CGROUP_MOUNT).join(cg.trim_start_matches('/')))
                .with_context(|| format!("creating cgroup {cg}"))?;
        }

        for (idx, spec) in self.specs.clone().into_iter().enumerate() {
            let l = self
                .spawn(&spec, idx)
                .with_context(|| format!("spawning `{}`", spec.argv.join(" ")))?;
            log::debug!("spawned pid {} for `{}`", l.child, spec.argv.join(" "));
            self.listeners.push(l);
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<Poll> {
        let mut events = Vec::new();
        self.reap(&mut events);

        // (spawn index, fd). The index is carried through so a notification
        // can be attributed to the process tree it came from.
        let fds: Vec<(usize, RawFd)> = self
            .listeners
            .iter()
            .enumerate()
            .filter(|(_, l)| !l.reaped && !l.hung_up)
            .map(|(i, l)| (i, l.fd.as_raw_fd()))
            .collect();

        if !fds.is_empty() {
            // SAFETY: every fd is owned by a Listener that outlives this call.
            let borrowed: Vec<BorrowedFd> = fds
                .iter()
                .map(|(_, f)| unsafe { BorrowedFd::borrow_raw(*f) })
                .collect();
            let mut pollfds: Vec<nix::poll::PollFd> = borrowed
                .iter()
                .map(|f| nix::poll::PollFd::new(*f, nix::poll::PollFlags::POLLIN))
                .collect();

            // Blocking with a timeout rather than spinning: the engine treats
            // consecutive idle polls as a stall, so a busy-wait here would
            // time out a run in microseconds, before the target had a chance to
            // reach its first checkpoint.
            let timeout: u16 = self.poll_timeout.as_millis().try_into().unwrap_or(u16::MAX);
            let ready = nix::poll::poll(&mut pollfds, timeout).context("polling notify fds")?;

            if ready > 0 {
                for (i, pfd) in pollfds.iter().enumerate() {
                    let revents = pfd.revents().unwrap_or(nix::poll::PollFlags::empty());
                    if !revents.contains(nix::poll::PollFlags::POLLIN) {
                        // No notification, and the writer is gone: nothing will
                        // ever arrive on this fd again. Retire it from the poll
                        // set so the exit can be reaped at leisure instead of
                        // being raced by a spin.
                        if revents.contains(nix::poll::PollFlags::POLLHUP) {
                            self.listeners[fds[i].0].hung_up = true;
                        }
                        continue;
                    }
                    let (spawn_idx, fd) = fds[i];
                    let req = match ScmpNotifReq::receive(fd) {
                        Ok(r) => r,
                        // The task died between poll and receive, or another
                        // notification raced us. Neither is an error.
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
                    self.arrival.push(format!("{spawn_idx}:{checkpoint}"));
                    self.pending.insert(req.id, fd);
                    events.push(BackendEvent::CheckpointHit {
                        pid,
                        checkpoint,
                        handle: NotifyHandle(req.id),
                    });
                }
            }
        } else if self.live() {
            // Every live child has hung up but none has been reaped yet. There
            // is nothing to wait *on*, and returning straight away would spend
            // the engine's whole idle budget in microseconds -- so wait anyway,
            // for as long as the poll would have. An idle poll has to cost real
            // time, because the engine's stall detector counts polls and has
            // nothing else with which to measure a stall.
            std::thread::sleep(self.poll_timeout);
        }

        if !events.is_empty() {
            return Ok(Poll::Events(events));
        }
        if !self.live() && self.pending.is_empty() {
            return Ok(Poll::Closed);
        }
        Ok(Poll::Idle)
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        if handle == EXIT_HANDLE {
            return Ok(());
        }
        let Some(fd) = self.pending.remove(&handle.0) else {
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
}
