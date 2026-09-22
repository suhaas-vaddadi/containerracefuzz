// SPDX-License-Identifier: GPL-2.0
//
// PROOF OF CONCEPT. Not the intended holding mechanism -- see "Why this is not
// the answer" below, and the `ops.dispatch` TODO in the crate README.
//
// A decorator that extends another backend's hold from one *thread* to a whole
// *thread group*, using the cgroup v2 freezer.
//
// The design doc's Background says a role denotes a thread group and "holding a
// role back means holding every thread of that thread group".
// `backend_seccomp::SeccompNotifyBackend` does not deliver that: seccomp
// user-notification suspends only the thread that made the syscall, so sibling
// threads keep running. tests/thread_group_holding.rs measures the gap -- with
// seccomp alone a 1ms-per-iteration sibling writes ~255 bytes during a 300ms
// hold.
//
// This wrapper closes it by writing `1` to the held task's `cgroup.freeze` the
// moment the inner backend reports a checkpoint hit, and `0` again when the
// engine releases it. Nothing in the cgroup gets CPU while frozen, siblings
// included.
//
// Composition, not replacement: seccomp still supplies the *precision* (stop
// exactly at this syscall), and the freezer supplies the *group coverage*. The
// inner backend is generic so the same decorator works over any future one.
//
// WHY THIS IS NOT THE ANSWER, and why `ops.dispatch` is still the plan:
//
//   - IT PERTURBS THE SYSCALL IT IS HOLDING. This is the serious one, and it
//     was found here rather than reasoned about. Freezing a cgroup wakes every
//     task in it, including one parked in a seccomp notification; that wait is
//     interruptible, so the kernel tears the notification down, restarts the
//     syscall (`ERESTARTSYS`), and the restarted call re-enters the filter and
//     raises a *fresh* notification with a new id. Measured directly: old id
//     14407828070108571077 stopped being answerable the moment the cgroup
//     froze, and id ...078 appeared in its place for the same task at the same
//     checkpoint.
//
//     Two consequences. Mechanically, a notification id is no longer stable for
//     the lifetime of a hold, which is what `live` and `stale` below exist to
//     paper over. Semantically -- and this is the part that matters for a study
//     of races -- the held syscall is *re-executed* from the kernel's point of
//     view. For an idempotent path-resolving call like `fstatat` that is
//     survivable; for a call whose re-entry is observable it is a change to the
//     behavior under test, introduced by the instrument. `ops.dispatch` never
//     touches the syscall path, so it has nothing of this kind to correct for.
//
//   - The boundary is fuzzy. `cgroup.freeze` is asynchronous: the write
//     returns immediately and tasks converge to frozen over the following
//     milliseconds, which this code waits out by polling `cgroup.events`.
//     Between the inner backend reporting a hit and that convergence, siblings
//     are still running. The window is bounded and measured (see
//     `FreezeStats`), not eliminated.
//   - A task in uninterruptible sleep (D state) cannot be frozen until it
//     wakes, so convergence has no upper bound in principle. `ops.dispatch`
//     handles this for free: a sleeping task is not on a CPU anyway, and gets
//     gated on its way back in.
//   - Freeze/thaw costs milliseconds per step, which caps how many
//     interleavings a discovery run can explore per second.
//
// A `sched_ext` `ops.dispatch` backend has none of these properties: gating is
// a map lookup on the enqueue path, so the boundary is one scheduling round
// and a sleeping task is handled by construction.

use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::NotifyHandle;
use crate::backend::Poll;
use crate::checkpoint::CheckpointDecl;
use crate::role::Pid;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Where the unified cgroup v2 hierarchy is mounted.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// How long to wait for `cgroup.events` to report `frozen 1` before giving up.
///
/// Freezing cannot complete while any task in the cgroup is in uninterruptible
/// sleep, so this is a real failure mode rather than defensive padding -- it is
/// the D-state limitation in the header, made observable instead of hanging.
const FREEZE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often to re-read `cgroup.events` while waiting for convergence.
const FREEZE_POLL: Duration = Duration::from_micros(200);

/// How long `release` will chase a notification id that a freeze invalidated
/// before giving up. See the header: after a thaw the task restarts its
/// syscall and re-notifies, but not instantly.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// What the freezer cost and how fuzzy its boundary was, per operation.
///
/// Recorded because the whole reason this backend is a proof of concept rather
/// than the answer is its asynchronous boundary. Measuring it is what makes the
/// case for `ops.dispatch` an argument from evidence rather than from theory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FreezeStats {
    pub freezes: usize,
    pub thaws: usize,
    /// Worst time spent waiting for `frozen 1` after requesting a freeze. This
    /// is the window during which sibling threads were still running.
    pub max_freeze_latency: Duration,
}

/// Extends an inner backend's per-thread hold to the whole thread group.
#[derive(Debug)]
pub struct FreezerBackend<B: CheckpointBackend> {
    inner: B,
    /// Handle as the engine knows it -> the task it belongs to.
    ///
    /// The engine keeps whichever handle it was first told about, so this is
    /// how a release of that handle finds its way to whatever notification the
    /// task is actually parked on now.
    owner: HashMap<NotifyHandle, Pid>,
    /// Task -> the notification it is parked on *right now*.
    ///
    /// Diverges from `owner` as soon as a freeze restarts the syscall: see the
    /// header. Always the id to answer.
    live: HashMap<Pid, NotifyHandle>,
    /// Task -> the cgroup whose freezer governs it, as an absolute filesystem
    /// path under `/sys/fs/cgroup`.
    ///
    /// Learned from the `CheckpointHit` the inner backend reports, via
    /// `/proc/<pid>/cgroup`. Deliberately *not* taken from any configured
    /// cgroup path: a fork/exec descendant is in whatever cgroup it inherited,
    /// and that is the one whose freezer governs it.
    cgroups: HashMap<Pid, PathBuf>,
    /// Tasks already reported to the engine as being at a checkpoint.
    ///
    /// A freeze-induced restart raises a second notification for a task that is
    /// at the same checkpoint it was already reported at. Reporting that again
    /// would put a duplicate in the ready set and corrupt the canonical log, so
    /// the restart is absorbed here.
    reported: Vec<Pid>,
    /// Events observed while resolving a stale handle inside `release`, held
    /// over for the next `poll` rather than dropped.
    deferred: Vec<BackendEvent>,
    /// Cgroups currently frozen by this backend, so a second hit inside an
    /// already-frozen group does not pay for a redundant freeze.
    frozen: Vec<PathBuf>,
    stats: FreezeStats,
}

impl<B: CheckpointBackend> FreezerBackend<B> {
    pub fn new(inner: B) -> Self {
        FreezerBackend {
            inner,
            owner: HashMap::new(),
            live: HashMap::new(),
            cgroups: HashMap::new(),
            reported: Vec::new(),
            deferred: Vec::new(),
            frozen: Vec::new(),
            stats: FreezeStats::default(),
        }
    }

    pub fn stats(&self) -> &FreezeStats {
        &self.stats
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    fn freeze(&mut self, cgroup: &PathBuf) -> Result<()> {
        if self.frozen.contains(cgroup) {
            return Ok(());
        }
        std::fs::write(cgroup.join("cgroup.freeze"), "1")
            .with_context(|| format!("freezing {}", cgroup.display()))?;
        let started = Instant::now();
        wait_until_frozen(cgroup, true)?;
        let latency = started.elapsed();

        self.stats.freezes += 1;
        self.stats.max_freeze_latency = self.stats.max_freeze_latency.max(latency);
        self.frozen.push(cgroup.clone());
        Ok(())
    }

    fn thaw(&mut self, cgroup: &PathBuf) -> Result<()> {
        if !self.frozen.contains(cgroup) {
            return Ok(());
        }
        std::fs::write(cgroup.join("cgroup.freeze"), "0")
            .with_context(|| format!("thawing {}", cgroup.display()))?;
        // Waited on, and NOT merely for tidiness: answering a seccomp
        // notification for a task that has not finished leaving the freezer
        // fails the SEND ioctl outright ("system failure beyond the control of
        // libseccomp"). Measured -- a release issued immediately after writing
        // `0` fails every time, and the same release succeeds once the cgroup
        // reports `frozen 0`.
        wait_until_frozen(cgroup, false)?;
        self.stats.thaws += 1;
        self.frozen.retain(|c| c != cgroup);
        Ok(())
    }
}

impl<B: CheckpointBackend> CheckpointBackend for FreezerBackend<B> {
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()> {
        self.inner.attach(checkpoints)
    }

    fn poll(&mut self) -> Result<Poll> {
        let polled = self.inner.poll()?;
        let mut events = match polled {
            Poll::Events(e) => e,
            other => {
                if self.deferred.is_empty() {
                    return Ok(other);
                }
                Vec::new()
            }
        };
        events.splice(0..0, std::mem::take(&mut self.deferred));

        let mut out = Vec::with_capacity(events.len());
        for event in events {
            let BackendEvent::CheckpointHit { pid, handle, .. } = &event else {
                out.push(event);
                continue;
            };
            let (pid, handle) = (*pid, *handle);

            // A task that exited between the inner backend seeing it and this
            // lookup has no cgroup to freeze and nothing left to hold.
            let Some(cgroup) = cgroup_of(pid)? else {
                out.push(event);
                continue;
            };
            self.freeze(&cgroup)?;
            self.cgroups.insert(pid, cgroup);
            self.live.insert(pid, handle);

            if self.reported.contains(&pid) {
                // A freeze-induced restart of a checkpoint the engine has
                // already been told about. `live` now points at the new id;
                // the engine keeps the one it has and never learns the
                // difference.
                continue;
            }
            self.reported.push(pid);
            self.owner.insert(handle, pid);
            out.push(event);
        }

        if out.is_empty() {
            return Ok(Poll::Idle);
        }
        Ok(Poll::Events(out))
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        let Some(pid) = self.owner.remove(&handle) else {
            // Never frozen by us -- a synthetic exit, or a task that was gone
            // before its cgroup could be read.
            return self.inner.release(handle);
        };
        self.reported.retain(|p| *p != pid);

        // Thaw before answering. While the cgroup is frozen the task cannot
        // re-raise the notification a previous freeze tore down, so a release
        // issued here would have nothing valid to answer.
        if let Some(cgroup) = self.cgroups.remove(&pid) {
            self.thaw(&cgroup)?;
        }

        let deadline = Instant::now() + RESOLVE_TIMEOUT;
        loop {
            let live = self.live.get(&pid).copied().unwrap_or(handle);
            match self.inner.release(live) {
                Ok(()) => {
                    self.live.remove(&pid);
                    return Ok(());
                }
                Err(e) => {
                    // The id went stale under a freeze. The task is still held
                    // -- it restarted its syscall and is parked on a new
                    // notification that has not reached us yet. Poll for it.
                    if Instant::now() >= deadline {
                        return Err(e).with_context(|| {
                            format!(
                                "releasing pid {pid}: no answerable notification within \
                                 {RESOLVE_TIMEOUT:?} of thawing"
                            )
                        });
                    }
                    let Poll::Events(events) = self.inner.poll()? else {
                        std::thread::sleep(FREEZE_POLL);
                        continue;
                    };
                    for ev in events {
                        match &ev {
                            BackendEvent::CheckpointHit {
                                pid: p, handle: h, ..
                            } if *p == pid => {
                                self.live.insert(pid, *h);
                            }
                            // Anything about another task still matters to the
                            // engine, so it is queued rather than dropped.
                            _ => self.deferred.push(ev),
                        }
                    }
                }
            }
        }
    }
}

/// Thaw anything still frozen when the backend goes away.
///
/// Not tidiness. A frozen task keeps every file descriptor it inherited open,
/// including the stdout it shares with whoever launched the run, so a frozen
/// process left behind hangs any shell or test harness waiting on that pipe --
/// observed as exactly that, a run that completed its assertions and then never
/// returned. `SeccompNotifyBackend` has no `Drop` of its own because a held
/// thread dies with its notification fd; a frozen thread group does not.
impl<B: CheckpointBackend> Drop for FreezerBackend<B> {
    fn drop(&mut self) {
        for cgroup in std::mem::take(&mut self.frozen) {
            // Best-effort: a cgroup removed underneath us is already not
            // freezing anything, and there is no caller left to report to.
            let _ = std::fs::write(cgroup.join("cgroup.freeze"), "0");
        }
    }
}

/// Read the cgroup v2 path a task belongs to, as an absolute filesystem path.
///
/// Returns `Ok(None)` if the task is gone -- a race this backend tolerates
/// rather than fails on, since a role's task can exit at any point.
fn cgroup_of(pid: Pid) -> Result<Option<PathBuf>> {
    let raw = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading /proc/{pid}/cgroup")),
    };
    Ok(parse_cgroup_path(&raw)
        .map(|rel| PathBuf::from(CGROUP_MOUNT).join(rel.trim_start_matches('/'))))
}

/// Pull the unified-hierarchy path out of `/proc/<pid>/cgroup`.
///
/// cgroup v2 writes a single `0::<path>` line, where the path is relative to
/// the cgroup root and NOT prefixed with `/sys/fs/cgroup`. A v1-only line
/// (`<id>:<controller>:<path>`) is not a v2 path and is ignored, so a host
/// without the unified hierarchy yields `None` rather than a bogus path.
pub fn parse_cgroup_path(proc_cgroup: &str) -> Option<String> {
    proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
}

/// Block until `cgroup.events` reports the wanted frozen state.
fn wait_until_frozen(cgroup: &PathBuf, want: bool) -> Result<()> {
    let events = cgroup.join("cgroup.events");
    let deadline = Instant::now() + FREEZE_TIMEOUT;
    loop {
        let raw = std::fs::read_to_string(&events)
            .with_context(|| format!("reading {}", events.display()))?;
        if is_frozen(&raw) == Some(want) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "{} did not reach frozen={} within {:?} -- a task in the cgroup is likely \
                 in uninterruptible sleep, which the cgroup freezer cannot preempt",
                cgroup.display(),
                want,
                FREEZE_TIMEOUT
            );
        }
        std::thread::sleep(FREEZE_POLL);
    }
}

/// Read the `frozen` flag out of a `cgroup.events` file.
///
/// The file is a set of `<key> <value>` lines, e.g. `populated 1\nfrozen 0`.
/// Returns `None` if there is no `frozen` key at all, which is how a kernel
/// without freezer support presents itself.
pub fn is_frozen(cgroup_events: &str) -> Option<bool> {
    cgroup_events.lines().find_map(|l| {
        let (key, value) = l.split_once(' ')?;
        (key == "frozen").then(|| value.trim() == "1")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_unified_hierarchy_path() {
        assert_eq!(
            parse_cgroup_path("0::/crfuzz/run0\n").as_deref(),
            Some("/crfuzz/run0")
        );
    }

    #[test]
    fn ignores_v1_only_lines() {
        let v1 = "12:pids:/user.slice\n11:memory:/user.slice\n";
        assert_eq!(parse_cgroup_path(v1), None);
    }

    #[test]
    fn picks_the_v2_line_out_of_a_hybrid_hierarchy() {
        let hybrid = "12:pids:/user.slice\n0::/crfuzz/run0\n";
        assert_eq!(parse_cgroup_path(hybrid).as_deref(), Some("/crfuzz/run0"));
    }

    #[test]
    fn treats_an_empty_v2_path_as_absent() {
        assert_eq!(parse_cgroup_path("0::\n"), None);
    }

    #[test]
    fn reads_the_frozen_flag() {
        assert_eq!(is_frozen("populated 1\nfrozen 1\n"), Some(true));
        assert_eq!(is_frozen("populated 1\nfrozen 0\n"), Some(false));
    }

    #[test]
    fn a_kernel_without_freezer_support_has_no_frozen_key() {
        assert_eq!(is_frozen("populated 1\n"), None);
    }
}
