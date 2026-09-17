// SPDX-License-Identifier: GPL-2.0
//
// The checkpoint backend: the seam between the engine and the mechanisms that
// actually hold a task.
//
// Everything the design doc requires to be real -- seccomp in user-notification
// mode, uprobe/kprobe/LSM attachment, `ops.dispatch` declining to place a task
// on a CPU (Background, "Checkpoint") -- is Linux-only, privileged, and
// untestable off-target. It therefore lives behind this trait, so the engine's
// phase machine, role resolution, policies and log can be exercised on any
// host against `StubBackend`.
//
// The real backend is not implemented here. See `lib.rs`, "Seams".

use crate::checkpoint::CheckpointDecl;
use crate::checkpoint::CheckpointId;
use crate::role::Pid;
use crate::role::TaskInfo;
use anyhow::Result;
use std::collections::HashMap;
use std::collections::VecDeque;

/// An opaque reference to one held task, handed back to `release`.
///
/// On Linux this wraps a seccomp notification id; the engine treats it as
/// opaque and never interprets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NotifyHandle(pub u64);

/// The reserved handle for a synthetic exit hit, which has no task to release.
pub const EXIT_HANDLE: NotifyHandle = NotifyHandle(u64::MAX);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEvent {
    /// A task entered the scenario's scope and is available for role
    /// resolution. Emitted for tasks whether or not they belong to a role --
    /// deciding that is the role table's job, not the backend's.
    TaskAppeared(TaskInfo),
    /// A task is blocked at a checkpoint and will stay blocked until released.
    CheckpointHit {
        pid: Pid,
        checkpoint: CheckpointId,
        handle: NotifyHandle,
    },
    TaskExited(Pid),
}

/// The result of polling the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    Events(Vec<BackendEvent>),
    /// Nothing new, but tasks are still held or still running: polling again
    /// may produce more.
    Idle,
    /// The scenario is over. No further events will ever arrive.
    Closed,
}

pub trait CheckpointBackend {
    /// Attach the declared checkpoints. Called once, before `Barrier`.
    ///
    /// NOTE (design doc section 14-J, unresolved): for `one` roles this happens
    /// before `Enforcing` begins, so nothing races it. Pool members, though,
    /// can be recognised at any point (section 5), and the doc does not say
    /// whether there is a window between a late member's first path-touching
    /// syscall and attachment to it -- which would be a hole in the synchronous
    /// holding guarantee for exactly those members. A real backend has to
    /// answer this; the trait shape does not settle it either way.
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()>;

    fn poll(&mut self) -> Result<Poll>;

    /// Let a held task proceed past its checkpoint.
    fn release(&mut self, handle: NotifyHandle) -> Result<()>;
}

// ---------------------------------------------------------------------------
// StubBackend
// ---------------------------------------------------------------------------

/// A scripted backend for testing the engine off-target.
///
/// Each task has its own event queue. A task that hits a checkpoint is *held*
/// and produces no further events until released, which is what lets a script
/// put several roles at their own checkpoints simultaneously -- the situation
/// section 3.2 introduces and that the base design never had to handle.
///
/// IMPORTANT (design doc section 14-A): because the script fixes the order in
/// which tasks reach their checkpoints, any determinism this backend
/// demonstrates is determinism of `decide()` as a pure function of
/// `(seed, ready-set-sequence)` -- and nothing more.
///
/// That distinction is not hypothetical. Measured against real processes with
/// `backend_seccomp::SeccompNotifyBackend`, the ready-set sequence is *not*
/// reproducible: about one run in a few hundred has two roles reach their first
/// checkpoint in the opposite order, which reverses their position in the ready
/// set and diverges the whole run. So a green determinism test here says
/// nothing whatsoever about whether the same seed reproduces against real
/// processes -- it demonstrably does not, every few hundred runs. See the
/// crate docs, "Section 14-A is no longer open".
#[derive(Debug, Default)]
pub struct StubBackend {
    /// Task pids in the order they were first scripted; drives emission order.
    order: Vec<Pid>,
    queues: HashMap<Pid, VecDeque<BackendEvent>>,
    /// Handle -> pid, for tasks currently held at a checkpoint.
    held: HashMap<NotifyHandle, Pid>,
    next_handle: u64,
    pub attached: Vec<CheckpointDecl>,
    pub released: Vec<NotifyHandle>,
}

impl StubBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn queue(&mut self, pid: Pid) -> &mut VecDeque<BackendEvent> {
        if !self.queues.contains_key(&pid) {
            self.order.push(pid);
        }
        self.queues.entry(pid).or_default()
    }

    /// Script a task appearing.
    pub fn task(mut self, task: TaskInfo) -> Self {
        let pid = task.pid;
        self.queue(pid).push_back(BackendEvent::TaskAppeared(task));
        self
    }

    /// Script `pid` reaching `checkpoint` and being held there.
    pub fn hit(mut self, pid: Pid, checkpoint: &str) -> Self {
        let handle = NotifyHandle(self.next_handle);
        self.next_handle += 1;
        self.queue(pid).push_back(BackendEvent::CheckpointHit {
            pid,
            checkpoint: CheckpointId::new(checkpoint),
            handle,
        });
        self
    }

    /// Script `pid` exiting.
    pub fn exit(mut self, pid: Pid) -> Self {
        self.queue(pid).push_back(BackendEvent::TaskExited(pid));
        self
    }

    fn is_held(&self, pid: Pid) -> bool {
        self.held.values().any(|p| *p == pid)
    }

    fn drained(&self) -> bool {
        self.queues.values().all(|q| q.is_empty())
    }
}

impl CheckpointBackend for StubBackend {
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()> {
        self.attached = checkpoints.to_vec();
        Ok(())
    }

    fn poll(&mut self) -> Result<Poll> {
        let mut events = Vec::new();
        for pid in self.order.clone() {
            if self.is_held(pid) {
                continue;
            }
            let Some(event) = self.queues.get_mut(&pid).and_then(|q| q.pop_front()) else {
                continue;
            };
            if let BackendEvent::CheckpointHit { handle, .. } = &event {
                self.held.insert(*handle, pid);
            }
            events.push(event);
        }

        if !events.is_empty() {
            return Ok(Poll::Events(events));
        }
        if self.drained() && self.held.is_empty() {
            return Ok(Poll::Closed);
        }
        Ok(Poll::Idle)
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        if handle != EXIT_HANDLE {
            self.held.remove(&handle);
        }
        self.released.push(handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(pid: Pid, comm: &str) -> TaskInfo {
        TaskInfo {
            pid,
            tgid: pid,
            parent_tgid: 1,
            comm: comm.to_string(),
            cgroup: "/c/run0".to_string(),
        }
    }

    #[test]
    fn a_held_task_produces_no_further_events_until_released() {
        let mut b = StubBackend::new()
            .task(task(10, "victim"))
            .hit(10, "stat")
            .hit(10, "openat");

        assert!(matches!(b.poll().unwrap(), Poll::Events(_))); // appeared
        let Poll::Events(e) = b.poll().unwrap() else {
            panic!()
        };
        let BackendEvent::CheckpointHit { handle, .. } = e[0].clone() else {
            panic!()
        };

        assert_eq!(b.poll().unwrap(), Poll::Idle, "still held");
        b.release(handle).unwrap();
        assert!(matches!(b.poll().unwrap(), Poll::Events(_)), "now proceeds");
    }

    #[test]
    fn two_tasks_can_be_held_at_their_own_checkpoints_at_once() {
        // The situation section 3.2 introduces: a ready set with >1 member.
        let mut b = StubBackend::new()
            .task(task(10, "victim"))
            .task(task(20, "racer"))
            .hit(10, "stat")
            .hit(20, "symlink");

        b.poll().unwrap(); // both appear
        let Poll::Events(e) = b.poll().unwrap() else {
            panic!()
        };
        assert_eq!(e.len(), 2, "both hits arrive together");
    }

    #[test]
    fn closes_only_once_every_queue_is_drained_and_nothing_is_held() {
        let mut b = StubBackend::new().task(task(10, "victim")).exit(10);
        b.poll().unwrap();
        b.poll().unwrap();
        assert_eq!(b.poll().unwrap(), Poll::Closed);
    }

    #[test]
    fn attach_records_what_it_was_given() {
        let mut b = StubBackend::new();
        let cps = crate::checkpoint::default_discovery_checkpoints();
        b.attach(&cps).unwrap();
        assert_eq!(b.attached.len(), cps.len());
    }

    #[test]
    fn releasing_the_exit_handle_is_a_no_op_that_cannot_unhold_a_task() {
        let mut b = StubBackend::new().task(task(10, "v")).hit(10, "stat");
        b.poll().unwrap();
        b.poll().unwrap();
        b.release(EXIT_HANDLE).unwrap();
        assert_eq!(b.poll().unwrap(), Poll::Idle, "the real hold survives");
    }
}
