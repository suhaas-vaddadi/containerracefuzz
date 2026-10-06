// SPDX-License-Identifier: GPL-2.0
//
// The checkpoint backend: the seam between the engine and the mechanisms that
// actually hold a task.
//
// The real mechanisms -- seccomp user notification, the `sched_ext` gate and
// its thread-state sensor -- are Linux-only and privileged, so they live
// behind this trait (`backend_seccomp`, `backend_gate`), and the engine's
// thread table, role resolution, policies and log are exercised on any host
// against `StubBackend`.

use crate::checkpoint::CheckpointDecl;
use crate::checkpoint::CheckpointId;
use crate::event::ConflictKey;
use crate::role::Pid;
use crate::role::TaskInfo;
use anyhow::Result;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

/// An opaque reference to one held task, handed back to `release`.
///
/// On Linux this wraps a seccomp notification id; the engine treats it as
/// opaque and never interprets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NotifyHandle(pub u64);

/// What the thread-state sensor saw a thread do. Mirrors the gate's
/// `RecordKind`; the Linux backend converts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreadStateKind {
    /// Created; `arg` is the creator's tid.
    Created,
    /// A wakeup started; the thread is not at rest until `WakeDone`.
    WakeStart,
    WakeDone,
    /// Went to sleep; `arg` is its `prev_state`.
    Asleep,
    Exited,
    /// Moved into / out of the run's cgroup; `arg` is the threadgroup flag.
    Joined,
    Left,
}

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
        /// The path the held syscall resolved, when the backend could capture
        /// it (`checkpoint::path_arg_index` names the register, and the backend
        /// reads it from the target's memory). `None` for syscalls with no
        /// path argument, backends that do not capture arguments, or a capture
        /// that failed. The attacker/oracle orchestration acts on this path.
        path: Option<PathBuf>,
        /// The conflict tokens the held syscall touches (plan Phase 1), one per
        /// path argument (`checkpoint::path_arg_indices`), each tagged
        /// resolve/rebind. Empty for non-path syscalls and backends that do
        /// not capture keys; POS treats an empty key set as
        /// non-conflicting.
        keys: Vec<ConflictKey>,
    },
    /// A thread-state sensor record. Within one poll batch, every
    /// `ThreadState` comes before every other event, and every record a
    /// thread made before its batch's `CheckpointHit` is in that batch or an
    /// earlier one: the backend reads the notifications first, then drains
    /// the sensor.
    ThreadState {
        tid: Pid,
        tgid: Pid,
        kind: ThreadStateKind,
        arg: u32,
    },
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
    /// Attach the declared checkpoints. Called once, before anything runs.
    ///
    /// NOTE (design doc section 14-J, unresolved): for `one` roles this happens
    /// before the first decision, so nothing races it. Pool members, though,
    /// can be recognised at any point (section 5), and the doc does not say
    /// whether there is a window between a late member's first path-touching
    /// syscall and attachment to it -- which would be a hole in the synchronous
    /// holding guarantee for exactly those members. A real backend has to
    /// answer this; the trait shape does not settle it either way.
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()>;

    /// The pids `attach` spawned. Each is created outside the run's cgroup,
    /// so no `Created` record names it.
    fn spawned(&self) -> Vec<Pid>;

    /// Wait up to `timeout` (forever when `None`) for something to report.
    fn poll(&mut self, timeout: Option<Duration>) -> Result<Poll>;

    /// Let a held task proceed past its checkpoint.
    fn release(&mut self, handle: NotifyHandle) -> Result<()>;

    /// The conflict keys of a still-held hit, captured afresh from the
    /// arguments it parked with. `None` when the notification is gone
    /// (answered, interrupted, or its thread dead).
    fn recapture(&mut self, handle: NotifyHandle) -> Result<Option<Vec<ConflictKey>>>;

    /// Hold one thread wherever it is: runnable, but never run until `thaw`.
    fn freeze(&mut self, tid: Pid) -> Result<()>;
    fn thaw(&mut self, tid: Pid) -> Result<()>;

    /// Hold a whole thread group the same way, until `ungate_group`.
    fn gate_group(&mut self, tgid: Pid) -> Result<()>;
    fn ungate_group(&mut self, tgid: Pid) -> Result<()>;

    /// CPU time `tid` has run, in ns. `None` once it is gone.
    fn cpu_ns(&self, tid: Pid) -> Option<u64>;

    /// Whether a Blocked `tid` will wake on its own at a wall-clock time: a
    /// sleep with a timeout, an uninterruptible (I/O) wait, or already awake
    /// again with its records still on their way.
    fn wakes_on_its_own(&self, tid: Pid) -> bool;

    /// Thread-state records lost so far. Nonzero means the readout is
    /// unknowable.
    fn dropped(&self) -> Result<u64>;

    /// Whether something is ready that `poll` has not read yet, without
    /// waiting.
    fn pending(&self) -> bool {
        false
    }

    /// Whether `tid` is still inside the run's scope.
    ///
    /// The thread-state sensor is cgroup-scoped, so a task that has left the
    /// run's cgroup can no longer be reported at rest; the seccomp filter is
    /// only namespace-scoped, so it still delivers that task's checkpoints.
    /// The engine must not track such a task -- it would sit `Running` forever
    /// and stall the readout. `true` where the concept does not apply.
    fn in_scope(&self, _tid: Pid) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// StubBackend
// ---------------------------------------------------------------------------

/// A scripted backend for testing the engine off-target.
///
/// Each task has its own event queue. A task that hits a checkpoint is *held*
/// and produces no further events until released, which is what lets a script
/// put several roles at their own checkpoints simultaneously -- the situation
/// section 3.2 introduces and that the base design never had to handle. The
/// exception is records scripted with `parked`, which a held thread still
/// produces: every hit queues its thread's `Asleep` that way, and a script
/// can add a signal's wakeup. A task named by a scripted `Created` emits
/// nothing before that record.
///
/// The script fixes arrival order; `shuffle` varies the cross-thread order a
/// script arrives in. A green determinism test here says nothing about the
/// real sensor (see the crate docs, "Section 14-A").
#[derive(Debug, Default)]
pub struct StubBackend {
    /// Task pids in the order they were first scripted; drives emission order.
    order: Vec<Pid>,
    /// Per pid: each event, and whether it is emitted while the pid is held.
    queues: HashMap<Pid, VecDeque<(BackendEvent, bool)>>,
    /// Handle -> pid, for tasks currently held at a checkpoint.
    held: HashMap<NotifyHandle, Pid>,
    next_handle: u64,
    /// What `recapture` returns for a held handle.
    recaptures: HashMap<NotifyHandle, Option<Vec<ConflictKey>>>,
    /// Per tid: CPU readings, one per `cpu_ns` call; the last one repeats.
    cpu: RefCell<HashMap<Pid, VecDeque<u64>>>,
    /// When set, each poll emits one event, from a task this picks.
    rng: Option<ChaCha8Rng>,
    /// What `spawned` returns.
    spawns: Vec<Pid>,
    /// See `asleep_first`.
    asleep_first: bool,
    /// What `wakes_on_its_own` answers yes for.
    timed: Vec<Pid>,
    /// What `in_scope` answers no for.
    out_of_scope: Vec<Pid>,
    /// See `spinner`.
    spinners: Vec<Pid>,
    /// See `late`.
    late: HashMap<Pid, usize>,
    /// The `late` events have arrived.
    arrived: Cell<bool>,
    pub attached: Vec<CheckpointDecl>,
    pub released: Vec<NotifyHandle>,
    /// Every freeze/thaw/gate_group/ungate_group call, and every release
    /// (as `("release", pid)`), in order.
    pub gate_calls: Vec<(&'static str, Pid)>,
    pub dropped: u64,
}

impl StubBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn queue(&mut self, pid: Pid) -> &mut VecDeque<(BackendEvent, bool)> {
        if !self.queues.contains_key(&pid) {
            self.order.push(pid);
        }
        self.queues.entry(pid).or_default()
    }

    /// Script a task appearing.
    pub fn task(mut self, task: TaskInfo) -> Self {
        let pid = task.pid;
        self.queue(pid)
            .push_back((BackendEvent::TaskAppeared(task), false));
        self
    }

    /// Script `pid` as spawned by `attach`.
    pub fn spawn(mut self, pid: Pid) -> Self {
        self.spawns.push(pid);
        self
    }

    /// Script `pid` reaching `checkpoint` and being held there.
    pub fn hit(self, pid: Pid, checkpoint: &str) -> Self {
        self.hit_path(pid, checkpoint, None)
    }

    /// Script `pid` reaching `checkpoint` with a captured `path`, as a real
    /// backend would report for a use-shaped syscall.
    pub fn hit_path(self, pid: Pid, checkpoint: &str, path: Option<&str>) -> Self {
        self.hit_keys(pid, checkpoint, path, Vec::new())
    }

    /// Script `pid` reaching `checkpoint` with both a captured `path` and the
    /// conflict `keys` the syscall touches (plan Phase 1). Lets a host-side
    /// policy test script conflicts without a kernel. Handles are numbered
    /// from 0 in scripting order.
    pub fn hit_keys(
        mut self,
        pid: Pid,
        checkpoint: &str,
        path: Option<&str>,
        keys: Vec<ConflictKey>,
    ) -> Self {
        let handle = NotifyHandle(self.next_handle);
        self.next_handle += 1;
        self.recaptures.insert(handle, Some(keys.clone()));
        let hit = BackendEvent::CheckpointHit {
            pid,
            checkpoint: CheckpointId::new(checkpoint),
            handle,
            path: path.map(PathBuf::from),
            keys,
        };
        if self.asleep_first {
            let asleep = self.state_event(pid, ThreadStateKind::Asleep, 1);
            self.queue(pid).push_back((asleep, false));
            self.queue(pid).push_back((hit, false));
            return self;
        }
        self.queue(pid).push_back((hit, false));
        // The parked thread goes to sleep in its notification.
        self.parked(pid, ThreadStateKind::Asleep, 1)
    }

    /// From here on, script each hit's `Asleep` ahead of the hit, in the
    /// same batch: the drain round that read the `Asleep` reads the hit
    /// only in the next round, and a batch carries thread states first.
    pub fn asleep_first(mut self) -> Self {
        self.asleep_first = true;
        self
    }

    /// Script `tid` as in a timed sleep whenever it is Blocked.
    pub fn timed_sleeper(mut self, tid: Pid) -> Self {
        self.timed.push(tid);
        self
    }

    /// Script `tid` as having left the run's cgroup, so `in_scope` answers no.
    pub fn out_of_scope(mut self, tid: Pid) -> Self {
        self.out_of_scope.push(tid);
        self
    }

    /// Script `tid` as spinning on a flag it sees only once the watchdog has
    /// frozen and thawed it: it emits nothing before its first `thaw`.
    pub fn spinner(mut self, tid: Pid) -> Self {
        self.spinners.push(tid);
        self
    }

    /// Withhold the last `n` events scripted so far for `tid` until `pending`
    /// reports them or a release goes ahead without asking: they happen after
    /// the engine's last drain.
    pub fn late(mut self, tid: Pid, n: usize) -> Self {
        self.late.insert(tid, n);
        self
    }

    /// Script what `recapture(handle)` returns while `handle` is held
    /// (by default, the keys it was hit with).
    pub fn recaptured(mut self, handle: NotifyHandle, keys: Option<Vec<ConflictKey>>) -> Self {
        self.recaptures.insert(handle, keys);
        self
    }

    /// The tgid the script gave `tid` (announced, or created into), else its
    /// own.
    fn tgid_of(&self, tid: Pid) -> Pid {
        self.queues
            .values()
            .flatten()
            .find_map(|(e, _)| match e {
                BackendEvent::TaskAppeared(t) if t.pid == tid => Some(t.tgid),
                BackendEvent::ThreadState {
                    tid: t,
                    tgid,
                    kind: ThreadStateKind::Created,
                    ..
                } if *t == tid => Some(*tgid),
                _ => None,
            })
            .unwrap_or(tid)
    }

    fn state_event(&self, tid: Pid, kind: ThreadStateKind, arg: u32) -> BackendEvent {
        BackendEvent::ThreadState {
            tid,
            tgid: self.tgid_of(tid),
            kind,
            arg,
        }
    }

    /// Script `creator` creating `child` into thread group `tgid` (its own
    /// tgid for a thread, `child` for a fork). The record is the creator's,
    /// so it keeps the creator's order, and the child emits nothing before it.
    pub fn created(mut self, creator: Pid, child: Pid, tgid: Pid) -> Self {
        let e = BackendEvent::ThreadState {
            tid: child,
            tgid,
            kind: ThreadStateKind::Created,
            arg: creator as u32,
        };
        self.queue(creator).push_back((e, false));
        self.queue(child);
        self
    }

    /// Script a thread-state record of `tid`.
    pub fn state(mut self, tid: Pid, kind: ThreadStateKind, arg: u32) -> Self {
        let e = self.state_event(tid, kind, arg);
        self.queue(tid).push_back((e, false));
        self
    }

    /// Script a record `tid` produces while held at its last hit. A
    /// `WakeDone` here is a signal interrupting the hold: the hit's handle is
    /// dead from then on, and the thread runs on unreleased.
    pub fn parked(mut self, tid: Pid, kind: ThreadStateKind, arg: u32) -> Self {
        let e = self.state_event(tid, kind, arg);
        self.queue(tid).push_back((e, true));
        self
    }

    /// Script `pid` exiting.
    pub fn exit(self, pid: Pid) -> Self {
        self.state(pid, ThreadStateKind::Exited, 0)
    }

    /// Script `tid`'s CPU readings, returned one per `cpu_ns` call; the last
    /// one repeats.
    pub fn cpu(self, tid: Pid, readings: &[u64]) -> Self {
        self.cpu
            .borrow_mut()
            .insert(tid, readings.iter().copied().collect());
        self
    }

    /// Emit one event per poll, from a task a `seed`ed RNG picks, so seeds
    /// enumerate cross-thread interleavings of one script. Each task's own
    /// events keep their order.
    pub fn shuffle(mut self, seed: u64) -> Self {
        self.rng = Some(ChaCha8Rng::seed_from_u64(seed));
        self
    }

    fn can_emit(&self, pid: Pid) -> bool {
        let Some((_, parked)) = self.queues.get(&pid).and_then(|q| q.front()) else {
            return false;
        };
        let uncreated = self.queues.values().flatten().any(|(e, _)| {
            matches!(e, BackendEvent::ThreadState {
                tid,
                kind: ThreadStateKind::Created,
                ..
            } if *tid == pid)
        });
        let spinning = self.spinners.contains(&pid) && !self.gate_calls.contains(&("thaw", pid));
        let late = !self.arrived.get()
            && self.queues[&pid].len() <= self.late.get(&pid).copied().unwrap_or(0);
        !uncreated && !spinning && !late && (*parked || !self.held.values().any(|p| *p == pid))
    }

    fn emit(&mut self, pid: Pid) -> Vec<BackendEvent> {
        let (event, parked) = self.queues.get_mut(&pid).unwrap().pop_front().unwrap();
        let paired = self.asleep_first
            && matches!(event, BackendEvent::ThreadState {
                kind: ThreadStateKind::Asleep,
                ..
            })
            && matches!(
                self.queues[&pid].front(),
                Some((BackendEvent::CheckpointHit { .. }, _))
            );
        match &event {
            BackendEvent::CheckpointHit { handle, .. } => {
                self.held.insert(*handle, pid);
            }
            BackendEvent::ThreadState {
                kind: ThreadStateKind::WakeDone,
                ..
            } if parked => self.held.retain(|_, p| *p != pid),
            _ => {}
        }
        let mut out = vec![event];
        if paired {
            out.extend(self.emit(pid));
        }
        out
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

    fn spawned(&self) -> Vec<Pid> {
        self.spawns.clone()
    }

    /// Never blocks.
    fn poll(&mut self, _timeout: Option<Duration>) -> Result<Poll> {
        let ready: Vec<Pid> = self
            .order
            .iter()
            .copied()
            .filter(|p| self.can_emit(*p))
            .collect();
        let mut events = match &mut self.rng {
            Some(_) if ready.is_empty() => Vec::new(),
            Some(rng) => {
                let pid = ready[rng.gen_range(0..ready.len())];
                self.emit(pid)
            }
            None => ready.into_iter().flat_map(|p| self.emit(p)).collect(),
        };
        // The real backend's batch contract: thread states first.
        events.sort_by_key(|e| !matches!(e, BackendEvent::ThreadState { .. }));

        if !events.is_empty() {
            return Ok(Poll::Events(events));
        }
        if self.drained() && self.held.is_empty() {
            return Ok(Poll::Closed);
        }
        Ok(Poll::Idle)
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        self.arrived.set(true);
        if let Some(pid) = self.held.remove(&handle) {
            self.gate_calls.push(("release", pid));
        }
        self.released.push(handle);
        Ok(())
    }

    fn recapture(&mut self, handle: NotifyHandle) -> Result<Option<Vec<ConflictKey>>> {
        if !self.held.contains_key(&handle) {
            return Ok(None);
        }
        Ok(self.recaptures.get(&handle).cloned().flatten())
    }

    fn freeze(&mut self, tid: Pid) -> Result<()> {
        self.gate_calls.push(("freeze", tid));
        Ok(())
    }

    fn thaw(&mut self, tid: Pid) -> Result<()> {
        self.gate_calls.push(("thaw", tid));
        Ok(())
    }

    fn gate_group(&mut self, tgid: Pid) -> Result<()> {
        self.gate_calls.push(("gate_group", tgid));
        Ok(())
    }

    fn ungate_group(&mut self, tgid: Pid) -> Result<()> {
        self.gate_calls.push(("ungate_group", tgid));
        Ok(())
    }

    fn cpu_ns(&self, tid: Pid) -> Option<u64> {
        let mut cpu = self.cpu.borrow_mut();
        let readings = cpu.get_mut(&tid)?;
        if readings.len() > 1 {
            readings.pop_front()
        } else {
            readings.front().copied()
        }
    }

    fn wakes_on_its_own(&self, tid: Pid) -> bool {
        self.timed.contains(&tid)
    }

    fn in_scope(&self, tid: Pid) -> bool {
        !self.out_of_scope.contains(&tid)
    }

    fn dropped(&self) -> Result<u64> {
        Ok(self.dropped)
    }

    fn pending(&self) -> bool {
        !self.late.is_empty() && !self.arrived.replace(true)
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

    fn events(b: &mut StubBackend) -> Vec<BackendEvent> {
        match b.poll(None).unwrap() {
            Poll::Events(e) => e,
            other => panic!("expected events, got {other:?}"),
        }
    }

    #[test]
    fn a_held_task_produces_no_further_events_until_released() {
        let mut b = StubBackend::new()
            .task(task(10, "victim"))
            .hit(10, "stat")
            .hit(10, "openat");

        events(&mut b); // appeared
        let BackendEvent::CheckpointHit { handle, .. } = events(&mut b)[0].clone() else {
            panic!()
        };
        events(&mut b); // its Asleep

        assert_eq!(b.poll(None).unwrap(), Poll::Idle, "still held");
        b.release(handle).unwrap();
        events(&mut b); // now proceeds
    }

    #[test]
    fn two_tasks_can_be_held_at_their_own_checkpoints_at_once() {
        // The situation section 3.2 introduces: a ready set with >1 member.
        let mut b = StubBackend::new()
            .task(task(10, "victim"))
            .task(task(20, "racer"))
            .hit(10, "stat")
            .hit(20, "symlink");

        events(&mut b); // both appear
        assert_eq!(events(&mut b).len(), 2, "both hits arrive together");
    }

    #[test]
    fn closes_only_once_every_queue_is_drained_and_nothing_is_held() {
        let mut b = StubBackend::new().task(task(10, "victim")).exit(10);
        events(&mut b);
        events(&mut b);
        assert_eq!(b.poll(None).unwrap(), Poll::Closed);
    }

    #[test]
    fn attach_records_what_it_was_given() {
        let mut b = StubBackend::new();
        let cps = crate::checkpoint::default_discovery_checkpoints();
        b.attach(&cps).unwrap();
        assert_eq!(b.attached.len(), cps.len());
        assert!(b.spawned().is_empty());
        assert_eq!(StubBackend::new().spawn(7).spawned(), [7]);
    }

    #[test]
    fn a_batch_carries_its_thread_states_before_its_hits() {
        let mut b = StubBackend::new()
            .hit(20, "stat")
            .state(10, ThreadStateKind::Asleep, 1);
        let e = events(&mut b);
        assert!(matches!(e[0], BackendEvent::ThreadState { tid: 10, .. }), "{e:?}");
        assert!(matches!(e[1], BackendEvent::CheckpointHit { .. }), "{e:?}");
    }

    #[test]
    fn a_created_thread_emits_nothing_before_its_creator_s_record() {
        let mut b = StubBackend::new()
            .hit(11, "stat")
            .state(10, ThreadStateKind::WakeStart, 0)
            .created(10, 11, 10);
        let first = events(&mut b);
        assert_eq!(first.len(), 1, "only the creator: {first:?}");
        let BackendEvent::ThreadState { tid: 10, .. } = first[0] else {
            panic!("{first:?}")
        };
        assert_eq!(
            events(&mut b),
            vec![BackendEvent::ThreadState {
                tid: 11,
                tgid: 10,
                kind: ThreadStateKind::Created,
                arg: 10
            }]
        );
        assert!(matches!(events(&mut b)[0], BackendEvent::CheckpointHit { pid: 11, .. }));
    }

    #[test]
    fn a_held_thread_still_reports_its_parked_records_and_a_signal_ends_the_hold() {
        let mut b = StubBackend::new()
            .task(TaskInfo {
                tgid: 10,
                ..task(11, "victim")
            })
            .hit(11, "stat")
            .parked(11, ThreadStateKind::WakeStart, 0)
            .parked(11, ThreadStateKind::WakeDone, 0)
            .hit(11, "openat");
        events(&mut b);
        events(&mut b); // the hit
        let asleep = events(&mut b);
        assert_eq!(
            asleep,
            vec![BackendEvent::ThreadState {
                tid: 11,
                tgid: 10,
                kind: ThreadStateKind::Asleep,
                arg: 1
            }],
            "queued by the hit, emitted while held, with the scripted tgid"
        );
        events(&mut b); // WakeStart
        events(&mut b); // WakeDone: the signal
        assert_eq!(b.recapture(NotifyHandle(0)).unwrap(), None, "its handle is dead");
        let BackendEvent::CheckpointHit { handle, .. } = events(&mut b)[0] else {
            panic!("expected the re-park")
        };
        assert_eq!(handle, NotifyHandle(1), "it re-parks without a release");
    }

    #[test]
    fn a_seed_permutes_cross_thread_order_and_keeps_each_thread_s_own() {
        let script = |seed| {
            let mut b = (0..4).fold(StubBackend::new(), |b, t| {
                b.state(t, ThreadStateKind::WakeStart, 0)
                    .state(t, ThreadStateKind::WakeDone, 0)
                    .exit(t)
            });
            b = b.shuffle(seed);
            let mut seen = Vec::new();
            while let Poll::Events(e) = b.poll(None).unwrap() {
                assert_eq!(e.len(), 1, "one record per poll");
                let BackendEvent::ThreadState { tid, kind, .. } = e[0] else {
                    panic!()
                };
                seen.push((tid, kind));
            }
            seen
        };
        assert_eq!(script(1), script(1), "a seed is reproducible");
        let orders: std::collections::HashSet<_> = (0..16).map(script).collect();
        assert!(orders.len() > 1, "seeds vary the interleaving");
        for order in orders {
            for t in 0..4 {
                let own: Vec<_> = order.iter().filter(|(p, _)| *p == t).map(|(_, k)| *k).collect();
                assert_eq!(
                    own,
                    [ThreadStateKind::WakeStart, ThreadStateKind::WakeDone, ThreadStateKind::Exited]
                );
            }
        }
    }

    #[test]
    fn recapture_returns_scripted_keys_while_held_and_none_once_released() {
        use crate::event::Direction;
        use crate::event::FileToken;
        let fresh = vec![ConflictKey::file(FileToken::new(1, 2, Vec::new()), Direction::Rebind)];
        let mut b = StubBackend::new()
            .hit(10, "stat")
            .hit(20, "openat")
            .recaptured(NotifyHandle(1), Some(fresh.clone()));
        assert_eq!(b.recapture(NotifyHandle(0)).unwrap(), None, "not parked yet");
        events(&mut b);
        assert_eq!(b.recapture(NotifyHandle(0)).unwrap(), Some(Vec::new()), "hit keys");
        assert_eq!(b.recapture(NotifyHandle(1)).unwrap(), Some(fresh));
        b.release(NotifyHandle(1)).unwrap();
        assert_eq!(b.recapture(NotifyHandle(1)).unwrap(), None);
    }

    #[test]
    fn gate_calls_are_recorded_and_cpu_readings_advance() {
        let mut b = StubBackend::new().cpu(10, &[5, 9]);
        b.freeze(10).unwrap();
        b.thaw(10).unwrap();
        b.gate_group(20).unwrap();
        b.ungate_group(20).unwrap();
        assert_eq!(
            b.gate_calls,
            [("freeze", 10), ("thaw", 10), ("gate_group", 20), ("ungate_group", 20)]
        );
        assert_eq!(b.cpu_ns(10), Some(5));
        assert_eq!(b.cpu_ns(10), Some(9));
        assert_eq!(b.cpu_ns(10), Some(9), "the last reading repeats");
        assert_eq!(b.cpu_ns(11), None);
        assert_eq!(b.dropped().unwrap(), 0);
    }
}
