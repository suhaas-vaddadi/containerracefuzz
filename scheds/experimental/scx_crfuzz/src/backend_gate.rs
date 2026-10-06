// SPDX-License-Identifier: GPL-2.0
//
// The `sched_ext` side of a run: the gate that keeps a thread or a thread
// group off the CPU, and the thread-state sensor that reports what every
// thread in the run's cgroup is doing.
//
// Wraps the seccomp backend, which still parks each checkpoint hit. This layer
// does not decorate hits: holding beyond the parked thread is the engine's
// call, through `freeze`/`thaw` (one thread, wherever it is) and
// `gate_group`/`ungate_group` (a whole thread group, for `auto_attack`'s
// attacker window). A gated thread is runnable but never dispatched, so it is
// not disturbed: a thread parked in its seccomp notification stays parked, and
// the notification id the engine holds stays valid.

use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::NotifyHandle;
use crate::backend::Poll;
use crate::backend::ThreadStateKind;
use crate::backend_seccomp::SeccompNotifyBackend;
use crate::checkpoint::CheckpointDecl;
use crate::event::ConflictKey;
use crate::role::Pid;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use scx_crfuzz_gate::GateMap;
use scx_crfuzz_gate::RecordKind;
use scx_crfuzz_gate::RunSensor;
use scx_crfuzz_gate::ThreadRecord;
use std::time::Duration;
use std::time::Instant;

pub struct GateBackend {
    inner: SeccompNotifyBackend,
    map: GateMap,
    /// Registered by `attach`, before anything is spawned into the cgroup.
    sensor: Option<RunSensor>,
    /// `SCX_EV_BYPASS_ACTIVATE` when the run started.
    bypass_at_start: u64,
}

impl GateBackend {
    pub fn new(inner: SeccompNotifyBackend) -> Result<Self> {
        Ok(GateBackend {
            inner,
            map: GateMap::open()?,
            sensor: None,
            bypass_at_start: GateMap::bypass_activations()?,
        })
    }

    pub fn inner(&self) -> &SeccompNotifyBackend {
        &self.inner
    }

    /// Fail the run if the kernel ejected the scheduler underneath us, or
    /// put it in bypass mode.
    ///
    /// Checked every round. Either one releases every gate at once, and the
    /// engine would go on believing it holds tasks that are in fact running
    /// free -- producing a clean-looking verdict from a run that enforced
    /// nothing. That is worse than a crash, so it is treated as one.
    fn check_still_attached(&self) -> Result<()> {
        if !GateMap::scheduler_enabled() {
            bail!(
                "the sched_ext scheduler was ejected mid-run: every gate is gone and \
                 nothing was being held. Check `dmesg` for the ops.timeout_ms watchdog \
                 -- a hold longer than 30s ejects the scheduler."
            );
        }
        let bypass = GateMap::bypass_activations()?;
        if bypass > self.bypass_at_start {
            bail!(
                "the sched_ext scheduler entered bypass mode mid-run \
                 (SCX_EV_BYPASS_ACTIVATE {} -> {bypass}): the kernel scheduled every \
                 task itself, so no gate was holding.",
                self.bypass_at_start
            );
        }
        Ok(())
    }
}

fn thread_state(r: ThreadRecord) -> BackendEvent {
    BackendEvent::ThreadState {
        tid: r.tid,
        tgid: r.tgid,
        kind: match r.kind {
            RecordKind::Created => ThreadStateKind::Created,
            RecordKind::WakeStart => ThreadStateKind::WakeStart,
            RecordKind::WakeDone => ThreadStateKind::WakeDone,
            RecordKind::Asleep => ThreadStateKind::Asleep,
            RecordKind::Exited => ThreadStateKind::Exited,
            RecordKind::Joined => ThreadStateKind::Joined,
            RecordKind::Left => ThreadStateKind::Left,
        },
        arg: r.arg,
    }
}

/// A `Joined` for every thread of `tgid` but its leader, from
/// `/proc/<tgid>/task`, in tid order.
fn group_threads(tgid: Pid) -> Vec<BackendEvent> {
    let Ok(dir) = std::fs::read_dir(format!("/proc/{tgid}/task")) else {
        return Vec::new();
    };
    let mut tids: Vec<Pid> = dir
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<Pid>().ok())
        .filter(|tid| *tid != tgid)
        .collect();
    // Sorted, so the clone paths they are numbered with do not follow
    // directory order.
    tids.sort_unstable();
    tids.into_iter()
        .map(|tid| BackendEvent::ThreadState {
            tid,
            tgid,
            kind: ThreadStateKind::Joined,
            arg: 0,
        })
        .collect()
}

impl CheckpointBackend for GateBackend {
    fn spawned(&self) -> Vec<Pid> {
        self.inner.spawned()
    }

    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()> {
        self.check_still_attached()?;
        // The sensor sees only what happens after it registers, so it
        // registers before the seccomp backend spawns anything into the
        // cgroup.
        let dir = self.inner.cgroup_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating cgroup {}", dir.display()))?;
        let sensor = RunSensor::register(&dir, self.map.epoch())?;
        self.inner.wake_on(sensor.fd());
        self.sensor = Some(sensor);
        self.inner.attach(checkpoints)
    }

    /// Order is load-bearing, and the engine's thread table depends on it
    /// (design doc section 2, "Draining"). It drains in rounds -- the
    /// notification fds, then the sensor -- until a sensor drain comes back
    /// empty, and delivers every record before every hit:
    /// - every record a thread made before its notification was queued (the
    ///   wakeup that let it reach the syscall) was reserved before that
    ///   round's notification read, so it is in this batch or an earlier one;
    /// - the kernel queues a notification before its thread's `Asleep`, so
    ///   the round after the one that drained an `Asleep` reads its hit.
    ///
    /// `Idle` means `timeout` passed with nothing to report, or a signal: a
    /// wake for a reaped child or a hung-up listener waits on.
    fn poll(&mut self, timeout: Option<Duration>) -> Result<Poll> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let (polled, records) = loop {
            self.check_still_attached()?;
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            // Wakes for a record as well as a notification or an exit.
            let woken = self.inner.wait(left)?;
            let mut hits = Vec::new();
            let mut closed = false;
            let mut records = Vec::new();
            loop {
                match self.inner.poll(Some(Duration::ZERO))? {
                    Poll::Events(e) => hits.extend(e),
                    Poll::Closed => closed = true,
                    Poll::Idle => {}
                }
                let before = records.len();
                if let Some(sensor) = &mut self.sensor {
                    sensor.drain(&mut records)?;
                }
                if records.len() == before {
                    break;
                }
            }
            let polled = match (hits.is_empty(), closed) {
                (false, _) => Poll::Events(hits),
                (true, true) => Poll::Closed,
                (true, false) => Poll::Idle,
            };
            if !records.is_empty() || polled != Poll::Idle || !woken || left == Some(Duration::ZERO)
            {
                break (polled, records);
            }
        };
        if records.is_empty() {
            return Ok(polled);
        }
        let mut events = Vec::new();
        for r in records {
            events.push(thread_state(r));
            // A group attach names only the leader; the rest of its group
            // moved with it.
            if r.kind == RecordKind::Joined && r.arg != 0 {
                events.extend(group_threads(r.tgid));
            }
        }
        if let Poll::Events(e) = polled {
            events.extend(e);
        }
        Ok(Poll::Events(events))
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        self.check_still_attached()?;
        self.inner.release(handle)
    }

    fn recapture(&mut self, handle: NotifyHandle) -> Result<Option<Vec<ConflictKey>>> {
        self.inner.recapture(handle)
    }

    fn freeze(&mut self, tid: Pid) -> Result<()> {
        self.map.gate_tid(tid)?;
        // A gate takes effect at a task's next enqueue, so a thread already
        // on-CPU needs a preempting kick to get there.
        self.map.kick()
    }

    fn thaw(&mut self, tid: Pid) -> Result<()> {
        self.map.ungate_tid(tid)?;
        self.map.kick()
    }

    fn gate_group(&mut self, tgid: Pid) -> Result<()> {
        self.map.gate(tgid)?;
        self.map.kick()
    }

    fn ungate_group(&mut self, tgid: Pid) -> Result<()> {
        self.map.ungate(tgid)?;
        self.map.kick()
    }

    fn cpu_ns(&self, tid: Pid) -> Option<u64> {
        self.inner.cpu_ns(tid)
    }

    fn wakes_on_its_own(&self, tid: Pid) -> bool {
        self.inner.wakes_on_its_own(tid)
    }

    /// The sensor's ringbuf is in the seccomp backend's epoll set.
    fn pending(&self) -> bool {
        self.inner.pending()
    }

    fn dropped(&self) -> Result<u64> {
        match &self.sensor {
            Some(sensor) => sensor.dropped(),
            None => Ok(0),
        }
    }
}

impl Drop for GateBackend {
    /// Clear this run's gates; the sensor's own `Drop` frees its slot.
    ///
    /// Without it a crashed run leaves its threads gated forever, and the
    /// next run's tasks inherit a machine that will not schedule them -- as a
    /// leaked hold that keeps inherited descriptors (the shared stdout among
    /// them) open, hanging whatever launched the run.
    fn drop(&mut self) {
        if let Err(e) = self.map.clear_epoch() {
            log::warn!("clearing this run's gates: {e:#}");
        }
        if let Err(e) = self.map.kick() {
            log::warn!("kicking cpus after clearing this run's gates: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;

    #[test]
    fn a_group_s_threads_are_listed_in_tid_order_without_the_leader() {
        let (tx, rx) = std::sync::mpsc::channel();
        let listed = Arc::new(Barrier::new(4));
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let (tx, listed) = (tx.clone(), listed.clone());
                std::thread::spawn(move || {
                    // SAFETY: a plain syscall.
                    tx.send(unsafe { libc::gettid() }).unwrap();
                    listed.wait();
                })
            })
            .collect();
        let spawned: Vec<Pid> = (0..3).map(|_| rx.recv().unwrap()).collect();
        let tgid = std::process::id() as Pid;
        let tids: Vec<Pid> = group_threads(tgid)
            .into_iter()
            .map(|e| match e {
                BackendEvent::ThreadState { tid, tgid: g, .. } if g == tgid => tid,
                other => panic!("{other:?}"),
            })
            .collect();
        listed.wait();
        for w in workers {
            w.join().unwrap();
        }
        assert!(tids.windows(2).all(|w| w[0] < w[1]), "{tids:?}");
        assert!(!tids.contains(&tgid));
        assert!(spawned.iter().all(|t| tids.contains(t)), "{spawned:?} in {tids:?}");
    }
}
