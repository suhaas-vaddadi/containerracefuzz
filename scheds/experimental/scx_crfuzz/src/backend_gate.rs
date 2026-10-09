// SPDX-License-Identifier: GPL-2.0
//
// The intended holding mechanism: a `sched_ext` scheduler declines to place a
// gated thread group on a CPU.
//
// A decorator over another backend: seccomp supplies the precision (stop at
// exactly this syscall), the gate supplies the coverage (nothing else in the
// thread group gets CPU).
//
// WHAT THIS FIXES, AND WHAT IT DOES NOT.
//
// Fixed: holding a thread group without perturbing the syscall it holds. A
// cgroup freeze would wake every task in the cgroup, including one parked in a
// seccomp notification; that wait is interruptible, so the kernel would
// restart the syscall and a fresh notification id would replace the one the
// engine was told about. The gate never touches the held thread -- it stays
// parked for the whole hold -- so the only state here is `owner`, mapping a
// handle back to a thread group.
//
// Not fixed: the boundary is sharper, not zero. Between the notification
// arriving and this code writing the gate entry, siblings still run -- one
// userspace round trip.
// `GateStats` measures it rather than asserting it away. Closing it needs the
// gate set in-kernel in the trapping task's own context; see the spec's
// "Residual window, and phase 2".
//
// Also not fixed: which thread inside a thread group arrives first. The gate
// does not touch it: it makes the other
// threads stop; it does not make them stop in a chosen order.

use crate::backend::CheckpointBackend;
use crate::backend::NotifyHandle;
use crate::backend::Poll;
use crate::checkpoint::CheckpointDecl;
use crate::role::Pid;
use anyhow::bail;
use anyhow::Result;
use scx_crfuzz_gate::GateMap;
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

/// What the gate cost and how fuzzy its boundary was.
///
/// The case against a mechanism should be evidence rather than theory, and
/// the case *for* one is held to the same standard.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GateStats {
    pub gates: usize,
    pub ungates: usize,
    /// Worst notification-to-kick-complete seen: the cost to *issue* a hold,
    /// which excludes the scheduling round in which it takes effect.
    pub max_gate_latency: Duration,
}

pub struct GateBackend<B: CheckpointBackend> {
    inner: B,
    map: GateMap,
    /// Handle as the engine knows it -> the thread group it belongs to.
    ///
    /// There is no second map: the handle the engine was given stays valid
    /// for the whole hold, because nothing disturbs it.
    owner: HashMap<NotifyHandle, Pid>,
    stats: GateStats,
}

/// The thread group a task belongs to, from `/proc/<pid>/status`.
///
/// `CheckpointHit` carries only a pid, and gating is per-thread-group, so this
/// is the one lookup the gate needs. A pid that has already gone (or never
/// existed, as in the stub tests) is treated as its own leader, matching the
/// engine's own default in `role.rs`.
pub fn tgid_of(pid: Pid) -> Pid {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return pid;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(pid)
}

impl<B: CheckpointBackend> GateBackend<B> {
    pub fn new(inner: B) -> Result<Self> {
        Ok(GateBackend {
            inner,
            map: GateMap::open()?,
            owner: HashMap::new(),
            stats: GateStats::default(),
        })
    }

    pub fn stats(&self) -> &GateStats {
        &self.stats
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Fail the run if the kernel ejected the scheduler underneath us.
    ///
    /// Checked every round. An ejection releases every gate at once, and the
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
        Ok(())
    }
}

impl<B: CheckpointBackend> CheckpointBackend for GateBackend<B> {
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()> {
        self.check_still_attached()?;
        self.inner.attach(checkpoints)
    }

    fn poll(&mut self) -> Result<Poll> {
        self.check_still_attached()?;
        // The group hold is applied in `hold`, once the engine has resolved the
        // hit to the victim: the backend does not know victim-ness (that is the
        // engine's job), so gating here would gate a bystander's siblings too.
        self.inner.poll()
    }

    fn hold(&mut self, pid: Pid, handle: NotifyHandle) -> Result<()> {
        self.check_still_attached()?;
        let started = Instant::now();
        let tgid = tgid_of(pid);
        self.map.gate(tgid)?;
        // Gating only takes effect at a task's next enqueue, so a sibling
        // already on-CPU needs a preempting kick to get there.
        self.map.kick()?;
        let latency = started.elapsed();

        self.owner.insert(handle, tgid);
        self.stats.gates += 1;
        self.stats.max_gate_latency = self.stats.max_gate_latency.max(latency);
        Ok(())
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        self.check_still_attached()?;

        // Order is load-bearing: ungate before answering the notification, or
        // the notifying thread returns from the kernel into a still-gated
        // thread group and is parked again immediately.
        if let Some(tgid) = self.owner.remove(&handle) {
            self.map.ungate(tgid)?;
            self.map.kick()?;
            self.stats.ungates += 1;
        }
        self.inner.release(handle)
    }
}

impl<B: CheckpointBackend> Drop for GateBackend<B> {
    /// Clear this run's gates.
    ///
    /// Without it a crashed run leaves its thread groups gated forever, and
    /// the next run's tasks inherit a machine that will not schedule them --
    /// as a leaked hold that keeps inherited descriptors (the shared stdout
    /// among them) open, hanging whatever launched the run.
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
    use crate::backend::BackendEvent;
    use crate::backend::StubBackend;
    use crate::role::TaskInfo;

    fn task(pid: Pid) -> TaskInfo {
        TaskInfo { pid, tgid: pid, parent_tgid: 1, comm: "v".into(), cgroup: "/c".into() }
    }

    // Each test below gates a distinct high synthetic tgid (the
    // 424242-and-up convention `scx_crfuzz_gate/src/client.rs` already uses)
    // rather than a small pid like 10. This is not a stylistic choice:
    //
    //   - A low pid is very likely a live kernel thread on any real machine
    //     (pid 10 is commonly `kworker/0:0H-events_highpri`). Gating one is
    //     safe today only by accident -- kernel threads run `SCHED_OTHER`
    //     and the gate's `SWITCH_PARTIAL` ignores anything not in
    //     `SCHED_EXT` -- and it would take the real `/proc/<pid>/status`
    //     read path, not the "pid does not exist" fallback these tests exist
    //     to cover. A synthetic tgid makes `/proc/<tgid>/status` genuinely
    //     absent, so `tgid_of` takes that fallback for real.
    //   - Giving each test its own tgid also means the tests -- which
    //     cargo runs concurrently in one binary against `GateMap`'s
    //     machine-global state -- cannot step on each other's gate-map entry.
    fn skip() -> bool {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("skipping: needs root");
            return true;
        }
        if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
            eprintln!("skipping: scx_crfuzz_gated is not running");
            return true;
        }
        false
    }

    #[test]
    fn the_handle_the_engine_is_given_is_the_handle_it_releases() {
        // GateBackend::release passes the engine's handle straight through to
        // the inner backend, with no substitution. This test drives a
        // StubBackend, so the mechanism it measures is the gate's own.
        if skip() {
            return;
        }
        let inner = StubBackend::new().task(task(424244)).hit(424244, "openat");
        let mut b = GateBackend::new(inner).unwrap();

        b.poll().unwrap();
        let Poll::Events(e) = b.poll().unwrap() else { panic!("expected the hit") };
        let BackendEvent::CheckpointHit { handle, .. } = e[0].clone() else { panic!() };

        b.release(handle).unwrap();
        assert_eq!(
            b.inner().released,
            vec![handle],
            "released exactly the handle the engine was given, unchanged"
        );
    }

    #[test]
    fn a_hit_does_not_gate_until_the_victim_is_held() {
        if skip() {
            return;
        }
        let inner = StubBackend::new().task(task(424245)).hit(424245, "openat");
        let mut b = GateBackend::new(inner).unwrap();
        b.poll().unwrap();
        let Poll::Events(e) = b.poll().unwrap() else { panic!() };
        let BackendEvent::CheckpointHit { handle, .. } = e[0].clone() else { panic!() };

        assert_eq!(
            b.stats().gates,
            0,
            "delivering a hit does not gate: the engine has not resolved the victim yet"
        );
        b.hold(424245, handle).unwrap();
        assert_eq!(
            b.stats().gates,
            1,
            "holding the victim gates its whole thread group"
        );
        b.release(handle).unwrap();
        assert_eq!(b.stats().ungates, 1, "the release ungated it");
    }
}
