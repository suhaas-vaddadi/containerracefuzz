// SPDX-License-Identifier: GPL-2.0
//
//! The thread-state sensor's client face: register a run's cgroup, read its
//! records back from the run's own ringbuf.
//!
//! Like `client`, this knows nothing about roles or the engine: only tids,
//! cgroups and the record kinds the BPF tracepoints emit.

use crate::bpf_intf;
use crate::client::test_run;
use crate::client::PIN_DIR;
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::MapType;
use std::cell::RefCell;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Created,
    WakeStart,
    WakeDone,
    Asleep,
    Exited,
    Joined,
    Left,
}

/// One record. `arg` is the creator tid for `Created`, `prev_state` for
/// `Asleep`, the `threadgroup` flag for `Joined`/`Left` (a group attach names
/// only the leader), and 0 otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadRecord {
    pub tid: i32,
    pub tgid: i32,
    pub kind: RecordKind,
    pub arg: u32,
}

pub struct RunSensor {
    slots: MapHandle,
    rings: MapHandle,
    ring: MapHandle,
    reader: libbpf_rs::RingBuffer<'static>,
    /// Raw `crfuzz_rec`s the reader's callback has copied out, not yet drained.
    pending: Rc<RefCell<Vec<[u32; 4]>>>,
    index: u32,
}

impl RunSensor {
    /// `cgroup_dir` is the /sys/fs/cgroup/... directory; its inode is the cgroup id.
    ///
    /// Must be called before anything is spawned into the cgroup: records from
    /// before registration are never seen.
    pub fn register(cgroup_dir: &std::path::Path, epoch: u64) -> Result<RunSensor> {
        let cgroup_id = std::fs::metadata(cgroup_dir)
            .with_context(|| format!("reading cgroup {}", cgroup_dir.display()))?
            .ino();
        let open = |name: &str| {
            MapHandle::from_pinned_path(format!("{PIN_DIR}/{name}")).with_context(|| {
                format!("opening {PIN_DIR}/{name} -- is scx_crfuzz_gated running?")
            })
        };
        let slots = open("sensor_slots")?;
        let rings = open("sensor_rings")?;
        let claim = libbpf_rs::Program::fd_from_pinned_path(format!("{PIN_DIR}/slot_claim"))
            .with_context(|| format!("opening {PIN_DIR}/slot_claim"))?;

        // Everything that can fail without a slot happens before the claim, so
        // a failed register never leaves one claimed.
        let opts = libbpf_rs::libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
            ..Default::default()
        };
        let ring = MapHandle::create(
            MapType::RingBuf,
            Some("crfuzz_run"),
            0,
            0,
            bpf_intf::CRFUZZ_RINGBUF_BYTES,
            &opts,
        )
        .context("creating the run's ringbuf")?;
        let pending = Rc::new(RefCell::new(Vec::new()));
        let sink = pending.clone();
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(&ring, move |data: &[u8]| {
            let word = |i: usize| u32::from_ne_bytes(data[4 * i..4 * i + 4].try_into().unwrap());
            sink.borrow_mut().push([word(0), word(1), word(2), word(3)]);
            0
        })?;
        let reader = builder.build().context("building the ringbuf reader")?;

        let ret = test_run(&claim, Some(&epoch.to_ne_bytes()))
            .context("claiming a sensor slot via crfuzz_slot_claim")? as i32;
        anyhow::ensure!(
            ret >= 0,
            "crfuzz_slot_claim failed: {} (all {} slots busy? `scx_crfuzz_gated --reset` \
             clears slots a crashed run left claimed)",
            std::io::Error::from_raw_os_error(-ret),
            bpf_intf::CRFUZZ_MAX_RUNS
        );
        // From here on Drop releases the slot, including on the errors below.
        let sensor = RunSensor {
            slots,
            rings,
            ring,
            reader,
            pending,
            index: ret as u32,
        };
        let key = sensor.index.to_ne_bytes();
        sensor
            .rings
            .update(
                &key,
                &sensor.ring.as_fd().as_raw_fd().to_ne_bytes(),
                MapFlags::ANY,
            )
            .context("installing the run's ringbuf")?;
        // Last: a nonzero cgroup_id is what makes BPF start reserving.
        let mut slot = [0u8; std::mem::size_of::<bpf_intf::crfuzz_slot>()];
        slot[..8].copy_from_slice(&cgroup_id.to_ne_bytes());
        slot[8..16].copy_from_slice(&epoch.to_ne_bytes());
        sensor
            .slots
            .update(&key, &slot, MapFlags::ANY)
            .context("activating the sensor slot")?;
        Ok(sensor)
    }

    /// The fd to put in an epoll set; readable when records are pending.
    pub fn fd(&self) -> RawFd {
        self.ring.as_fd().as_raw_fd()
    }

    /// Non-blocking: append every committed record, in ringbuf order.
    pub fn drain(&mut self, out: &mut Vec<ThreadRecord>) -> Result<()> {
        self.reader
            .consume()
            .context("consuming the run's ringbuf")?;
        for [tid, tgid, kind, arg] in self.pending.borrow_mut().drain(..) {
            let kind = match kind {
                bpf_intf::CRFUZZ_REC_CREATED => RecordKind::Created,
                bpf_intf::CRFUZZ_REC_WAKE_START => RecordKind::WakeStart,
                bpf_intf::CRFUZZ_REC_WAKE_DONE => RecordKind::WakeDone,
                bpf_intf::CRFUZZ_REC_ASLEEP => RecordKind::Asleep,
                bpf_intf::CRFUZZ_REC_EXITED => RecordKind::Exited,
                bpf_intf::CRFUZZ_REC_JOINED => RecordKind::Joined,
                bpf_intf::CRFUZZ_REC_LEFT => RecordKind::Left,
                k => anyhow::bail!("unknown sensor record kind {k}"),
            };
            out.push(ThreadRecord {
                tid: tid as i32,
                tgid: tgid as i32,
                kind,
                arg,
            });
        }
        Ok(())
    }

    /// Records lost to a full ringbuf. Nonzero means the readout is unknowable.
    pub fn dropped(&self) -> Result<u64> {
        let slot = self
            .slots
            .lookup(&self.index.to_ne_bytes(), MapFlags::ANY)
            .context("reading the sensor slot")?
            .context("sensor slot missing")?;
        Ok(u64::from_ne_bytes(slot[16..24].try_into().unwrap()))
    }
}

impl Drop for RunSensor {
    fn drop(&mut self) {
        if let Err(e) = release_slot(&self.slots, &self.rings, self.index) {
            eprintln!(
                "warning: sensor slot {} left claimed ({e:#}); `scx_crfuzz_gated --reset` frees it",
                self.index
            );
        }
    }
}

/// Free slot `index`, in the reverse of `register`'s order: stop BPF reserving
/// (zero `cgroup_id`), remove the ringbuf, then free the claim (zero `epoch`).
pub fn release_slot(slots: &MapHandle, rings: &MapHandle, index: u32) -> Result<()> {
    let key = index.to_ne_bytes();
    let mut slot = slots
        .lookup(&key, MapFlags::ANY)
        .context("reading the sensor slot")?
        .context("sensor slot missing")?;
    slot[..8].fill(0);
    slots
        .update(&key, &slot, MapFlags::ANY)
        .context("deactivating the sensor slot")?;
    match rings.delete(&key) {
        Ok(()) => {}
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("removing the run's ringbuf"),
    }
    slot.fill(0);
    slots
        .update(&key, &slot, MapFlags::ANY)
        .context("freeing the sensor slot")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GateMap;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;

    const CHILD_ENV: &str = "CRFUZZ_SENSOR_CHILD";

    fn skip() -> bool {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("skipping: needs root");
            return true;
        }
        if GateMap::open().is_err() {
            eprintln!("skipping: scx_crfuzz_gated is not running");
            return true;
        }
        false
    }

    /// A fresh cgroup, removed on drop (it must be empty by then).
    struct Cgroup(PathBuf);

    impl Cgroup {
        fn new(tag: &str) -> Cgroup {
            let dir = PathBuf::from(format!(
                "/sys/fs/cgroup/crfuzz-sensor-test-{}-{tag}",
                std::process::id()
            ));
            std::fs::create_dir(&dir).unwrap();
            Cgroup(dir)
        }
    }

    impl Drop for Cgroup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    /// The workload the sensor test re-executes this binary into: two threads
    /// that each sleep, joined by the main thread. A no-op in a normal run.
    #[test]
    fn child_workload() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let threads: Vec<_> = (0..2)
            .map(|_| {
                std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_millis(20)))
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }

    /// Run `child_workload` in `SCHED_EXT` inside `cg` and return its pid.
    fn run_child(cg: &Cgroup) -> i32 {
        let procs = cg.0.join("cgroup.procs");
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "sensor::tests::child_workload", "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdout(std::process::Stdio::null());
        // SAFETY: only async-signal-safe-in-practice calls between fork and
        // exec, the same as backend_seccomp's child setup.
        unsafe {
            cmd.pre_exec(move || {
                std::fs::write(&procs, "0")?;
                let param: libc::sched_param = std::mem::zeroed();
                if libc::sched_setscheduler(0, 7 /* SCHED_EXT */, &param) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let pid = child.id() as i32;
        assert!(child.wait().unwrap().success());
        pid
    }

    #[test]
    fn records_arrive_for_the_run_cgroup_only() {
        if skip() {
            return;
        }
        let epoch = GateMap::open().unwrap().epoch();
        let (cg_a, cg_b) = (Cgroup::new("a"), Cgroup::new("b"));
        let mut a = RunSensor::register(&cg_a.0, epoch).unwrap();
        let mut b = RunSensor::register(&cg_b.0, epoch).unwrap();
        assert_ne!(a.index, b.index);

        let pid = run_child(&cg_a);
        let (mut ra, mut rb) = (Vec::new(), Vec::new());
        a.drain(&mut ra).unwrap();
        b.drain(&mut rb).unwrap();

        let mine: Vec<_> = ra.iter().filter(|r| r.tgid == pid).collect();
        for kind in [
            RecordKind::Created,
            RecordKind::Asleep,
            RecordKind::WakeStart,
            RecordKind::WakeDone,
            RecordKind::Exited,
        ] {
            assert!(
                mine.iter().any(|r| r.kind == kind),
                "no {kind:?} in {mine:?}"
            );
        }
        assert!(
            ra.contains(&ThreadRecord {
                tid: pid,
                tgid: pid,
                kind: RecordKind::Joined,
                arg: 1,
            }),
            "the cgroup.procs write is a group attach of the leader"
        );
        // Every thread was created by one of the child's own threads (libtest
        // runs the workload on a thread of its own, not the leader).
        let tids: std::collections::HashSet<_> = mine.iter().map(|r| r.tid).collect();
        assert!(mine
            .iter()
            .filter(|r| r.kind == RecordKind::Created)
            .all(|r| tids.contains(&(r.arg as i32))));
        assert_eq!(a.dropped().unwrap(), 0);
        assert_eq!(b.dropped().unwrap(), 0);

        // The attach into `a` is reported to every other run as Left; nothing
        // else about the child may reach `b`.
        let leaked: Vec<_> = rb
            .iter()
            .filter(|r| tids.contains(&r.tid) && r.kind != RecordKind::Left)
            .collect();
        assert!(leaked.is_empty(), "b saw a's threads: {leaked:?}");
    }

    #[test]
    fn drop_frees_the_slot() {
        if skip() {
            return;
        }
        let epoch = GateMap::open().unwrap().epoch();
        let cg = Cgroup::new("drop");
        let sensor = RunSensor::register(&cg.0, epoch).unwrap();
        let index = sensor.index.to_ne_bytes();
        let slots = MapHandle::from_pinned_path(format!("{PIN_DIR}/sensor_slots")).unwrap();
        drop(sensor);
        // Another test may claim the freed index at once, so check it is no
        // longer ours rather than that it is empty.
        let slot = slots.lookup(&index, MapFlags::ANY).unwrap().unwrap();
        assert_ne!(u64::from_ne_bytes(slot[8..16].try_into().unwrap()), epoch);
    }
}
