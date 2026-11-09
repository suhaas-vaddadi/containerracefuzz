//! The gate: the sched_ext scheduler (BPF), loaded by `serve` (`scx_crfuzz
//! gated`, or a `Scheduler` thread in a run's own process), and `GateMap`, the
//! client the engine drives it with over the pinned objects (spec §3.2).

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

use anyhow::{bail, Context, Result};
use bpf_skel::*;
use libbpf_rs::libbpf_sys;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use scx_utils::{scx_ops_attach, scx_ops_load, scx_ops_open, uei_exited, uei_report};
use std::ffi::CString;
use std::fs::{self, File};
use std::mem::MaybeUninit;
use std::os::fd::{FromRawFd, OwnedFd, AsRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

pub const PIN_DIR: &str = "/sys/fs/bpf/scx_crfuzz";
pub const LOCK_PATH: &str = "/run/scx_crfuzz_gate.lock";
pub const PINS: [&str; 3] = ["gate_tgid", "kick_all", "new_epoch"];
/// The enabled scheduler's name; ours is `crfuzz_gate_<version>_...`.
const OPS: &str = "/sys/kernel/sched_ext/root/ops";

fn ops() -> String {
    fs::read_to_string(OPS).unwrap_or_default().trim().to_string()
}

/// Load the gate scheduler, attach it, pin what `GateMap` opens, call `ready`
/// with its enable_seq, and hold it until `stop()` or ejection, unpinning on
/// every way out. Ejection is reported to stderr and returned as an error.
pub fn serve(stop: &dyn Fn() -> bool, ready: impl FnOnce(u64)) -> Result<()> {
    // flock before the state check: two starting together both pass it
    // (state isn't `enabled` until attach) and the second would delete the
    // first's pins.
    let lock = File::create(LOCK_PATH).with_context(|| LOCK_PATH)?;
    if lock.try_lock().is_err() {
        bail!("another crfuzz holds {LOCK_PATH}");
    }
    let state = sched_ext_state()?;
    if state != "disabled" {
        bail!("sched_ext is {state}, scheduler {:?} ({OPS})", ops());
    }
    // Holding the lock with sched_ext disabled, any pins are stale.
    let _ = fs::remove_dir_all(PIN_DIR);

    let mut open_object = MaybeUninit::uninit();
    let builder = BpfSkelBuilder::default();
    let mut skel = scx_ops_open!(builder, &mut open_object, crfuzz_gate_ops, None)?;
    let mut skel = scx_ops_load!(skel, crfuzz_gate_ops, uei)?;
    // Not pinned: the link dies with this process, so the kernel detaches
    // the scheduler and a new one can attach.
    let _link = scx_ops_attach!(skel, crfuzz_gate_ops)?;

    // Dropped before the link: unpin, then detach.
    struct Unpin;
    impl Drop for Unpin {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(PIN_DIR);
        }
    }
    let _unpin = Unpin;
    fs::create_dir_all(PIN_DIR)?;
    skel.maps.gate_tgid.pin(pin_path("gate_tgid"))?;
    skel.progs.kick_all.pin(pin_path("kick_all"))?;
    skel.progs.new_epoch.pin(pin_path("new_epoch"))?;
    ready(enable_seq()?);

    while !uei_exited!(&skel, uei) {
        if stop() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    uei_report!(&skel, uei)?;
    bail!("gate scheduler ejected; every gate is released");
}

/// The gate scheduler on a thread of this process, for a `run` or `replay`
/// that finds none. Drop unpins and detaches it.
pub struct Scheduler {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Scheduler {
    /// None: crfuzz's scheduler already runs (another crfuzz, or `scx_crfuzz
    /// gated`); runs use it. Any other scheduler is an error naming it.
    pub fn start() -> Result<Option<Self>> {
        let pinned = PINS.iter().all(|p| Path::new(&pin_path(p)).exists());
        if sched_ext_state()? == "enabled" && ops().starts_with("crfuzz_gate") && pinned {
            return Ok(None);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let s = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut up = false;
            let r = serve(&|| s.load(Ordering::Relaxed), |_| {
                up = true;
                let _ = tx.send(Ok(()));
            });
            match r {
                // Reported once; the runs then fail through `GateMap::check`.
                Err(e) if up => eprintln!("{e:#}"),
                r => drop(tx.send(r)),
            }
        });
        rx.recv().context("gate scheduler thread panicked")??;
        Ok(Some(Self { stop, thread: Some(thread) }))
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `scx_crfuzz status`: sched_ext state, scheduler and pins.
pub fn status() -> Result<()> {
    println!("state:      {}", sched_ext_state()?);
    println!("enable_seq: {}", enable_seq()?);
    println!("ops:        {}", ops());
    for p in PINS {
        let path = pin_path(p);
        let mark = if Path::new(&path).exists() { "present" } else { "missing" };
        println!("pin:        {path} {mark}");
    }
    Ok(())
}

pub fn sched_ext_state() -> Result<String> {
    Ok(fs::read_to_string("/sys/kernel/sched_ext/state")?.trim().to_string())
}

pub fn enable_seq() -> Result<u64> {
    Ok(fs::read_to_string("/sys/kernel/sched_ext/enable_seq")?.trim().parse()?)
}

fn pin_path(name: &str) -> String {
    format!("{PIN_DIR}/{name}")
}

fn open_pinned_prog(name: &str) -> Result<OwnedFd> {
    let path = CString::new(pin_path(name))?;
    let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
    if fd < 0 {
        bail!("{}: {}", pin_path(name), std::io::Error::from_raw_os_error(-fd));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Run a pinned `SEC("syscall")` program once and return its retval.
fn test_run(prog: &OwnedFd) -> Result<u32> {
    let mut opts: libbpf_sys::bpf_test_run_opts = unsafe { std::mem::zeroed() };
    opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as _;
    let err = unsafe { libbpf_sys::bpf_prog_test_run_opts(prog.as_raw_fd(), &mut opts) };
    if err < 0 {
        bail!("test_run: {}", std::io::Error::from_raw_os_error(-err));
    }
    Ok(opts.retval)
}

/// One run's handle on the gate scheduler. Every call first checks the scheduler
/// is still the one this run opened (L:Gate: 30 s ejection / restart).
/// Drop removes this run's gate entries.
pub struct GateMap {
    tgid: MapHandle,
    kick_prog: OwnedFd,
    enable_seq: u64,
    pub epoch: u32,
}

impl GateMap {
    pub fn open() -> Result<Self> {
        let state = sched_ext_state()?;
        if state != "enabled" {
            bail!("sched_ext is {state}; is the gate scheduler (`scx_crfuzz gated`) running?");
        }
        // Read before opening pins: a restart in between then shows up as a
        // changed seq on the first check rather than going unnoticed.
        let enable_seq = enable_seq()?;
        let open_map = |n| MapHandle::from_pinned_path(pin_path(n)).with_context(|| pin_path(n));
        let gm = Self {
            tgid: open_map("gate_tgid")?,
            kick_prog: open_pinned_prog("kick_all")?,
            enable_seq,
            epoch: test_run(&open_pinned_prog("new_epoch")?)?,
        };
        gm.check()?;
        Ok(gm)
    }

    pub fn check(&self) -> Result<()> {
        let state = sched_ext_state()?;
        if state != "enabled" || enable_seq()? != self.enable_seq {
            bail!("gate scheduler ejected or restarted (state={state}); every hold is released");
        }
        Ok(())
    }

    fn set(&self, map: &MapHandle, id: u32) -> Result<()> {
        self.check()?;
        map.update(&id.to_ne_bytes(), &self.epoch.to_ne_bytes(), MapFlags::ANY)?;
        Ok(())
    }

    fn unset(&self, map: &MapHandle, id: u32) -> Result<()> {
        self.check()?;
        // Already gone (exit_task cleaned it) is fine.
        let _ = map.delete(&id.to_ne_bytes());
        Ok(())
    }

    pub fn gate_tgid(&self, tgid: u32) -> Result<()> { self.set(&self.tgid, tgid) }
    pub fn ungate_tgid(&self, tgid: u32) -> Result<()> { self.unset(&self.tgid, tgid) }

    /// Preempt every CPU so a gate change takes effect. Asynchronous (IPI):
    /// not a barrier. Returns the number of CPUs kicked.
    pub fn kick(&self) -> Result<u32> {
        self.check()?;
        test_run(&self.kick_prog)
    }

    /// Remove this run's gate entries, then kick.
    pub fn clear(&self) -> Result<()> {
        clear_map(&self.tgid, Some(self.epoch))?;
        self.kick().map(|_| ())
    }
}

impl Drop for GateMap {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

/// Delete gate entries owned by `epoch`, or all of them if `None`.
fn clear_map(map: &MapHandle, epoch: Option<u32>) -> Result<()> {
    // Collect first: deleting mid-iteration can skip entries.
    let keys: Vec<Vec<u8>> = map
        .keys()
        .filter(|k| match epoch {
            None => true,
            Some(e) => matches!(map.lookup(k, MapFlags::ANY), Ok(Some(v)) if v == e.to_ne_bytes()),
        })
        .collect();
    for k in keys {
        let _ = map.delete(&k);
    }
    Ok(())
}

/// Drop the gate entries of `tgids`, whatever run owns them, then kick: for a
/// dead run's processes, which no `GateMap` will clear.
pub fn ungate_tgids(tgids: &[u32]) -> Result<()> {
    let map = MapHandle::from_pinned_path(pin_path("gate_tgid")).with_context(|| pin_path("gate_tgid"))?;
    for t in tgids {
        let _ = map.delete(&t.to_ne_bytes());
    }
    test_run(&open_pinned_prog("kick_all")?)?;
    Ok(())
}

/// `scx_crfuzz reset`: drop every gate entry of every run, then kick.
pub fn reset_all() -> Result<()> {
    let open_map = |n| MapHandle::from_pinned_path(pin_path(n)).with_context(|| pin_path(n));
    clear_map(&open_map("gate_tgid")?, None)?;
    test_run(&open_pinned_prog("kick_all")?)?;
    Ok(())
}
