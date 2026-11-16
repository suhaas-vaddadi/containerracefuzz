//! The gate: the sched_ext scheduler (BPF), loaded by `serve` (`scx_crfuzz
//! gated`, or a `Scheduler` thread in a run's own process), and `GateMap`, a
//! run's client for it over the pinned objects. The scheduler tracks each
//! run's task tree: which tasks are in it, whether any can run, what each
//! process is called, and whether it may run at all (see `bpf/main.bpf.c`).

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

use anyhow::{bail, ensure, Context, Result};
use bpf_skel::*;
use libbpf_rs::libbpf_sys;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use scx_utils::{scx_ops_attach, scx_ops_load, scx_ops_open, uei_exited, uei_report};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

pub const PIN_DIR: &str = "/sys/fs/bpf/scx_crfuzz";
pub const LOCK_PATH: &str = "/run/scx_crfuzz_gate.lock";
/// Maps, then the `SEC("syscall")` programs.
pub const PINS: [&str; 6] = ["runs", "procs", "sys_regs", "new_run", "join", "set_gate"];
/// The enabled scheduler's name; ours is `crfuzz_gate_<version>_...`.
const OPS: &str = "/sys/kernel/sched_ext/root/ops";

pub fn ops() -> String {
    fs::read_to_string(OPS).unwrap_or_default().trim().to_string()
}

/// Load the gate scheduler, attach it, pin what `GateMap` opens, call `ready`
/// with its enable_seq, and hold it until `stop()` or ejection, unpinning on
/// every way out. Ejection is reported to stderr and returned as an error.
pub fn serve(stop: &dyn Fn() -> bool, ready: impl FnOnce(u64)) -> Result<()> {
    // Warnings and failures only: libbpf's info lines ("member ... not found
    // in kernel, skipping it") read as errors.
    libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |_, m: String| eprint!("{m}"))));
    // flock before the state check: two starting together both pass it
    // (state isn't `enabled` until attach) and the second would delete the
    // first's pins.
    let lock = File::create(LOCK_PATH).with_context(|| LOCK_PATH)?;
    if lock.try_lock().is_err() {
        bail!("another crfuzz holds {LOCK_PATH}");
    }
    let state = sched_ext_state()?;
    if state != "disabled" {
        bail!("sched_ext is {state}, scheduler {:?} ({OPS}); if it is crfuzz_gate without every pin in {PIN_DIR} (an older crfuzz), restart `scx_crfuzz gated`", ops());
    }
    // Holding the lock with sched_ext disabled, any pins are stale.
    let _ = fs::remove_dir_all(PIN_DIR);

    let mut open_object = MaybeUninit::uninit();
    let builder = BpfSkelBuilder::default();
    let mut skel = scx_ops_open!(builder, &mut open_object, crfuzz_gate_ops, None)?;
    let mut skel = scx_ops_load!(skel, crfuzz_gate_ops, uei)?;
    // Not pinned: the links die with this process, so the kernel detaches
    // the scheduler and a new one can attach. Attaches the tree's
    // tracepoints and the callsite kprobe too (by their SEC names).
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
    skel.maps.runs.pin(pin_path("runs"))?;
    skel.maps.procs.pin(pin_path("procs"))?;
    skel.maps.sys_regs.pin(pin_path("sys_regs"))?;
    skel.progs.new_run.pin(pin_path("new_run"))?;
    skel.progs.join.pin(pin_path("join"))?;
    skel.progs.set_gate.pin(pin_path("set_gate"))?;
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
        if running()? {
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
    const STATE: &str = "/sys/kernel/sched_ext/state";
    Ok(fs::read_to_string(STATE).context(STATE)?.trim().to_string())
}

/// crfuzz's scheduler is enabled, its pins present: runs borrow it.
pub fn running() -> Result<bool> {
    let pinned = PINS.iter().all(|p| Path::new(&pin_path(p)).exists());
    Ok(sched_ext_state()? == "enabled" && ops().starts_with("crfuzz_gate") && pinned)
}

pub fn enable_seq() -> Result<u64> {
    Ok(fs::read_to_string("/sys/kernel/sched_ext/enable_seq")?.trim().parse()?)
}

fn pin_path(name: &str) -> String {
    format!("{PIN_DIR}/{name}")
}

fn open_map(name: &str) -> Result<MapHandle> {
    MapHandle::from_pinned_path(pin_path(name)).with_context(|| pin_path(name))
}

fn open_prog(name: &str) -> Result<OwnedFd> {
    let path = CString::new(pin_path(name))?;
    let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
    if fd < 0 {
        bail!("{}: {}", pin_path(name), std::io::Error::from_raw_os_error(-fd));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Run a pinned `SEC("syscall")` program on `arg` (its `struct run_arg`) and
/// return its retval. No allocation: also called between fork and exec.
fn test_run(prog: RawFd, arg: [u32; 2]) -> std::io::Result<u32> {
    let mut opts: libbpf_sys::bpf_test_run_opts = unsafe { std::mem::zeroed() };
    opts.sz = std::mem::size_of::<libbpf_sys::bpf_test_run_opts>() as _;
    opts.ctx_in = arg.as_ptr().cast();
    opts.ctx_size_in = std::mem::size_of_val(&arg) as _;
    let err = unsafe { libbpf_sys::bpf_prog_test_run_opts(prog, &mut opts) };
    if err < 0 {
        return Err(std::io::Error::from_raw_os_error(-err));
    }
    Ok(opts.retval)
}

/// A map key or value made of u32s (`struct run`'s `busy` is its last two).
fn words(v: &[u8]) -> Vec<u32> {
    v.chunks_exact(4).map(|c| u32::from_ne_bytes(c.try_into().unwrap())).collect()
}

/// The tgids of `run`'s tree. A set: a key deleted mid-walk restarts it.
fn members(procs: &MapHandle, run: u32) -> BTreeSet<u32> {
    procs.keys().filter(|k| matches!(procs.lookup(k, MapFlags::ANY), Ok(Some(v)) if words(&v)[0] == run)).map(|k| words(&k)[0]).collect()
}

/// SIGKILL `run`'s tree until nothing of it is left, for up to 1 s. By the
/// tree, not a cgroup: a container runtime moves its processes between
/// cgroups. A process is gone once it is reaped (by its parent or init): the
/// kill then finds no one, and its entry is dropped here rather than waiting
/// for the scheduler to see it freed. A member forked mid-walk is caught by
/// the next round. False if some are still there. The run must be ungated: a
/// gated task can't run to act on the signal.
fn kill(procs: &MapHandle, run: u32) -> bool {
    for _ in 0..1000 {
        let left = members(procs, run);
        if left.is_empty() {
            return true;
        }
        for t in left {
            if unsafe { libc::kill(t as i32, libc::SIGKILL) } != 0 {
                let _ = procs.delete(&t.to_ne_bytes());
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// One run's handle on the gate scheduler: its tree's root joins through it,
/// and the engine reads and gates the tree with it. Every call first checks
/// the scheduler is still the one this run opened: a task held past 30 s
/// ejects it, and a restarted scheduler reads `enabled` again but has fresh
/// maps. Drop ungates and forgets the run.
pub struct GateMap {
    runs: MapHandle,
    procs: MapHandle,
    sys_regs: MapHandle,
    join: OwnedFd,
    set_gate: OwnedFd,
    enable_seq: u64,
    /// This run's id in the scheduler.
    pub run: u32,
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
        let gm = Self {
            runs: open_map("runs")?,
            procs: open_map("procs")?,
            sys_regs: open_map("sys_regs")?,
            join: open_prog("join")?,
            set_gate: open_prog("set_gate")?,
            enable_seq,
            run: test_run(open_prog("new_run")?.as_raw_fd(), [0; 2])?,
        };
        ensure!(gm.run != 0, "the gate's run table is full");
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

    /// For the SUT's `pre_exec`: the calling process becomes the root of this
    /// run's tree. Before it enrolls in SCHED_EXT, or the scheduler misses
    /// its first runnable transition. Async-signal-safe.
    pub fn joiner(&self) -> impl Fn() -> std::io::Result<()> + Send + Sync + 'static {
        let (prog, run) = (self.join.as_raw_fd(), self.run);
        move || match test_run(prog, [run, 0])? {
            0 => Ok(()),
            e => Err(std::io::Error::from_raw_os_error(-(e as i32))),
        }
    }

    /// No task of the tree can run: none is runnable, none is being woken.
    /// Exact as of the read; a thread asleep on a timer or on I/O from
    /// outside the tree still wakes on its own later. Fails if part of the
    /// tree is out of the gate's reach, which no later read can see.
    pub fn quiet(&self) -> Result<bool> {
        self.check()?;
        let r = words(&self.runs.lookup(&self.run.to_ne_bytes(), MapFlags::ANY)?.context("the run is gone from the gate")?);
        ensure!(r[2] == 0, "a task of the SUT tree left SCHED_EXT, or the gate's process table is full: the gate can no longer stop the tree");
        Ok(r[4] == 0 && r[5] == 0)
    }

    /// Stop (or let go) every task of the tree, whatever it forks meanwhile,
    /// wherever it has moved. Takes effect as each CPU is preempted (an IPI):
    /// not a barrier.
    pub fn set_gate(&self, on: bool) -> Result<()> {
        self.check()?;
        ensure!(test_run(self.set_gate.as_raw_fd(), [self.run, on as u32])? == 0, "the run is gone from the gate");
        Ok(())
    }

    /// `tid`'s user `[pc, sp, fp]` at its latest syscall (read while it is
    /// held there, that syscall's) and its tgid. None: it trapped outside
    /// SCHED_EXT or outside every tree; `quiet` then fails.
    pub fn sys_regs(&self, tid: u32) -> Option<([u64; 3], u32)> {
        let v = self.sys_regs.lookup(&tid.to_ne_bytes(), MapFlags::ANY).ok().flatten()?;
        let w = |i: usize| Some(u64::from_ne_bytes(v.get(i * 8..i * 8 + 8)?.try_into().ok()?));
        Some(([w(0)?, w(1)?, w(2)?], w(3)? as u32))
    }

    /// `tgid`'s place in this run's process creation tree (stable across
    /// runs, unlike a tgid): the root is `0`, the k-th process a process
    /// forks is `<its name>/k`. Kept by the scheduler from each fork, so a
    /// tgid reused in the run names its new owner. None: not of this run, or
    /// deeper than the scheduler records.
    pub fn name(&self, tgid: u32) -> Option<String> {
        let p = words(&self.procs.lookup(&tgid.to_ne_bytes(), MapFlags::ANY).ok()??);
        let path = p.get(3..3 + p[2] as usize).filter(|_| p[0] == self.run)?;
        Some(path.iter().fold("0".to_string(), |n, k| format!("{n}/{k}")))
    }

    /// The tgids of the tree.
    pub fn members(&self) -> BTreeSet<u32> {
        members(&self.procs, self.run)
    }

    /// Ungate and kill the tree; false if some of it is still there.
    pub fn kill(&self) -> bool {
        let _ = self.set_gate(false);
        kill(&self.procs, self.run)
    }
}

impl Drop for GateMap {
    fn drop(&mut self) {
        let _ = self.set_gate(false);
        let _ = self.runs.delete(&self.run.to_ne_bytes());
    }
}

/// The runs of crfuzz processes that died without dropping them: ungate and
/// forget each, and kill its tree. A live owner's runs are never touched:
/// several crfuzz processes can share one scheduler. How many still have
/// tasks.
// ponytail: a dead owner's pid reused by a live process keeps its stale run
// until that pid exits.
pub fn sweep() -> Result<usize> {
    let (runs, procs, gate) = (open_map("runs")?, open_map("procs")?, open_prog("set_gate")?);
    let mut left = 0;
    // Collect first: deleting mid-iteration can skip entries.
    for k in runs.keys().collect::<Vec<_>>() {
        let Ok(Some(r)) = runs.lookup(&k, MapFlags::ANY) else { continue };
        if Path::new(&format!("/proc/{}", words(&r)[0])).exists() {
            continue;
        }
        let run = words(&k)[0];
        // Ungate before killing: the owner may have died in a tree hold.
        let _ = test_run(gate.as_raw_fd(), [run, 0]);
        let _ = runs.delete(&k);
        left += !kill(&procs, run) as usize;
    }
    Ok(left)
}

/// `scx_crfuzz reset`: ungate every run.
pub fn reset_all() -> Result<()> {
    let (runs, gate) = (open_map("runs")?, open_prog("set_gate")?);
    for k in runs.keys() {
        test_run(gate.as_raw_fd(), [words(&k)[0], 0])?;
    }
    Ok(())
}
