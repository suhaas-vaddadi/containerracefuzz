use anyhow::{bail, Context, Result};
use libbpf_rs::libbpf_sys;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::ffi::CString;
use std::fs;
use std::os::fd::{FromRawFd, OwnedFd, AsRawFd};

pub const PIN_DIR: &str = "/sys/fs/bpf/scx_crfuzz";
pub const LOCK_PATH: &str = "/run/scx_crfuzz_gated.lock";
pub const PINS: [&str; 4] = ["gate_tgid", "gate_tid", "kick_all", "new_epoch"];

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

/// One run's handle on the gate daemon. Every call first checks the scheduler
/// is still the one this run opened (L:Gate: 30 s ejection / daemon restart).
/// Drop removes this run's gate entries.
pub struct GateMap {
    tgid: MapHandle,
    tid: MapHandle,
    kick_prog: OwnedFd,
    enable_seq: u64,
    pub epoch: u32,
}

impl GateMap {
    pub fn open() -> Result<Self> {
        let state = sched_ext_state()?;
        if state != "enabled" {
            bail!("sched_ext is {state}; is scx_crfuzz_gated running?");
        }
        // Read before opening pins: a restart in between then shows up as a
        // changed seq on the first check rather than going unnoticed.
        let enable_seq = enable_seq()?;
        let open_map = |n| MapHandle::from_pinned_path(pin_path(n)).with_context(|| pin_path(n));
        let gm = Self {
            tgid: open_map("gate_tgid")?,
            tid: open_map("gate_tid")?,
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

    /// Never gate a tgid and tids of the same group at once: is_held ORs them.
    pub fn gate_tgid(&self, tgid: u32) -> Result<()> { self.set(&self.tgid, tgid) }
    pub fn ungate_tgid(&self, tgid: u32) -> Result<()> { self.unset(&self.tgid, tgid) }
    pub fn gate_tid(&self, tid: u32) -> Result<()> { self.set(&self.tid, tid) }
    pub fn ungate_tid(&self, tid: u32) -> Result<()> { self.unset(&self.tid, tid) }

    /// Preempt every CPU so a gate change takes effect. Asynchronous (IPI):
    /// not a barrier. Returns the number of CPUs kicked.
    pub fn kick(&self) -> Result<u32> {
        self.check()?;
        test_run(&self.kick_prog)
    }

    /// Remove this run's gate entries, then kick.
    pub fn clear(&self) -> Result<()> {
        clear_maps(&[&self.tgid, &self.tid], Some(self.epoch))?;
        self.kick().map(|_| ())
    }
}

impl Drop for GateMap {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

/// Delete gate entries owned by `epoch`, or all of them if `None`.
fn clear_maps(maps: &[&MapHandle], epoch: Option<u32>) -> Result<()> {
    for map in maps {
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
    }
    Ok(())
}

/// `--reset`: drop every gate entry of every run, then kick.
pub fn reset_all() -> Result<()> {
    let open_map = |n| MapHandle::from_pinned_path(pin_path(n)).with_context(|| pin_path(n));
    clear_maps(&[&open_map("gate_tgid")?, &open_map("gate_tid")?], None)?;
    test_run(&open_pinned_prog("kick_all")?)?;
    Ok(())
}
