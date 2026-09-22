// SPDX-License-Identifier: GPL-2.0
//
//! The client face of the gate: open the pinned maps, gate and ungate by tgid.
//!
//! Deliberately knows nothing about roles, checkpoints or the engine. The only
//! vocabulary here is "thread group" and "epoch".

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::OwnedFd;

const PIN_DIR: &str = "/sys/fs/bpf/crfuzz";

/// Invoke a pinned `SEC("syscall")` program via `BPF_PROG_TEST_RUN` and return
/// its integer return value.
///
/// libbpf-rs 0.27.0's safe `Program::test_run` is only defined on
/// `ProgramMut`, which needs a live `&mut bpf_program` from an open
/// `bpf_object` -- not obtainable from a bare bpffs pin, which is all a
/// pinned program's fd gives us here (the daemon does not expose its
/// skeleton to us). `Program::fd_from_pinned_path` hands back just the fd, so
/// this calls the same libbpf function the safe wrapper calls, directly --
/// the same workaround upstream scx's `rust/scx_arena` used for the identical
/// reason (that crate is not part of this repository).
fn test_run(fd: &OwnedFd, ctx_in: Option<&[u8]>) -> Result<u32> {
    let mut opts = libbpf_rs::libbpf_sys::bpf_test_run_opts::default();
    opts.sz = std::mem::size_of_val(&opts) as _;
    if let Some(ctx) = ctx_in {
        opts.ctx_in = ctx.as_ptr().cast();
        opts.ctx_size_in = ctx.len() as u32;
    }
    let ret = unsafe { libbpf_rs::libbpf_sys::bpf_prog_test_run_opts(fd.as_raw_fd(), &mut opts) };
    anyhow::ensure!(
        ret == 0,
        "BPF_PROG_TEST_RUN failed: {}",
        std::io::Error::from_raw_os_error(-ret)
    );
    Ok(opts.retval)
}

pub struct GateMap {
    gate: MapHandle,
    kicker: OwnedFd,
    epoch: u64,
}

impl GateMap {
    /// Open the pinned maps and mint this run's epoch.
    ///
    /// Fails if the daemon is not running. It must never fall back to "no
    /// gating": that is indistinguishable from a successful multi-threaded
    /// hold and is exactly the silent under-holding this engine must not do.
    pub fn open() -> Result<GateMap> {
        let gate = MapHandle::from_pinned_path(format!("{PIN_DIR}/gate")).with_context(|| {
            format!("opening {PIN_DIR}/gate -- is scx_crfuzz_gated running?")
        })?;

        // Opened before the epoch mint below so a missing/unopenable kick
        // pin fails before the epoch counter is bumped: minting first and
        // failing after would burn an epoch value for a GateMap that never
        // gets constructed. Epochs are otherwise never reused, but there is
        // no reason to waste one on a failed open.
        //
        // No `.ok()` here: swallowing the real error and replacing it with a
        // guessed diagnosis ("too old, or failed to pin") is itself a defect
        // in a crate whose whole thesis is that failures must be legible --
        // if the pin exists but EACCES or something else stops it opening,
        // the guess would actively mislead. Propagate what actually failed.
        let kicker = libbpf_rs::Program::fd_from_pinned_path(format!("{PIN_DIR}/kick"))
            .with_context(|| {
                format!(
                    "{PIN_DIR}/kick is missing or unopenable: holds would be bounded \
                     by the scheduling slice instead of one round; refusing rather \
                     than under-holding"
                )
            })?;

        // The epoch is minted by invoking the pinned crfuzz_epoch_next
        // program, NOT by a userspace lookup-then-update on the epoch map.
        // A plain read-modify-write here would race: two GateMap::open()
        // calls started close together could both read the same old value
        // and both write old+1, so two concurrent engine runs would
        // silently share one epoch. Then the first run's Drop-time
        // clear_epoch() would delete the SECOND run's gates too, leaving it
        // silently under-holding with nothing reporting an error -- which
        // defeats the entire reason the epoch exists (letting concurrent
        // runs coexist). __sync_fetch_and_add inside the BPF program makes
        // the increment a single atomic RMW, so concurrent opens are
        // guaranteed distinct epochs.
        let epoch_next_fd = libbpf_rs::Program::fd_from_pinned_path(format!("{PIN_DIR}/epoch_next"))
            .with_context(|| format!("opening {PIN_DIR}/epoch_next"))?;
        let ret = test_run(&epoch_next_fd, None)
            .context("minting an epoch via crfuzz_epoch_next")?;
        let epoch = ret as u64;
        anyhow::ensure!(
            epoch != 0,
            "crfuzz_epoch_next returned 0: the epoch map lookup failed in BPF"
        );

        Ok(GateMap {
            gate,
            kicker,
            epoch,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn gate(&self, tgid: i32) -> Result<()> {
        self.gate
            .update(
                &(tgid as u32).to_ne_bytes(),
                &self.epoch.to_ne_bytes(),
                MapFlags::ANY,
            )
            .with_context(|| format!("gating tgid {tgid}"))
    }

    pub fn ungate(&self, tgid: i32) -> Result<()> {
        match self.gate.delete(&(tgid as u32).to_ne_bytes()) {
            Ok(()) => Ok(()),
            // Already gone: ops.exit_task reaps on leader exit, so a release
            // that races an exit is normal, not an error.
            Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("ungating tgid {tgid}")),
        }
    }

    pub fn is_gated(&self, tgid: i32) -> bool {
        matches!(
            self.gate.lookup(&(tgid as u32).to_ne_bytes(), MapFlags::ANY),
            Ok(Some(_))
        )
    }

    /// Delete every entry stamped with this run's epoch. Returns how many.
    pub fn clear_epoch(&self) -> Result<usize> {
        // Collect keys before deleting any of them: MapKeyIter::next feeds
        // the previously-returned key back to the kernel's
        // bpf_map_get_next_key to find the next one. Deleting a key on this
        // hash map before asking for its successor makes the kernel fall
        // back to scanning from the (now-absent) key's bucket, which can
        // revisit or skip entries -- a skipped entry is one of this run's
        // own gates left permanently held. `reset()` in main.rs already
        // collects first for the same reason; match it here.
        let keys: Vec<_> = self.gate.keys().collect();
        let mut n = 0;
        for key in keys {
            let Ok(Some(v)) = self.gate.lookup(&key, MapFlags::ANY) else {
                continue;
            };
            if u64::from_ne_bytes(v[..8].try_into().unwrap()) == self.epoch {
                self.gate.delete(&key).context("clearing a gate entry")?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Is a sched_ext scheduler still attached?
    ///
    /// Polled every round by `GateBackend`: if the kernel ejects the scheduler
    /// mid-run, every gate evaporates and the engine would otherwise go on
    /// believing it holds tasks it does not -- a clean-looking bogus verdict.
    pub fn scheduler_enabled() -> bool {
        std::fs::read_to_string("/sys/kernel/sched_ext/state")
            .map(|s| s.trim() == "enabled")
            .unwrap_or(false)
    }

    pub fn kick(&self) -> Result<()> {
        let nr_cpus = libbpf_rs::num_possible_cpus().context("num_possible_cpus")? as u32;
        let arg = nr_cpus.to_ne_bytes();
        test_run(&self.kicker, Some(&arg)).context("kicking cpus")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // Gating std::process::id() below is safe ONLY because the test process
    // itself is never enrolled in SCHED_EXT: the map entry has no scheduling
    // effect on it. This is exercising the map, not the hold -- do not
    // "improve" this into gating a task that is actually under this
    // scheduler, or the test process will hang itself (a gated task cannot
    // even be killed: it is runnable-but-never-dispatched, and it must run
    // to process SIGKILL).
    #[test]
    fn gate_then_ungate_round_trips() {
        if skip() {
            return;
        }
        let m = GateMap::open().unwrap();
        let tgid = std::process::id() as i32;
        assert!(!m.is_gated(tgid), "nothing gated to start with");
        m.gate(tgid).unwrap();
        assert!(m.is_gated(tgid));
        m.kick().unwrap();
        m.ungate(tgid).unwrap();
        assert!(!m.is_gated(tgid));
    }

    #[test]
    fn clear_epoch_removes_only_this_epochs_entries() {
        if skip() {
            return;
        }
        let a = GateMap::open().unwrap();
        let b = GateMap::open().unwrap();
        assert_ne!(a.epoch(), b.epoch(), "each open mints a fresh epoch");

        a.gate(424242).unwrap();
        b.gate(424243).unwrap();
        assert_eq!(a.clear_epoch().unwrap(), 1, "only a's entry");
        assert!(!a.is_gated(424242));
        assert!(b.is_gated(424243), "b's gate survives a's cleanup");
        b.clear_epoch().unwrap();
    }
}
