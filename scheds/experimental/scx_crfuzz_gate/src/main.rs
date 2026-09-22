// SPDX-License-Identifier: GPL-2.0
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::MapCore;
use scx_crfuzz_gate::bpf_skel::*;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const PIN_DIR: &str = "/sys/fs/bpf/crfuzz";
const LOCK_PATH_PRIMARY: &str = "/run/scx_crfuzz_gated.lock";
const LOCK_PATH_FALLBACK: &str = "/tmp/scx_crfuzz_gated.lock";

#[derive(clap::Parser)]
#[command(name = "scx_crfuzz_gated")]
struct Args {
    /// Clear every gate in the pinned map and exit.
    ///
    /// Wholesale rather than by epoch: a recovery tool has no epoch of its own
    /// to match. It operates on the pinned map, so it neither requires nor
    /// replaces a running daemon.
    #[arg(long)]
    reset: bool,

    /// Report whether the gate is attached and how many gates are live.
    #[arg(long)]
    status: bool,
}

fn open_pinned_gate() -> Result<libbpf_rs::MapHandle> {
    libbpf_rs::MapHandle::from_pinned_path(format!("{PIN_DIR}/gate"))
        .with_context(|| format!("opening {PIN_DIR}/gate -- is scx_crfuzz_gated running?"))
}

fn reset() -> Result<()> {
    let map = open_pinned_gate()?;
    let keys: Vec<Vec<u8>> = map.keys().collect();
    let n = keys.len();
    for k in keys {
        map.delete(&k).context("deleting a gate entry")?;
    }
    println!("cleared {n} gate(s)");
    Ok(())
}

fn status() -> Result<()> {
    let state = std::fs::read_to_string("/sys/kernel/sched_ext/state")
        .unwrap_or_else(|_| "unavailable".into());
    let ops = std::fs::read_to_string("/sys/kernel/sched_ext/root/ops")
        .unwrap_or_else(|_| "none".into());
    let attached = state.trim() == "enabled";
    println!("sched_ext state: {}", state.trim());
    println!("attached ops:    {}", ops.trim());
    match open_pinned_gate() {
        Ok(map) if attached => println!("live gates:      {}", map.keys().count()),
        // Pins exist but nothing is attached: since a daemon that is running
        // would show up as "enabled" above, these pins cannot belong to a
        // live scheduler. They are leftovers from a dead or cleanly-stopped
        // daemon that the next `scx_crfuzz_gated` start will clear -- a raw
        // count here would look like real state when it means nothing.
        Ok(_) => println!(
            "live gates:      stale pins present at {PIN_DIR} (no scheduler attached) -- \
             will be cleared on next daemon start"
        ),
        Err(e) => println!("live gates:      {e:#}"),
    }
    Ok(())
}

/// Remove the four pins and their directory. Called both to clear stale
/// leftovers from a dead daemon before pinning fresh ones, and on graceful
/// shutdown so a clean stop leaves nothing behind either.
fn remove_pins() -> std::io::Result<()> {
    for name in ["gate", "epoch", "kick", "epoch_next"] {
        match std::fs::remove_file(format!("{PIN_DIR}/{name}")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    match std::fs::remove_dir(PIN_DIR) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Acquire an exclusive, non-blocking advisory lock for the daemon's whole
/// lifetime.
///
/// This exists to close a race the "already attached" check alone cannot:
/// `/sys/kernel/sched_ext/state` does not flip to "enabled" until
/// `scx_ops_attach!` succeeds, so two daemons started close together can both
/// pass that check, both reach the pin step, and the second one deletes the
/// first's freshly-created pins as "stale" -- leaving the pins pointing at
/// the second daemon's (about-to-fail) maps while the first is the one
/// actually attached. flock is what makes only one daemon reach the pin step
/// at a time.
///
/// bpffs is deliberately not used for the lock: it is a special-purpose
/// filesystem for pinning BPF objects, not a general one, and must not be
/// assumed to support flock. /run is used because it is the conventional
/// home for this kind of runtime lockfile and is not wiped mid-boot the way
/// /tmp can be; /tmp is only a fallback for when /run is not writable.
fn acquire_startup_lock() -> Result<File> {
    let (path, file) = match OpenOptions::new().create(true).write(true).open(LOCK_PATH_PRIMARY) {
        Ok(f) => (LOCK_PATH_PRIMARY, f),
        Err(open_err) => {
            println!(
                "{LOCK_PATH_PRIMARY} is not writable ({open_err}); falling back to \
                 {LOCK_PATH_FALLBACK} for the startup lock"
            );
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(LOCK_PATH_FALLBACK)
                .with_context(|| {
                    format!("opening lockfile {LOCK_PATH_FALLBACK} (fallback from {LOCK_PATH_PRIMARY})")
                })?;
            (LOCK_PATH_FALLBACK, f)
        }
    };

    // SAFETY: flock's only preconditions are a valid fd, which `file` has.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        println!("startup lock acquired at {path}");
        return Ok(file);
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        // Distinct from the "already attached" failure below: that one means
        // a scheduler is fully up and running, this one means some
        // scx_crfuzz_gated -- possibly still mid-startup, possibly wedged --
        // holds the lock right now. Different causes, different message.
        anyhow::bail!("another scx_crfuzz_gated is starting or running (lock held on {path})");
    }
    Err(anyhow::Error::new(err).context(format!("locking {path}")))
}

fn main() -> Result<()> {
    let args = <Args as clap::Parser>::parse();
    if args.reset {
        return reset();
    }
    if args.status {
        return status();
    }

    // Held for the rest of main(): this is what makes the "already attached"
    // check below (and the stale-pin clearing further down) actually
    // exclusive, rather than just likely-exclusive. Binding it here, not in
    // an inner scope, keeps the fd -- and so the flock -- open until this
    // function returns, after the SIGINT loop and the unpin step.
    let _lock = acquire_startup_lock()?;

    // attach_struct_ops would fail here too, but with an opaque message.
    // Naming the incumbent up front is what makes a second daemon's refusal
    // legible rather than a bare libbpf errno.
    if let Ok(s) = std::fs::read_to_string("/sys/kernel/sched_ext/state") {
        if s.trim() == "enabled" {
            let ops = std::fs::read_to_string("/sys/kernel/sched_ext/root/ops")
                .unwrap_or_else(|_| "unknown".into());
            anyhow::bail!(
                "a sched_ext scheduler is already attached ({}); only one can be",
                ops.trim()
            );
        }
    }

    let mut open_object = std::mem::MaybeUninit::uninit();
    let skel_builder = BpfSkelBuilder::default();
    // scx_ops_open! (rather than a raw builder.open()) is required here: it
    // runs scx_utils::import_enums!, which writes the running kernel's
    // SCX_DSQ_GLOBAL/etc. values into the skeleton's rodata before load.
    // Skipping it leaves SCX_DSQ_GLOBAL at its link-time value of 0, so
    // dispatch's scx_bpf_dsq_move_to_local() targets DSQ 0, which the kernel
    // rejects as an invalid DSQ id and the scheduler is disabled on the spot.
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, crfuzz_gate_ops, None)
        .context("open skel")?;
    skel.struct_ops.crfuzz_gate_ops_mut().flags |= *scx_utils::compat::SCX_OPS_SWITCH_PARTIAL;
    let mut skel = scx_ops_load!(skel, crfuzz_gate_ops, uei).context("load skel")?;

    // Pinned so the scheduler is campaign-scoped rather than run-scoped: a
    // struct_ops attach costs a BPF load plus a verifier pass, and at ~200ms
    // per fuzzing iteration that cost would roughly double if paid per run.
    // The daemon attaches once; each engine run opens these pins instead.
    //
    // Any pins already at PIN_DIR at this point are provably stale -- but
    // only because of two checks together, not the attach check alone. The
    // "already attached" check above rules out a fully-attached sibling; the
    // startup lock held in `_lock` rules out a sibling that is concurrently
    // between that check and its own pin step (state does not flip to
    // "enabled" until scx_ops_attach! succeeds, so the attach check by
    // itself cannot see a racing daemon that hasn't attached yet). With both
    // held, whatever daemon put these pins here can only be dead: it either
    // crashed (no graceful unpin ran) or was killed before the shutdown path
    // below removed them. Clear them loudly rather than failing on the
    // EEXIST that pinning over them would produce, and rather than silently
    // reusing whatever a dead process left behind.
    if std::path::Path::new(PIN_DIR).exists() {
        println!("clearing stale pins from a previous daemon at {PIN_DIR}");
        remove_pins().with_context(|| format!("clearing stale pins at {PIN_DIR}"))?;
    }
    std::fs::create_dir_all(PIN_DIR).with_context(|| format!("creating {PIN_DIR}"))?;
    skel.maps.gate.pin(format!("{PIN_DIR}/gate")).context("pinning the gate map")?;
    skel.maps.epoch.pin(format!("{PIN_DIR}/epoch")).context("pinning the epoch map")?;
    // The kick program too: a pinned map gives no access to a program, and
    // GateMap::kick needs to invoke this one via test_run.
    skel.progs
        .crfuzz_kick_all
        .pin(format!("{PIN_DIR}/kick"))
        .context("pinning the kick program")?;
    // Same reasoning for the epoch minter: GateMap::open() invokes this via
    // test_run to bump the epoch atomically instead of doing a
    // lookup-then-update race in userspace.
    skel.progs
        .crfuzz_epoch_next
        .pin(format!("{PIN_DIR}/epoch_next"))
        .context("pinning the epoch_next program")?;

    let _link = scx_ops_attach!(skel, crfuzz_gate_ops).context("attach struct_ops")?;

    // Verified at startup rather than at first use: if kicking is not
    // available, every hold would silently have a one-tick boundary instead of
    // a one-round one, which is exactly the kind of quiet under-holding this
    // engine must never do.
    //
    // This proves the program loads, is callable from userspace while the
    // scheduler is attached, and runs its full loop (the returned count
    // equals every CPU we asked it to kick). It does NOT prove a running
    // sibling was actually preempted -- there is nothing enrolled in
    // SCHED_EXT to preempt at startup. Actual sibling preemption is verified
    // in Task 3's gate test, which watches a ticking process stop.
    {
        use libbpf_rs::ProgramInput;
        let nr_cpus = libbpf_rs::num_possible_cpus().context("num_possible_cpus")? as u32;
        let mut arg = nr_cpus.to_ne_bytes().to_vec();
        let input = ProgramInput {
            context_in: Some(&mut arg),
            ..Default::default()
        };
        let out = skel.progs.crfuzz_kick_all.test_run(input).context("kick prog test_run")?;
        anyhow::ensure!(
            out.return_value == nr_cpus,
            "kick prog kicked {} of {} cpus -- it did not run to completion, so holds would be \
             bounded by the scheduling slice rather than one round",
            out.return_value,
            nr_cpus
        );
        println!("kick mechanism verified over {nr_cpus} cpus");
    }

    println!("crfuzz gate attached; Ctrl-C to detach");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::Relaxed))?;
    while running.load(Ordering::Relaxed) && !uei_exited!(&skel, uei) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    drop(_link);
    // Clean shutdown leaves nothing behind. A failure here only warns rather
    // than aborting: the scheduler is already detached, and if this doesn't
    // fully succeed, the stale-pin clearing above will finish the job the
    // next time a daemon starts.
    if let Err(e) = remove_pins() {
        eprintln!("warning: failed to remove pins at {PIN_DIR}: {e}");
    }
    uei_report!(&skel, uei)?;
    Ok(())
}
