//! scx_crfuzz_gated: loads the gate scheduler once per campaign, pins its
//! maps and programs, and runs until SIGINT or ejection (spec §3.2).
//!
//!   scx_crfuzz_gated            run the daemon
//!   scx_crfuzz_gated --status   sched_ext state + pins
//!   scx_crfuzz_gated --kick     open a GateMap and kick every CPU
//!   scx_crfuzz_gated --reset    delete every gate entry of every run

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz_gated: Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        None => daemon::run(),
        Some("--status") => daemon::status(),
        Some("--kick") => {
            let n = scx_crfuzz_gate::GateMap::open()?.kick()?;
            println!("kicked {n} cpus");
            Ok(())
        }
        Some("--reset") => scx_crfuzz_gate::reset_all(),
        Some(a) => anyhow::bail!("unknown argument {a}"),
    }
}

#[cfg(target_os = "linux")]
mod daemon {
    use anyhow::{bail, Context, Result};
    use scx_crfuzz_gate::bpf_skel::*;
    use scx_crfuzz_gate::{enable_seq, sched_ext_state, LOCK_PATH, PINS, PIN_DIR};
    use scx_utils::{scx_ops_attach, scx_ops_load, scx_ops_open, uei_exited, uei_report};
    use std::fs::{self, File};
    use std::mem::MaybeUninit;
    use std::path::Path;
    use std::time::Duration;

    pub fn status() -> Result<()> {
        println!("state:      {}", sched_ext_state()?);
        println!("enable_seq: {}", enable_seq()?);
        let ops = fs::read_to_string("/sys/kernel/sched_ext/root/ops").unwrap_or_default();
        println!("ops:        {}", ops.trim());
        for p in PINS {
            let path = format!("{PIN_DIR}/{p}");
            let mark = if Path::new(&path).exists() { "present" } else { "missing" };
            println!("pin:        {path} {mark}");
        }
        Ok(())
    }

    pub fn run() -> Result<()> {
        // flock before the enabled check: two daemons starting together both
        // pass it (state isn't `enabled` until attach) and the second would
        // delete the first's pins.
        let lock = File::create(LOCK_PATH).with_context(|| LOCK_PATH)?;
        if lock.try_lock().is_err() {
            bail!("another scx_crfuzz_gated holds {LOCK_PATH}");
        }
        let state = sched_ext_state()?;
        if state != "disabled" {
            bail!("a sched_ext scheduler is already {state}");
        }
        // Holding the lock with sched_ext disabled, any pins are stale.
        let _ = fs::remove_dir_all(PIN_DIR);

        let mut open_object = MaybeUninit::uninit();
        let builder = BpfSkelBuilder::default();
        let mut skel = scx_ops_open!(builder, &mut open_object, crfuzz_gate_ops, None)?;
        let mut skel = scx_ops_load!(skel, crfuzz_gate_ops, uei)?;
        // Not pinned: the link dies with this process, so the kernel detaches
        // the scheduler and a new daemon can attach.
        let _link = scx_ops_attach!(skel, crfuzz_gate_ops)?;

        fs::create_dir_all(PIN_DIR)?;
        skel.maps.gate_tgid.pin(format!("{PIN_DIR}/gate_tgid"))?;
        skel.maps.gate_tid.pin(format!("{PIN_DIR}/gate_tid"))?;
        skel.progs.kick_all.pin(format!("{PIN_DIR}/kick_all"))?;
        skel.progs.new_epoch.pin(format!("{PIN_DIR}/new_epoch"))?;
        println!("scx_crfuzz_gated: attached, enable_seq={}", enable_seq()?);

        // ponytail: SIGINT kills the process without unpinning; stale pins are
        // harmless (GateMap::open checks state) and the next daemon removes them.
        while !uei_exited!(&skel, uei) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = fs::remove_dir_all(PIN_DIR);
        uei_report!(&skel, uei)?;
        bail!("scheduler ejected; every gate is released");
    }
}
