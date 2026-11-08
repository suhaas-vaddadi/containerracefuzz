//! Needs root and a running `scx_crfuzz gated`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1
#![cfg(target_os = "linux")]

use scx_crfuzz::gate::GateMap;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;

const SCHED_EXT: i32 = 7;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn enroll_self() -> std::io::Result<()> {
    let param = libc::sched_param { sched_priority: 0 };
    match unsafe { libc::sched_setscheduler(0, SCHED_EXT, &param) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

fn spawn_spinner() -> Child {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "while :; do :; done"]);
    unsafe { cmd.pre_exec(enroll_self) };
    cmd.spawn().unwrap()
}

/// utime + stime in clock ticks (fields 14, 15 of /proc/<pid>/stat).
fn cpu_ticks(proc_path: &str) -> u64 {
    let stat = std::fs::read_to_string(format!("{proc_path}/stat")).unwrap();
    let f: Vec<&str> = stat.rsplit_once(')').unwrap().1.split_whitespace().collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

fn ticks_over(proc_path: &str, d: Duration) -> u64 {
    let a = cpu_ticks(proc_path);
    sleep(d);
    cpu_ticks(proc_path) - a
}

#[test]
#[ignore]
fn gate_stops_and_ungate_resumes() {
    let gm = GateMap::open().unwrap();
    let mut child = spawn_spinner();
    let p = format!("/proc/{}", child.id());
    sleep(ms(200));
    assert!(ticks_over(&p, ms(500)) > 0);

    gm.gate_tgid(child.id()).unwrap();
    assert!(gm.kick().unwrap() > 0);
    sleep(ms(100));
    assert_eq!(ticks_over(&p, Duration::from_secs(1)), 0, "gated task ran");

    gm.ungate_tgid(child.id()).unwrap();
    gm.kick().unwrap();
    assert!(ticks_over(&p, ms(500)) > 0, "ungated task stuck");

    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[ignore]
fn drop_clears_only_own_epoch() {
    let a = GateMap::open().unwrap();
    let b = GateMap::open().unwrap();
    assert_ne!(a.epoch, b.epoch);

    let (mut ca, mut cb) = (spawn_spinner(), spawn_spinner());
    a.gate_tgid(ca.id()).unwrap();
    b.gate_tgid(cb.id()).unwrap();
    a.kick().unwrap();
    drop(a);
    sleep(ms(100));
    assert!(ticks_over(&format!("/proc/{}", ca.id()), ms(500)) > 0, "a's gate survived drop");
    assert_eq!(ticks_over(&format!("/proc/{}", cb.id()), ms(500)), 0, "a's drop released b");

    drop(b);
    for c in [&mut ca, &mut cb] {
        c.kill().unwrap();
        c.wait().unwrap();
    }
}
