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

/// A spinner that is the root of `gm`'s tree.
fn spawn_spinner(gm: &GateMap) -> Child {
    let join = gm.joiner();
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "while :; do :; done"]);
    unsafe {
        cmd.pre_exec(move || {
            join()?;
            enroll_self()
        })
    };
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
    let mut child = spawn_spinner(&gm);
    let p = format!("/proc/{}", child.id());
    sleep(ms(200));
    assert!(ticks_over(&p, ms(500)) > 0);
    assert!(!gm.quiet().unwrap(), "a spinner read quiet");
    assert_eq!(gm.name(child.id()).as_deref(), Some("0"));
    assert_eq!(gm.members().into_iter().collect::<Vec<_>>(), [child.id()]);

    gm.set_gate(true).unwrap();
    sleep(ms(100));
    assert_eq!(ticks_over(&p, Duration::from_secs(1)), 0, "gated task ran");
    assert!(!gm.quiet().unwrap(), "a gated spinner is still runnable");

    gm.set_gate(false).unwrap();
    assert!(ticks_over(&p, ms(500)) > 0, "ungated task stuck");

    child.kill().unwrap();
    child.wait().unwrap();
    assert!(gm.kill(), "the tree outlived its root");
    assert!(gm.quiet().unwrap(), "an empty tree is quiet");
}

#[test]
#[ignore]
fn drop_clears_only_own_run() {
    let a = GateMap::open().unwrap();
    let b = GateMap::open().unwrap();
    assert_ne!(a.run, b.run);

    let (mut ca, mut cb) = (spawn_spinner(&a), spawn_spinner(&b));
    a.set_gate(true).unwrap();
    b.set_gate(true).unwrap();
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
