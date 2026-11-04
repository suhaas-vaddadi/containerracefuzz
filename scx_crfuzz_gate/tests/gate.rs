//! Needs root, a running scx_crfuzz_gated, and `go` on PATH:
//!   sudo -E cargo test -p scx_crfuzz_gate -- --ignored --test-threads=1
#![cfg(target_os = "linux")]

use scx_crfuzz_gate::GateMap;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
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

fn spawn_ext(mut cmd: Command) -> Child {
    unsafe { cmd.pre_exec(enroll_self) };
    cmd.spawn().unwrap()
}

fn spawn_spinner() -> Child {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "while :; do :; done"]);
    spawn_ext(cmd)
}

/// Fields after `comm` in a /proc stat file: [0] = state, [11..13] = utime, stime.
fn stat_fields(path: String) -> Vec<String> {
    let stat = std::fs::read_to_string(path).unwrap();
    stat.rsplit_once(')').unwrap().1.split_whitespace().map(String::from).collect()
}

/// utime + stime in clock ticks, for a whole process or (with `/task/<tid>`) one thread.
fn cpu_ticks(proc_path: &str) -> u64 {
    let f = stat_fields(format!("{proc_path}/stat"));
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

fn thread_state(pid: u32, tid: u32) -> String {
    stat_fields(format!("/proc/{pid}/task/{tid}/stat"))[0].clone()
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

/// A running (not syscall-parked) thread gated by tid stops; its siblings don't.
#[test]
#[ignore]
fn tid_gate_holds_one_thread_siblings_run() {
    let gm = GateMap::open().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let threads: Vec<_> = (0..3)
        .map(|_| {
            let (stop, tx) = (stop.clone(), tx.clone());
            std::thread::spawn(move || {
                enroll_self().unwrap();
                let count = Arc::new(AtomicU64::new(0));
                tx.send((unsafe { libc::gettid() } as u32, count.clone())).unwrap();
                while !stop.load(Ordering::Relaxed) {
                    count.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    let workers: Vec<(u32, Arc<AtomicU64>)> = rx.iter().take(3).collect();
    let snap = || workers.iter().map(|(_, c)| c.load(Ordering::Relaxed)).collect::<Vec<_>>();
    let advanced = |a: &[u64], b: &[u64]| a.iter().zip(b).map(|(x, y)| y > x).collect::<Vec<_>>();

    gm.gate_tid(workers[0].0).unwrap();
    gm.kick().unwrap();
    sleep(ms(100));
    let a = snap();
    sleep(ms(500));
    assert_eq!(advanced(&a, &snap()), [false, true, true], "only worker 0 should be held");

    gm.ungate_tid(workers[0].0).unwrap();
    gm.kick().unwrap();
    let a = snap();
    sleep(ms(200));
    assert_eq!(advanced(&a, &snap()), [true, true, true], "worker 0 not released");

    stop.store(true, Ordering::Relaxed);
    threads.into_iter().for_each(|t| t.join().unwrap());
}

fn go_readers_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let out = std::env::temp_dir().join("crfuzz_go_readers");
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/go_readers");
        let ok = Command::new("go")
            .args(["build", "-o"])
            .arg(&out)
            .current_dir(src)
            .status()
            .expect("go on PATH")
            .success();
        assert!(ok, "go build failed");
        out
    })
}

/// The Go fixture with pipes on its fds 3 (goroutine A) and 4 (goroutine B),
/// and its stdout lines delivered on a channel.
struct GoReaders {
    child: Child,
    wake: [std::io::PipeWriter; 2],
    lines: mpsc::Receiver<String>,
}

impl GoReaders {
    fn spawn() -> Self {
        let (ra, wa) = std::io::pipe().unwrap();
        let (rb, wb) = std::io::pipe().unwrap();
        let (fa, fb) = (ra.as_raw_fd(), rb.as_raw_fd());
        let mut cmd = Command::new(go_readers_bin());
        cmd.stdout(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                // Move both out of the way first so dup2 to 3/4 can't clobber either.
                let a = libc::fcntl(fa, libc::F_DUPFD, 10);
                let b = libc::fcntl(fb, libc::F_DUPFD, 10);
                if a < 0 || b < 0 || libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = spawn_ext(cmd);
        let (tx, lines) = mpsc::channel();
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines() {
                if tx.send(l.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self { child, wake: [wa, wb], lines }
    }

    fn proc_path(&self) -> String {
        format!("/proc/{}", self.child.id())
    }

    /// The tid currently blocked in read(2) on `fd`: whichever M carries that
    /// goroutine right now. Stable for as long as it stays in the syscall.
    fn tid_in_read(&self, fd: i32) -> u32 {
        let want = format!("{} {:#x} ", libc::SYS_read, fd);
        for _ in 0..200 {
            for e in std::fs::read_dir(format!("{}/task", self.proc_path())).unwrap() {
                let e = e.unwrap();
                let sc = std::fs::read_to_string(e.path().join("syscall")).unwrap_or_default();
                if sc.starts_with(&want) {
                    return e.file_name().to_str().unwrap().parse().unwrap();
                }
            }
            sleep(ms(10));
        }
        panic!("no thread blocked in read on fd {fd}");
    }

    fn wake(&mut self, which: usize) {
        self.wake[which].write_all(b"x").unwrap();
    }

    fn expect_line(&self, want: &str) {
        assert_eq!(self.lines.recv_timeout(ms(1000)).as_deref(), Ok(want));
    }

    fn expect_silence(&self, d: Duration) {
        if let Ok(l) = self.lines.recv_timeout(d) {
            panic!("goroutine {l} ran while held");
        }
    }
}

impl Drop for GoReaders {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Goroutine-level interleaving control under M:N: hold the threads parked in
/// A's and B's syscalls, wake both, and release them in a chosen order. The
/// rest of the runtime (spinners, GC) must keep running throughout.
#[test]
#[ignore]
fn tid_gate_orders_go_goroutines_at_syscalls() {
    let gm = GateMap::open().unwrap();
    let mut go = GoReaders::spawn();
    let p = go.proc_path();

    for round in 0..10 {
        // Even rounds release B before A, odd rounds A before B.
        let order = if round % 2 == 0 { [1, 0] } else { [0, 1] };
        let tids = [go.tid_in_read(3), go.tid_in_read(4)];
        eprintln!("round {round}: A on tid {}, B on tid {}", tids[0], tids[1]);
        for t in tids {
            gm.gate_tid(t).unwrap();
        }
        go.wake(0);
        go.wake(1);
        sleep(ms(50));
        for t in tids {
            assert_eq!(thread_state(go.child.id(), t), "R", "woken thread {t} not runnable");
        }
        let before = tids.map(|t| cpu_ticks(&format!("{p}/task/{t}")));
        let others = ticks_over(&p, ms(300));
        go.expect_silence(ms(0));
        assert_eq!(tids.map(|t| cpu_ticks(&format!("{p}/task/{t}"))), before, "held thread ran");
        assert!(others > 10, "runtime stalled while A and B held ({others} ticks)");

        for (i, &w) in order.iter().enumerate() {
            gm.ungate_tid(tids[w]).unwrap();
            gm.kick().unwrap();
            go.expect_line(["A", "B"][w]);
            if i == 0 {
                go.expect_silence(ms(200));
            }
        }
    }
}

/// The hazard (L:Seccomp): a per-tid gate on a Go thread in user code blocks
/// stop-the-world, and the whole runtime stalls with it. Held well under the
/// 30 s watchdog.
#[test]
#[ignore]
fn tid_gate_in_go_user_code_stalls_runtime() {
    let gm = GateMap::open().unwrap();
    let go = GoReaders::spawn();
    let p = go.proc_path();
    sleep(ms(300));
    let free = ticks_over(&p, ms(1000));

    let running = std::fs::read_dir(format!("{p}/task"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|t| std::fs::read_to_string(t.join("syscall")).unwrap_or_default().starts_with("running"))
        .expect("a thread in user code");
    let tid: u32 = running.file_name().unwrap().to_str().unwrap().parse().unwrap();

    gm.gate_tid(tid).unwrap();
    gm.kick().unwrap();
    sleep(ms(300));
    let held = ticks_over(&p, ms(1000));
    gm.ungate_tid(tid).unwrap();
    gm.kick().unwrap();
    sleep(ms(200));
    let after = ticks_over(&p, ms(1000));
    eprintln!("ticks/s: free {free}, one user-code thread held {held}, released {after}");

    assert!(held * 4 < free, "runtime kept running with a user-code thread held");
    assert!(after * 2 > free, "runtime did not recover");
}
