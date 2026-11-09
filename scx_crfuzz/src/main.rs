//! scx_crfuzz run DIR --attacker UID:GID [--seeds N] [--time DURATION] [--first-seed S] [--jobs N] [--private DIR]... [--mutator PROG] [--layout PROG] [--scope DIR]... [--timeout SECS] [-v] -- CMD [ARGS...]
//! scx_crfuzz replay FILE [-v]
//! scx_crfuzz gated | status | reset | check
//!
//! `run` sweeps seeds S..S+N (default S 0; §3.10), each exhaustive over its
//! windows; with no `--seeds`, S, S+1, ... until stopped. `--time DURATION`
//! (`90s`, `30m`, `2h`; bare: seconds) starts no run once that much time has
//! passed: the stop below, but with a `time limit:` line and exit 0 or 3.
//! A seed runs CMD under POS (discovery): a baseline under the seed, no
//! mutator, then once per window, each run with its own canary, judged
//! against the attacker alice (UID:GID, no groups, no caps: §1). The windows
//! are the baseline's holds with a known path, not keys.all and not a `?tid`,
//! one per (syscall, path, occurrence): with `--mutator`, PROG (a binary or a
//! script with a #!) runs at window k's hold alone, once, as alice in the held
//! task's view: its namespaces, root and cwd, the path as issued in argv[1]
//! (§10.1). `--scope DIR` (repeatable) keeps only windows whose absolute path
//! is under one of the DIRs: where alice can act. A window that never reaches
//! its target is unmutated. `--layout PROG` (absolute, recorded in the
//! schedule) runs as root before every run to restore the starting
//! filesystem, so no run sees what an earlier one's SUT or mutator left
//! behind; a failure makes the run invalid. `--timeout SECS` (1 to 30,
//! default 30, recorded) ends a run still going.
//!
//! `--jobs N` (default 1) runs N seeds at once, one worker thread each, all
//! sharing the gate scheduler. `--private DIR` (repeatable, recorded, so
//! `replay` too) gives each worker its own copy of DIR: its own mount
//! namespace, `/` rslave, a `cp -a` of DIR under /var/lib/crfuzz/work
//! bind-mounted over DIR, inherited by the layout, the SUT and the mutator.
//! N > 1 needs one; neither the canaries nor DIR may be in one. At N > 1 a
//! seed's lines print as one block when it ends, rows and finding numbers go
//! by completion.
//!
//! Window k's schedule (§3.8) goes to `DIR/runs/<seed>/<k>.sched` and a row to
//! `DIR/runs.tsv`; its runs' output (SUT and layout: discovery, confirm,
//! minimize) to `DIR/runs/<seed>/<k>.log`, the baseline's to `baseline.log`,
//! each run after a `== <run>` line. A Violation repeating a finding
//! (`Dedup::repeated_by`) is only counted; a new one is confirmed and
//! minimized, as `replay` does, and if confirmed is finding n:
//! `DIR/findings/<n>/{schedule,seeds}`, `seeds` one `seed:k` per line. An
//! invalid run or baseline is recorded and the sweep goes on. Each seed ends
//! with its verdict: `safe` (every window valid, mutated and no Violation),
//! `unsafe` (a window's Violation), `incomplete` (else), or `no windows` (no
//! mutator or no target: the seed is one unmutated run, window 0); the sweep
//! with a summary.
//!
//! `replay FILE`: everything comes from the file. One baseline, a replay with
//! every recorded mutation that must give the same class and normalized
//! findings, then one replay per recorded mutation alone, in order, until one
//! flags a finding of the schedule's: the guilty hold.
//!
//! `replay` discards SUT and layout output; `-v` passes it to stderr and
//! prints every run's decisions. Exit status: 0 done, 3 done with a
//! confirmed finding (`replay`: a confirmed Violation), 2 a usage error, 1
//! any other error (`replay`: the schedule not reproduced), 130 stopped by
//! SIGINT or SIGTERM: the runs then ending are discarded, the campaign's
//! summary printed after an `interrupted:` line; a second signal kills at
//! once. Needs root.
//!
//! The gate scheduler: `run` and `replay` use the one running (another
//! crfuzz's, or `gated`'s), else load their own for their life; any other
//! sched_ext scheduler is an error. `gated` holds it in the foreground until
//! SIGINT or SIGTERM (exit 0) or ejection, for tests and for several crfuzz
//! processes sharing one; `status` prints sched_ext's state and the pins;
//! `reset` deletes every gate entry of every run.
//!
//! `check` runs the preflight, one line per check, and exits 1 if any failed;
//! `run` and `replay` run it first and stop on its failures.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scx_crfuzz runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
const USAGE: &str = "usage: scx_crfuzz run DIR --attacker UID:GID [--seeds N] [--time DURATION] [--first-seed S]
                      [--jobs N] [--private DIR]... [--mutator PROG] [--layout PROG] [--scope DIR]... [--timeout SECS] [-v] -- CMD [ARGS...]
       scx_crfuzz replay FILE [-v]
       scx_crfuzz gated     hold the gate scheduler until SIGINT/SIGTERM
       scx_crfuzz status    sched_ext state and pins
       scx_crfuzz reset     delete every gate entry of every run
       scx_crfuzz check     preflight: root, kernel, sched_ext, cgroup v2, bpffs, /var/lib/crfuzz
       scx_crfuzz --help | --version";

/// A bad or missing argument: exit 2, after the usage.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Usage(String);
#[cfg(target_os = "linux")]
impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n{USAGE}", self.0)
    }
}
#[cfg(target_os = "linux")]
impl std::error::Error for Usage {}

/// `90`, `90s`, `30m`, `2h`: digits, then at most one unit.
#[cfg(any(target_os = "linux", test))]
fn duration(s: &str) -> Option<std::time::Duration> {
    let (n, mul) = [("s", 1), ("m", 60), ("h", 3600)].into_iter().find_map(|(u, m)| Some((s.strip_suffix(u)?, m))).unwrap_or((s, 1));
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse::<u64>().ok()?.checked_mul(mul).map(std::time::Duration::from_secs)
}

#[cfg(test)]
#[test]
fn durations() {
    let secs = |s| duration(s).map(|d| d.as_secs());
    assert_eq!([secs("90"), secs("90s"), secs("30m"), secs("2h"), secs("0")], [Some(90), Some(90), Some(1800), Some(7200), Some(0)]);
    for bad in ["", "s", "1d", "1.5h", "+1", "-1", "1 h", "1hs", "2H"] {
        assert_eq!(secs(bad), None, "{bad}");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(match crfuzz() {
        Ok(code) => code,
        Err(e) if e.is::<Usage>() => {
            eprintln!("{e}");
            2
        }
        // `replay` stopped by SIGINT/SIGTERM, every Drop run.
        Err(e) if e.is::<scx_crfuzz::engine::Interrupted>() => {
            eprintln!("{e}");
            130
        }
        Err(e) => {
            eprintln!("Error: {e:?}");
            1
        }
    });
}

/// Each check's name and, failed, why and how to fix it.
#[cfg(target_os = "linux")]
fn preflight() -> Vec<(&'static str, Result<(), String>)> {
    use scx_crfuzz::{gate, oracle};
    use std::ffi::{CStr, CString};
    let euid = unsafe { libc::geteuid() };
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    let release = unsafe { CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().into_owned();
    let mut v = release.split(|c: char| !c.is_ascii_digit()).map(|n| n.parse::<u32>().unwrap_or(0));
    let kernel = (v.next().unwrap_or(0), v.next().unwrap_or(0));
    // The filesystem mounted at `p` is `magic`.
    let mounted = |p: &str, magic: u32, what: &str| -> Result<(), String> {
        let c = CString::new(p).unwrap();
        let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
            return Err(format!("{p}: {}; mount {what} there", std::io::Error::last_os_error()));
        }
        // f_type's type varies by target; the magics fit in a u32.
        if sf.f_type as u32 != magic {
            return Err(format!("{p} is not {what}; mount it: mount -t {what} none {p}"));
        }
        Ok(())
    };
    vec![
        ("root", if euid == 0 { Ok(()) } else { Err(format!("euid {euid}; run as root (sudo)")) }),
        ("kernel >= 6.12", if kernel >= (6, 12) { Ok(()) } else { Err(format!("{release} predates sched_ext; boot 6.12 or later")) }),
        (
            "sched_ext",
            match gate::sched_ext_state() {
                Err(e) => Err(format!("{e:#}; needs a kernel built with CONFIG_SCHED_CLASS_EXT")),
                Ok(s) if s == "disabled" || gate::running().unwrap_or(false) => Ok(()),
                // /sys/fs/bpf is root's: the pins can't be seen.
                Ok(s) if euid != 0 => Err(format!("{s}; only root can tell if it is crfuzz's gate ({})", gate::PIN_DIR)),
                Ok(s) => Err(format!("{s} with {:?}; needs it disabled, or crfuzz's gate with its pins in {}: stop any other scheduler", gate::ops(), gate::PIN_DIR)),
            },
        ),
        ("cgroup v2", mounted("/sys/fs/cgroup", libc::CGROUP2_SUPER_MAGIC as u32, "cgroup2")),
        ("bpffs", mounted("/sys/fs/bpf", libc::BPF_FS_MAGIC as u32, "bpf")),
        ("/var/lib/crfuzz", oracle::root_only().map_err(|e| format!("{e:#}; chown root and chmod go-w it"))),
    ]
}

/// The exit status: 0, 3 for a confirmed finding, or 130 interrupted.
#[cfg(target_os = "linux")]
fn crfuzz() -> anyhow::Result<i32> {
    use anyhow::{bail, ensure, Context, Result};
    use scx_crfuzz::backend::{self, GateBackend, SelfCheckFailed};
    use scx_crfuzz::engine::{self, Deadline, Decision, Interrupted, Judge, Replay};
    use scx_crfuzz::gate;
    use scx_crfuzz::oracle::{self, Alice, Canary, Finding, Outcome};
    use scx_crfuzz::pos::{EventId, Pos};
    use scx_crfuzz::schedule::{self, Dedup, Divergence, Fixed, Schedule};
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::io::{IsTerminal, Write};
    use std::os::unix::{ffi::OsStrExt, fs::DirBuilderExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Replays a discovery gets to reproduce before it counts as unconfirmed.
    const CONFIRM_TRIES: u32 = 3;
    // ponytail: a fixed watch set (the path syscalls D3 decodes, minus execve,
    // which needs CMD as a path) and fixed timing; flags when a scenario needs them.
    const WATCHED: &[i64] = &[
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlinkat,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_chdir,
        // The final hold (§5): its keys are `all`, so no mutator fires there.
        libc::SYS_exit_group,
    ];

    /// A run's mutator failed: invalid, but one minimize step or confirm try only.
    #[derive(Debug)]
    struct MutatorFailed(String);
    impl std::fmt::Display for MutatorFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "invalid: mutator failed: {}", self.0)
        }
    }
    impl std::error::Error for MutatorFailed {}

    /// This thread in its own mount namespace, `/` rslave (host mounts still
    /// show, nothing leaks out), each of `dirs` covered by a bind mount of its
    /// copy under `work` (`cp -a` of DIR itself: its owner and mode too).
    /// What the thread forks inherits it. Then the cwd again: one inside a DIR
    /// still points at the original.
    fn isolate(dirs: &[PathBuf], work: &Path) -> Result<()> {
        let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).context("NUL in path");
        let ok = |r: i32, what: &dyn std::fmt::Display| -> Result<()> {
            ensure!(r == 0, "{what}: {}", std::io::Error::last_os_error());
            Ok(())
        };
        let cwd = std::env::current_dir()?;
        ok(unsafe { libc::unshare(libc::CLONE_NEWNS) }, &"unshare(CLONE_NEWNS)")?;
        ok(unsafe { libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_SLAVE, std::ptr::null()) }, &"make / rslave")?;
        // work/<pid>/<w> root-only: alice must not reach another worker's copies.
        // Ours go through the bind mount, whose root is the copy itself.
        let base = work.parent().and_then(Path::parent).context("work dir")?;
        std::fs::DirBuilder::new().recursive(true).mode(0o755).create(base).with_context(|| base.display().to_string())?;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(work).with_context(|| work.display().to_string())?;
        for (i, d) in dirs.iter().enumerate() {
            let copy = work.join(i.to_string());
            let st = Command::new("cp").arg("-a").arg("--").arg(d).arg(&copy).status().context("cp")?;
            ensure!(st.success(), "cp -a {} {}: {st}", d.display(), copy.display());
            let r = unsafe { libc::mount(c(&copy)?.as_ptr(), c(d)?.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
            ok(r, &format_args!("bind {} over {}", copy.display(), d.display()))?;
        }
        std::env::set_current_dir(&cwd).with_context(|| cwd.display().to_string())
    }
    /// The private copies, removed once every run is done.
    struct Work(PathBuf);
    impl Drop for Work {
        fn drop(&mut self) {
            match std::fs::remove_dir_all(&self.0) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => eprintln!("left {}: {e}", self.0.display()),
                _ => {}
            }
        }
    }
    /// A worker's stdout: at --jobs 1 straight through, else kept in `buf`.
    struct Out {
        live: bool,
        buf: Vec<u8>,
    }
    impl Write for Out {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.live { std::io::stdout().write(b) } else { self.buf.write(b) }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::io::stdout().flush()
        }
    }

    let usage = |why: String| anyhow::Error::new(Usage(why));
    type Args = std::iter::Skip<std::env::Args>;
    let val = |args: &mut Args, flag: &str| args.next().ok_or_else(|| usage(format!("{flag} needs a value")));
    let num = |args: &mut Args, flag: &str| -> Result<u64> { val(args, flag)?.parse().map_err(|_| usage(format!("{flag}: not a number"))) };
    let nonzero = |args: &mut Args, flag: &str| -> Result<u64> { Some(num(args, flag)?).filter(|&v| v > 0).ok_or_else(|| usage(format!("{flag}: must be at least 1"))) };
    let mut args = std::env::args().skip(1);
    let (mut mutator, mut layout, mut attacker, mut scope) = (None, None, None, Vec::<PathBuf>::new());
    let (mut verbose, mut timeout, mut limit, mut jobs, mut private) = (false, 30, None, 1, Vec::new());
    // campaign: DIR and the seeds; loaded: the schedule to replay.
    let (campaign, loaded, cmd) = match args.next().as_deref() {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return Ok(0);
        }
        Some("-V" | "--version") => {
            println!("scx_crfuzz {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Some(c @ ("gated" | "status" | "reset" | "check")) => {
            if let Some(a) = args.next() {
                return Err(usage(format!("unknown argument {a}")));
            }
            match c {
                "gated" => {
                    engine::stop_on_signals();
                    gate::serve(&engine::stopped, |seq| println!("scx_crfuzz gated: attached, enable_seq={seq}"))?;
                }
                "status" => gate::status()?,
                "check" => {
                    let checks = preflight();
                    for (name, r) in &checks {
                        println!("{name}: {}", r.as_ref().map_or_else(|e| format!("FAIL: {e}"), |()| "ok".into()));
                    }
                    return Ok(if checks.iter().all(|(_, r)| r.is_ok()) { 0 } else { 1 });
                }
                _ => gate::reset_all()?,
            }
            return Ok(0);
        }
        // Everything comes from the file.
        Some("replay") => {
            let mut file = None;
            for a in args {
                match a.as_str() {
                    "-v" => verbose = true,
                    _ if file.is_none() && !a.starts_with('-') => file = Some(a),
                    _ => return Err(usage(format!("unknown argument {a}"))),
                }
            }
            let f = file.ok_or_else(|| usage("replay needs a FILE".into()))?;
            let s = std::fs::read_to_string(&f).context(f.clone())?.parse::<Schedule>().context(f)?;
            (mutator, layout, timeout, private, attacker) = (s.mutator.clone(), s.layout.clone(), s.timeout, s.private.clone(), Some(Alice::parse(&s.attacker)?));
            let cmd = s.cmd.clone();
            (None, Some(s), cmd)
        }
        Some("run") => {
            let dir = args.next().filter(|d| !d.starts_with('-')).ok_or_else(|| usage("run needs a DIR".into()))?;
            let (mut first, mut seeds) = (0, None);
            let cmd: Vec<String> = loop {
                match args.next().as_deref() {
                    Some("--attacker") => attacker = Some(Alice::parse(&val(&mut args, "--attacker")?).map_err(|e| usage(format!("{e:#}")))?),
                    Some("--seeds") => seeds = Some(nonzero(&mut args, "--seeds")?),
                    Some("--time") => {
                        let d = duration(&val(&mut args, "--time")?).filter(|d| !d.is_zero());
                        limit = Some(d.ok_or_else(|| usage("--time: not a nonzero N, Ns, Nm or Nh".into()))?);
                    }
                    Some("--first-seed") => first = num(&mut args, "--first-seed")?,
                    Some("--jobs") => jobs = nonzero(&mut args, "--jobs")? as usize,
                    Some("--private") => private.push(std::fs::canonicalize(val(&mut args, "--private")?).context("--private")?),
                    // Absolute: the mutator is exec'd after a chdir into the task's cwd.
                    Some("--mutator") => mutator = Some(std::fs::canonicalize(val(&mut args, "--mutator")?).context("--mutator")?),
                    Some("--layout") => layout = Some(std::fs::canonicalize(val(&mut args, "--layout")?).context("--layout")?),
                    Some("--scope") => scope.push(std::fs::canonicalize(val(&mut args, "--scope")?).context("--scope")?),
                    Some("--timeout") => timeout = Some(num(&mut args, "--timeout")?).filter(|t| (1..=30).contains(t)).ok_or_else(|| usage("--timeout: 1 to 30 seconds".into()))?,
                    Some("-v") => verbose = true,
                    Some("--") => break args.collect(),
                    Some(a) => return Err(usage(format!("unknown argument {a}"))),
                    None => return Err(usage("run needs -- CMD".into())),
                }
            };
            if seeds.is_some_and(|n| first.checked_add(n).is_none()) {
                return Err(usage("--first-seed + --seeds overflows".into()));
            }
            if jobs > 1 && private.is_empty() {
                return Err(usage("--jobs N > 1 needs --private DIR: the workers share one filesystem, so their layouts, SUTs and mutators would meet in what the runs write".into()));
            }
            (Some((PathBuf::from(dir), first, seeds)), None, cmd)
        }
        Some(a) => return Err(usage(format!("unknown command {a}"))),
        None => return Err(usage("a command is required".into())),
    };
    // §1: an input, never inferred; refused before anything starts.
    let alice = attacker.ok_or_else(|| usage("--attacker is required".into()))?;
    let (prog, rest) = cmd.split_first().ok_or_else(|| usage("run needs a CMD after --".into()))?;
    // No resume: an old campaign's runs/ and findings/ would read as this one's.
    if let Some((d, ..)) = &campaign {
        ensure!(std::fs::read_dir(d).map_or(true, |mut e| e.next().is_none()), "run: {} is not empty", d.display());
    }
    // The canaries stay shared (unique names), the campaign's output too.
    let canaries = std::fs::canonicalize(oracle::ROOT).unwrap_or_else(|_| oracle::ROOT.into());
    let output = campaign.as_ref().map(|(d, ..)| std::fs::canonicalize(d).or_else(|_| std::path::absolute(d))).transpose()?;
    for d in &private {
        ensure!(d.is_dir(), "--private {}: not a directory", d.display());
        ensure!(!canaries.starts_with(d) && !d.starts_with(&canaries), "--private {}: overlaps {}, where the canaries must stay shared", d.display(), canaries.display());
        ensure!(!output.as_ref().is_some_and(|o| o.starts_with(d)), "--private {}: holds DIR, whose output would land in a private copy", d.display());
    }
    if let Ok(cpus) = std::thread::available_parallelism() {
        if jobs > cpus.get() {
            eprintln!("warning: --jobs {jobs} > {cpus} CPUs: runs compete for them, and more decisions turn partial");
        }
    }

    /// One judged run (§5, §6).
    struct Judged {
        /// None: the deadline, or a self-check failed on a changed canary.
        end: Option<ExitStatus>,
        /// Read and write halves together.
        found: Vec<Finding>,
        /// Ended by the deadline (§3.8: replay lets it end there too).
        deadline: bool,
        /// `found`, normalized: what replays compare (§3.8).
        norm: BTreeSet<Finding>,
        /// Removed on drop unless kept (§10.2).
        canary: Canary,
    }

    // --time counts from here; checked before each run, like a stop.
    let started = Instant::now();
    // A worker's fatal error stops the others the same way.
    let fatal = AtomicBool::new(false);
    let over = || limit.is_some_and(|l| started.elapsed() >= l) || fatal.load(Relaxed);
    // Canary numbers, one per run of this crfuzz: a kept canary is never reused.
    let runs = AtomicU32::new(0);
    // One run with its own canary; its decisions go to `log` whatever the
    // ending, and with -v to stdout. Its output and the layout's go to `out`
    // after a `== <name>` line; with no `out`, nowhere, or with -v to stderr.
    // Stdin is /dev/null. Interrupted if it ends once stopped (a terminal ^C
    // also reaches the SUT), so nothing records it, or starts past --time.
    let judged = |seed: u64, mutator: Option<&Path>, target: Option<&EventId>, replay: Option<&mut Replay>, out: Option<&Path>, name: &str, log: &mut Vec<Decision>| -> Result<Judged> {
        ensure!(!engine::stopped() && !over(), Interrupted);
        let r = (|| -> Result<Judged> {
            let file = out
                .map(|p| -> Result<std::fs::File> {
                    let mut f = std::fs::File::options().create(true).append(true).open(p).with_context(|| p.display().to_string())?;
                    writeln!(f, "== {name}")?;
                    Ok(f)
                })
                .transpose()?;
            let stdio = |c: &mut Command| -> Result<()> {
                let (o, e): (Stdio, Stdio) = match &file {
                    Some(f) => (f.try_clone()?.into(), f.try_clone()?.into()),
                    None if verbose => (std::io::stderr().into(), std::io::stderr().into()),
                    None => (Stdio::null(), Stdio::null()),
                };
                c.stdin(Stdio::null()).stdout(o).stderr(e);
                Ok(())
            };
            if let Some(l) = &layout {
                let mut c = Command::new(l);
                stdio(&mut c)?;
                let st = c.status().with_context(|| l.display().to_string())?;
                ensure!(st.success(), "invalid: layout {} failed: {st}", l.display());
            }
            let canary = Canary::create(runs.fetch_add(1, Relaxed))?;
            backend::read_before(&canary, &alice)?;
            let mut sut = Command::new(prog);
            sut.args(rest);
            stdio(&mut sut)?;
            let mut be = GateBackend::spawn(sut, WATCHED)?;
            let mut j = Judge { canary: &canary, alice: alice.clone(), reached: None, task: None };
            let until = Instant::now().checked_add(Duration::from_secs(timeout)).context("--timeout too large")?;
            let r = engine::run(&mut be, &mut Pos::new(seed), mutator, target, replay, Some(&mut j), until, log);
            if verbose {
                // One block per run, whatever other workers print.
                let mut so = std::io::stdout().lock();
                log.iter().try_for_each(|d| writeln!(so, "{d:?}"))?;
            }
            let end = if r.is_ok() { Some(be.child().wait()?) } else { None };
            // Clears gates and cgroup, ending what is left of the SUT, before the
            // write half: a gated task may serve a mount inside the canary.
            drop(be);
            let deadline = matches!(&r, Err(e) if e.is::<Deadline>());
            // Ended without the final hold (no read half), or judged on the write half alone.
            match r {
                Ok(()) => {}
                Err(e) if e.is::<Deadline>() => {}
                // read before passed, so alice's credentials were right: a gate
                // that stops failing her later was opened by the SUT, and the
                // write half shows it (a chmod'd gate). Judged, not invalid.
                Err(e) if e.is::<SelfCheckFailed>() && !canary.changed().is_empty() => {}
                Err(e) => return Err(e), // invalid: self-check, probe, crfuzz itself
            }
            let mut found = j.reached.unwrap_or_default();
            found.extend(canary.changed());
            // A mutator that failed (error, timeout, nonzero exit) never attacked,
            // so an unflagged run would pass as Clean: invalid, unless it flagged.
            let failed = log.iter().find_map(|d| match &d.mutation {
                Some(Err(e)) => Some(e.clone()),
                Some(Ok(st)) if !st.success() => Some(st.to_string()),
                _ => None,
            });
            if let (true, Some(e)) = (found.is_empty(), failed) {
                return Err(anyhow::Error::new(MutatorFailed(e)));
            }
            let task = j.task.as_ref().map(|(tid, tgid, name)| (*tid, *tgid, name.as_str()));
            let norm = found.iter().map(|f| schedule::normalize(f, &canary.dir, task)).collect();
            Ok(Judged { end, found, deadline, norm, canary })
        })();
        if engine::stopped() {
            return Err(Interrupted.into());
        }
        r
    };

    // A seed's baseline, which must leak nothing: its exit (for the oracle),
    // its windows' targets and its time. The targets are the holds a mutator
    // could fire at, named stably (not `?tid`), with --scope only those under
    // a scope directory, one per (syscall, path, occurrence): the engine
    // matches those in any thread.
    let in_scope = |p: &Path| scope.is_empty() || scope.iter().any(|d| p.starts_with(d));
    let baseline = |seed: u64, out: Option<&Path>, log: &mut Vec<Decision>| -> Result<(Option<ExitStatus>, Vec<EventId>, f64)> {
        log.clear();
        let t = Instant::now();
        let mut b = judged(seed, None, None, None, out, "baseline", log)?;
        if !b.found.is_empty() {
            b.canary.keep(); // the evidence
            bail!("invalid: the scenario leaks with no mutation: {:?}", b.found);
        }
        let mut seen = HashSet::new();
        let targets = log
            .iter()
            .filter(|d| d.id.path.as_deref().is_some_and(in_scope) && !d.keys.all && !d.id.thread.starts_with('?'))
            .filter(|d| seen.insert((d.id.nr, d.id.path.clone(), d.id.n)))
            .map(|d| d.id.clone())
            .collect();
        Ok((b.end, targets, t.elapsed().as_secs_f64()))
    };
    // Window k (from 1) mutates target k alone; with no mutator or no target
    // the seed is one unmutated run, window 0.
    let windows = |targets: &[EventId]| -> Vec<(usize, Option<EventId>)> {
        if mutator.is_none() || targets.is_empty() {
            vec![(0, None)]
        } else {
            (1..).zip(targets.iter().cloned().map(Some)).collect()
        }
    };
    const VERDICTS: [&str; 4] = ["safe", "unsafe", "incomplete", "no windows"];
    // bad: a window's Violation; gap: a window invalid or unmutated.
    let verdict = |ws: &[(usize, Option<EventId>)], bad: bool, gap: bool| if bad { 1 } else if ws[0].0 == 0 { 3 } else if gap { 2 } else { 0 };
    // Telemetry from a baseline: the size of one run and how much there is
    // for the mutator to hit. It sizes the campaign's estimate.
    let telemetry = |log: &[Decision], targets: usize, secs: f64| {
        let threads: BTreeSet<&str> = log.iter().map(|d| d.id.thread.as_str()).collect();
        format!(
            "telemetry: {} decisions ({} partial), {} threads, {targets} mutation targets, {secs:.1}s",
            log.len(),
            log.iter().filter(|d| d.partial).count(),
            threads.len(),
        )
    };

    // The run in `log` as a schedule (§3.8); `mutated`: it had a target.
    let attacker = format!("{}:{}", alice.uid, alice.gid);
    let schedule = |seed: u64, mutated: bool, class: &str, deadline: bool, findings: BTreeSet<Finding>, log: &[Decision]| Schedule {
        seed,
        attacker: attacker.clone(),
        mutator: mutator.clone().filter(|_| mutated),
        layout: layout.clone(),
        timeout,
        private: private.clone(),
        cmd: cmd.clone(),
        class: class.into(),
        deadline,
        findings,
        steps: engine::project(log),
    };
    // Discovery against the seed's baseline `end`: its class and schedule; a
    // Violation's canary is kept (the evidence).
    let discover = |seed: u64, target: Option<&EventId>, end: Option<ExitStatus>, out: &Path, log: &mut Vec<Decision>| -> Result<(Outcome, Judged, Schedule)> {
        log.clear();
        let mut run = judged(seed, target.and(mutator.as_deref()), target, None, Some(out), "discovery", log)?;
        let class = oracle::outcome(std::mem::take(&mut run.found), run.end, end);
        if matches!(class, Outcome::Violation(_)) {
            run.canary.keep();
        }
        let s = schedule(seed, target.is_some(), class.name(), run.deadline, std::mem::take(&mut run.norm), log);
        Ok((class, run, s))
    };

    // Confirm, then on a Violation minimize, each line to `w` after `pre`, the
    // runs' output to `out`. None: not
    // confirmed; Some(Some(k)): guilty step k; Some(None): no single guilty
    // hold, or a confirmed non-Violation.
    let confirm = |sched: &Schedule, end: Option<ExitStatus>, out: Option<&Path>, log: &mut Vec<Decision>, pre: &str, w: &mut dyn Write| -> Result<Option<Option<usize>>> {
        // Confirm: every recorded mutation, any divergence fails it.
        let fixed = || Fixed { steps: &sched.steps, next: 0, deadline: sched.deadline };
        // Code between holds may not be deterministic (M:N runtimes): one
        // replay that misses is not proof of a spurious finding.
        // ponytail: first match wins; report a rate over all tries if one is needed.
        let mut confirmed = None;
        for t in 1..=CONFIRM_TRIES {
            log.clear();
            let mut r = Replay { fixed: fixed(), only: None, diverged: None };
            let mut run = match judged(sched.seed, sched.mutator.as_deref(), None, Some(&mut r), out, &format!("confirm {t}/{CONFIRM_TRIES}"), log) {
                Err(e) if e.is::<Divergence>() || e.is::<MutatorFailed>() => {
                    writeln!(w, "{pre}not confirmed ({t}/{CONFIRM_TRIES}): {e:#}")?;
                    continue;
                }
                r => r?,
            };
            let class = oracle::outcome(std::mem::take(&mut run.found), run.end, end);
            if class.name() != sched.class || run.norm != sched.findings {
                writeln!(w, "{pre}not confirmed ({t}/{CONFIRM_TRIES}): {class:?}, normalized {:?}", run.norm)?;
                continue;
            }
            confirmed = Some((class, run));
            break;
        }
        let Some((class, mut run)) = confirmed else { return Ok(None) };
        writeln!(w, "{pre}confirmed: {}", sched.class)?;
        if !matches!(class, Outcome::Violation(_)) {
            return Ok(Some(None));
        }
        run.canary.keep(); // the evidence
        drop(run);

        // Minimize: the first hold whose mutation alone flags a finding of the
        // schedule's. ponytail: one bug, single holds only; a pair search when
        // findings need two mutations.
        for k in (0..sched.steps.len()).filter(|&k| sched.steps[k].mutate) {
            log.clear();
            let mut r = Replay { fixed: fixed(), only: Some(k), diverged: None };
            let mut run = match judged(sched.seed, sched.mutator.as_deref(), None, Some(&mut r), out, &format!("minimize step {k}"), log) {
                Err(e) if e.is::<Divergence>() || e.is::<MutatorFailed>() => {
                    writeln!(w, "{pre}minimize step {k}: not guilty, {e:#}")?;
                    continue;
                }
                res => res?,
            };
            let class = oracle::outcome(std::mem::take(&mut run.found), run.end, end);
            let tail = r.diverged.map(|d| format!(" (then POS: {d})")).unwrap_or_default();
            writeln!(w, "{pre}minimize step {k}: {class:?}{tail}")?;
            if matches!(class, Outcome::Violation(_)) && !run.norm.is_disjoint(&sched.findings) {
                writeln!(w, "{pre}guilty: step {k} {:?}", sched.steps[k].id)?;
                return Ok(Some(Some(k)));
            }
        }
        writeln!(w, "{pre}guilty: needs more than one hold")?;
        Ok(Some(None))
    };

    let failed: Vec<String> = preflight().into_iter().filter_map(|(name, r)| Some(format!("{name}: FAIL: {}", r.err()?))).collect();
    ensure!(failed.is_empty(), "preflight:\n{}", failed.join("\n"));
    engine::stop_on_signals();
    // Ours for this process's life unless crfuzz's already runs.
    let _sched = gate::Scheduler::start()?;
    backend::sweep();
    // Worker w's private copies: work/<w>/<i>.
    let work = Path::new(oracle::ROOT).join(format!("work/{}", std::process::id()));
    // A crfuzz killed with our pid left these (sweep keeps a live pid's): never ours yet.
    let _ = std::fs::remove_dir_all(&work);
    let _work = (!private.is_empty()).then(|| Work(work.clone()));
    println!("{alice}");
    let Some((dir, first, n)) = campaign else {
        let s = loaded.expect("replay");
        if !private.is_empty() {
            isolate(&private, &work.join("0"))?;
        }
        let mut log = Vec::new();
        let hint = |_: &anyhow::Error| {
            if !verbose && !engine::stopped() {
                eprintln!("(rerun with -v for the decision log)");
            }
        };
        let (end, targets, secs) = baseline(s.seed, None, &mut log).inspect_err(hint)?;
        println!("{}", telemetry(&log, targets.len(), secs));
        println!("discovery: {}", s.class);
        // Not reproduced in CONFIRM_TRIES: an error, never a clean exit.
        confirm(&s, end, None, &mut log, "", &mut std::io::stdout()).and_then(|c| c.with_context(|| format!("not reproduced in {CONFIRM_TRIES} tries: {}", s.class))).inspect_err(hint)?;
        return Ok(if s.class == "Violation" { 3 } else { 0 });
    };

    // §3.10: the sweep. Each row is written as its run ends: an interrupted
    // campaign keeps them.
    std::fs::create_dir_all(dir.join("runs")).with_context(|| dir.display().to_string())?;
    let mut tsv = std::fs::File::create(dir.join("runs.tsv"))?;
    writeln!(tsv, "seed\twindow\tclass\tstatus\tfinding\tdecisions\tpartial\tsecs\tnote")?;
    /// The campaign's totals, behind one lock for every worker.
    struct Tally {
        tsv: std::fs::File,
        total: u64,
        invalid: u64,
        decisions: usize,
        partial: usize,
        time: Duration,
        orders: HashSet<Vec<EventId>>,
        unmutated: u64,
        classes: BTreeMap<&'static str, u64>,
        verdicts: [u64; 4],
        /// Seeds ended, for the progress line.
        done: u64,
        /// A baseline has ended: the plan line is out.
        planned: bool,
    }
    let tally = Mutex::new(Tally {
        tsv,
        total: 0,
        invalid: 0,
        decisions: 0,
        partial: 0,
        time: Duration::ZERO,
        orders: HashSet::new(),
        unmutated: 0,
        classes: BTreeMap::new(),
        verdicts: [0; 4],
        done: 0,
        planned: false,
    });
    // Dedup, confirm and push under one lock: two workers on one new bug give
    // a finding and a repeat, never two findings.
    let found: Mutex<Vec<(Dedup, Vec<String>)>> = Mutex::new(Vec::new());
    let hold = |t: &str, nr: i64, p: &Option<PathBuf>| format!("({t} {nr} {})", p.as_deref().map_or("-".into(), |p| p.display().to_string()));
    let hms = |s: f64| {
        let s = s.round() as u64;
        if s >= 3600 { format!("{}h{:02}m", s / 3600, s / 60 % 60) } else if s >= 60 { format!("{}m{:02}s", s / 60, s % 60) } else { format!("{s}s") }
    };
    // On a terminal and without -v, a progress line over seeds on stderr below
    // the per-run lines; cleared before anything prints to stdout.
    let tty = !verbose && std::io::stderr().is_terminal();
    let clear = || if tty { eprint!("\r\x1b[K") };
    let bar = |t: &Tally| {
        if !tty {
            return;
        }
        let (done, elapsed) = (t.done, started.elapsed());
        let head = match n {
            Some(n) => {
                let w = 24;
                let fill = (done * w / n) as usize;
                // From the seeds so far (confirms included); the plan line has the first guess.
                let eta = if done == 0 { "?".into() } else { hms(elapsed.as_secs_f64() / done as f64 * (n - done) as f64) };
                format!("[{}{}] {done}/{n} seeds  ETA {eta}", "#".repeat(fill), ".".repeat(w as usize - fill))
            }
            None => {
                let left = limit.map(|l| format!("  {} left", hms(l.saturating_sub(elapsed).as_secs_f64()))).unwrap_or_default();
                format!("{done} seeds  {} elapsed{left}", hms(elapsed.as_secs_f64()))
            }
        };
        let counts: Vec<String> = t.classes.iter().map(|(c, k)| format!("{c} {k}")).collect();
        eprint!("\r{head}  {}\x1b[K", counts.join("  "));
    };
    // A line of a seed's, and then (`show`) the progress line: at --jobs 1 as
    // they come; else the seed's lines print as one block when it ends (`end`).
    let say = |w: &mut Out, line: String| -> Result<()> {
        if w.live {
            clear();
        }
        Ok(writeln!(w, "{line}")?)
    };
    let show = |w: &mut Out, t: &Tally, end: bool| -> Result<()> {
        if !w.live && end {
            clear();
            std::io::stdout().write_all(&std::mem::take(&mut w.buf))?;
        }
        if w.live || end {
            bar(t);
        }
        Ok(())
    };
    // The `[i/N]` of each line; `[i]` open-ended.
    let of = n.map_or(String::new(), |n| format!("/{n}"));
    // No worker (or private copy) without a seed.
    let jobs = n.map_or(jobs, |n| n.min(jobs as u64) as usize);
    let next = AtomicU64::new(0);
    // Worker w: seeds from `next` until they run out or a run is refused.
    let worker = |wk: usize| -> Result<()> {
        if !private.is_empty() {
            isolate(&private, &work.join(wk.to_string()))?;
        }
        let mut log = Vec::new();
        let mut w = Out { live: jobs == 1, buf: Vec::new() };
        'seeds: loop {
            let idx = next.fetch_add(1, Relaxed);
            if n.is_some_and(|n| idx >= n) {
                break;
            }
            let seed = first + idx;
            let t = Instant::now();
            let rd = dir.join(format!("runs/{seed}"));
            std::fs::create_dir_all(&rd)?;
            let b = baseline(seed, Some(&rd.join("baseline.log")), &mut log);
            let (end, targets, secs) = match b {
                Ok(b) => b,
                Err(e) if e.is::<Interrupted>() => break,
                Err(e) => {
                    let mut g = tally.lock().unwrap();
                    g.planned = true;
                    g.invalid += 1;
                    g.verdicts[2] += 1;
                    g.done += 1;
                    *g.classes.entry("invalid").or_default() += 1;
                    let note = format!("baseline: {e:#}").replace(['\t', '\n'], " ");
                    let part = log.iter().filter(|d| d.partial).count();
                    writeln!(g.tsv, "{seed}\t-\tinvalid\t-\t-\t{}\t{part}\t{:.3}\t{note}", log.len(), t.elapsed().as_secs_f64())?;
                    say(&mut w, format!("[{}{of}] seed {seed}: incomplete, {note}", idx + 1))?;
                    show(&mut w, &g, true)?;
                    continue;
                }
            };
            let ws = windows(&targets);
            let mut g = tally.lock().unwrap();
            // The plan, sized by the first baseline to end: a discovery costs
            // about one baseline, plus a confirm and minimization per new
            // Violation, the seeds `jobs` at a time.
            if !std::mem::replace(&mut g.planned, true) {
                let per = ws.len() as u64 + 1;
                clear();
                match n {
                    Some(n) => println!("plan: {n} seeds, {} windows in seed {seed}, ~{} runs, est. {} (+ confirms)", ws.len(), n.saturating_mul(per), hms(n as f64 * per as f64 * secs / jobs as f64)),
                    None => println!("plan: open-ended, {} windows in seed {seed}, ~{per} runs a seed, est. {} a seed (+ confirms)", ws.len(), hms(per as f64 * secs)),
                }
            }
            say(&mut w, format!("[{}{of}] seed {seed}: {}", idx + 1, telemetry(&log, targets.len(), secs)))?;
            show(&mut w, &g, false)?;
            drop(g);
            let (mut bad, mut gap) = (false, false);
            for (k, target) in &ws {
                let t = Instant::now();
                let out = rd.join(format!("{k}.log"));
                let r = discover(seed, target.as_ref(), end, &out, &mut log);
                let secs = t.elapsed();
                // Its target never came up: the run says nothing about the mutator.
                let unmut = r.is_ok() && target.is_some() && !log.iter().any(|d| d.mutation.is_some());
                let (len, part) = (log.len(), log.iter().filter(|d| d.partial).count());
                let file = rd.join(format!("{k}.sched"));
                let mut order = None;
                // status: new, repeat, unconfirmed or invalid on a Violation, else "-".
                // Interrupted, here or confirming: the window leaves no trace.
                let (class, status, finding, note) = match r {
                    Err(e) if e.is::<Interrupted>() => break 'seeds,
                    Err(e) => {
                        std::fs::write(&file, schedule(seed, target.is_some(), "invalid", false, BTreeSet::new(), &log).to_string())?;
                        ("invalid", "-", None, format!("{e:#}"))
                    }
                    Ok((class, run, s)) => {
                        // A Violation's canary, kept by discover: removed if the stop discards the window.
                        let kept = run.canary.dir.clone();
                        drop(run);
                        // Before confirm reuses `log`.
                        order = Some(schedule::canonical(&log.iter().map(|d| (&d.id, &d.keys)).collect::<Vec<_>>()));
                        let row = if !matches!(class, Outcome::Violation(_)) {
                            (class.name(), "-", None, String::new())
                        } else {
                            let mut found = found.lock().unwrap();
                            let row = if let Some(i) = found.iter().position(|(d, _)| d.repeated_by(&s.findings, &s.steps)) {
                                found[i].1.push(format!("{seed}:{k}"));
                                ("Violation", "repeat", Some(i + 1), String::new())
                            } else {
                                say(&mut w, format!("[{}{of}] seed {seed} window {k}: Violation, confirming", idx + 1))?;
                                match confirm(&s, end, Some(&out), &mut log, "  ", &mut w) {
                                    Err(e) if e.is::<Interrupted>() => {
                                        let _ = std::fs::remove_dir_all(&kept);
                                        break 'seeds;
                                    }
                                    Err(e) => ("Violation", "invalid", None, format!("{e:#}")),
                                    Ok(None) => ("Violation", "unconfirmed", None, String::new()),
                                    Ok(Some(g)) => {
                                        let id = g.map(|g| &s.steps[g].id);
                                        let note = match (g, id) {
                                            (Some(g), Some(id)) => format!("guilty step {g} {}", hold(&id.thread, id.nr, &id.path)),
                                            _ => "needs more than one hold".into(),
                                        };
                                        let guilty = id.map(|id| (id.thread.clone(), id.nr, id.path.clone()));
                                        found.push((Dedup { guilty, findings: s.findings.clone() }, vec![format!("{seed}:{k}")]));
                                        let f = dir.join(format!("findings/{}", found.len()));
                                        std::fs::create_dir_all(&f)?;
                                        std::fs::write(f.join("schedule"), s.to_string())?;
                                        ("Violation", "new", Some(found.len()), note)
                                    }
                                }
                            };
                            if let Some(i) = row.2 {
                                let list: String = found[i - 1].1.iter().map(|s| format!("{s}\n")).collect();
                                std::fs::write(dir.join(format!("findings/{i}/seeds")), list)?;
                            }
                            row
                        };
                        std::fs::write(&file, s.to_string())?;
                        row
                    }
                };
                let mut g = tally.lock().unwrap();
                g.orders.extend(order);
                g.unmutated += unmut as u64;
                gap |= unmut || class == "invalid";
                g.invalid += (class == "invalid" || status == "invalid") as u64;
                (g.total, g.time) = (g.total + 1, g.time + secs);
                (g.decisions, g.partial) = (g.decisions + len, g.partial + part);
                bad |= class == "Violation";
                *g.classes.entry(class).or_default() += 1;
                let note = match (unmut, note.is_empty()) {
                    (false, _) => note,
                    (true, true) => "unmutated".into(),
                    (true, false) => format!("unmutated; {note}"),
                };
                let note = note.replace(['\t', '\n'], " ");
                let f = finding.map_or("-".into(), |i| i.to_string());
                writeln!(g.tsv, "{seed}\t{k}\t{class}\t{status}\t{f}\t{len}\t{part}\t{:.3}\t{note}", secs.as_secs_f64())?;
                let what = match status {
                    "new" => format!("Violation → confirmed, {note} → finding #{f} (new)"),
                    "repeat" => format!("Violation → repeat of finding #{f}"),
                    "unconfirmed" => "Violation → not confirmed".into(),
                    "invalid" => format!("Violation → invalid: {note}"),
                    _ if class == "invalid" => format!("invalid: {note}"),
                    _ => class.into(),
                };
                say(&mut w, format!("[{}{of}] seed {seed} window {k}/{}: {what}{}  {:.1}s", idx + 1, ws.len(), if unmut { " (unmutated)" } else { "" }, secs.as_secs_f64()))?;
                show(&mut w, &g, false)?;
            }
            let v = verdict(&ws, bad, gap);
            let mut g = tally.lock().unwrap();
            g.verdicts[v] += 1;
            g.done += 1;
            say(&mut w, format!("[{}{of}] seed {seed}: {}", idx + 1, VERDICTS[v]))?;
            show(&mut w, &g, true)?;
        }
        // An interrupted seed's lines so far.
        if !w.buf.is_empty() {
            show(&mut w, &tally.lock().unwrap(), true)?;
        }
        Ok(())
    };
    let (worker, fatal) = (&worker, &fatal);
    std::thread::scope(|s| {
        let ws: Vec<_> = (0..jobs)
            .map(|wk| {
                s.spawn(move || {
                    // An error or a panic stops the other workers alike.
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(wk)));
                    if !matches!(r, Ok(Ok(()))) {
                        fatal.store(true, Relaxed);
                    }
                    r.unwrap_or_else(|p| std::panic::resume_unwind(p))
                })
            })
            .collect();
        ws.into_iter().map(|h| h.join().expect("worker panicked")).collect::<Result<Vec<()>>>()
    })?;
    clear();
    let Tally { total, invalid, decisions, partial, time, orders, unmutated, verdicts, .. } = tally.into_inner().unwrap();
    let found = found.into_inner().unwrap();

    let stopped = engine::stopped();
    let done = verdicts.iter().sum::<u64>();
    if stopped {
        println!("interrupted: {done} seeds complete");
    } else if n.is_none_or(|n| done < n) {
        // Only a stop or --time ends the loop early.
        println!("time limit: {done} seeds complete");
    }
    println!("campaign: {} seeds, {total} runs, {invalid} invalid, discovery {:.1}s", n.unwrap_or(done), time.as_secs_f64());
    let v: Vec<String> = VERDICTS.iter().zip(verdicts).map(|(name, c)| format!("{c} {name}")).collect();
    println!("seeds: {}", v.join(", "));
    println!("distinct partial orders: {}", orders.len());
    println!("partial decisions: {partial}/{decisions} ({:.0}%)", 100.0 * partial as f64 / decisions.max(1) as f64);
    if unmutated > 0 {
        println!("unmutated: {unmutated}/{total} runs never reached their target");
    }
    println!("findings: {}", found.len());
    for (i, (d, runs)) in found.iter().enumerate() {
        let guilty = d.guilty.as_ref().map_or("needs more than one hold".into(), |(t, nr, p)| hold(t, *nr, p));
        println!("finding #{}: {} runs, guilty {guilty}, {:?}, {}", i + 1, runs.len(), d.findings, dir.join(format!("findings/{}", i + 1)).display());
    }
    Ok(if stopped { 130 } else if found.is_empty() { 0 } else { 3 })
}
