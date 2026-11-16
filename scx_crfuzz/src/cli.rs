//! The command line: the usage, the arguments parsed into what each command
//! runs on, and the preflight.

use crate::campaign::{self, Campaign};
use crate::run;
use crate::targets::containerd;
use anyhow::{ensure, Context, Result};
use scx_crfuzz::oracle::{self, Alice};
use scx_crfuzz::schedule::Config;
use scx_crfuzz::{engine, gate};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "usage: scx_crfuzz run DIR --attacker UID:GID [--seeds N] [--time DURATION] [--first-seed S] [--resume]
                      [--jobs N] [--private DIR]... [--mutator PROG] [--layout PROG] [--scope DIR]... [--timeout SECS] [-v] -- CMD [ARGS...]
       scx_crfuzz replay FILE [-v]
       scx_crfuzz containerd [--dir D] [--image BUSYBOX] [--attacker UID:GID] [--seeds N] [--time DURATION] [--jobs N] [--resume] [-v]
       scx_crfuzz gated     hold the gate scheduler until SIGINT/SIGTERM
       scx_crfuzz status    sched_ext state and pins
       scx_crfuzz reset     delete every gate entry of every run
       scx_crfuzz check     preflight: root, kernel, sched_ext, cgroup v2, bpffs, /var/lib/crfuzz
       scx_crfuzz --help | --version";

/// `--timeout`'s default, and the containerd target's.
pub const TIMEOUT: u64 = 30;

/// A bad or missing argument: exit 2, after the usage.
#[derive(Debug)]
struct Usage(String);

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n{USAGE}", self.0)
    }
}

impl std::error::Error for Usage {}

fn usage(why: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Usage(why.into()))
}

enum Cmd {
    Help,
    Version,
    Gated,
    Status,
    Reset,
    Check,
    Replay { file: String, verbose: bool },
    Run(Campaign),
    Containerd(containerd::Opts),
}

/// `90`, `90s`, `30m`, `2h`: digits, then at most one unit.
fn duration(s: &str) -> Option<Duration> {
    let (n, mul) = [("s", 1), ("m", 60), ("h", 3600)].into_iter().find_map(|(u, m)| Some((s.strip_suffix(u)?, m))).unwrap_or((s, 1));
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse::<u64>().ok()?.checked_mul(mul).map(Duration::from_secs)
}

type Args = std::vec::IntoIter<String>;

fn val(args: &mut Args, flag: &str) -> Result<String> {
    args.next().ok_or_else(|| usage(format!("{flag} needs a value")))
}

fn num(args: &mut Args, flag: &str) -> Result<u64> {
    val(args, flag)?.parse().map_err(|_| usage(format!("{flag}: not a number")))
}

fn nonzero(args: &mut Args, flag: &str) -> Result<u64> {
    Some(num(args, flag)?).filter(|&v| v > 0).ok_or_else(|| usage(format!("{flag}: must be at least 1")))
}

fn time(args: &mut Args) -> Result<Duration> {
    duration(&val(args, "--time")?).filter(|d| !d.is_zero()).ok_or_else(|| usage("--time: not a nonzero N, Ns, Nm or Nh"))
}

/// `UID:GID`, as given: an input, never inferred (an alice guessed as root
/// would judge every canary reachable).
fn attacker(args: &mut Args) -> Result<String> {
    let a = val(args, "--attacker")?;
    Alice::parse(&a).map_err(|e| usage(format!("{e:#}")))?;
    Ok(a)
}

/// An existing path, made absolute: the mutator is exec'd after a chdir into
/// the task's cwd, and a schedule is replayed from anywhere.
fn path(args: &mut Args, flag: &'static str) -> Result<PathBuf> {
    std::fs::canonicalize(val(args, flag)?).context(flag)
}

/// The `CRFUZZ_*` environment: the layout's, SUT's and mutator's inputs.
pub fn env() -> BTreeMap<OsString, OsString> {
    std::env::vars_os().filter(|(k, _)| k.as_bytes().starts_with(b"CRFUZZ_")).collect()
}

fn parse(all: Vec<String>) -> Result<Cmd> {
    let mut args = all.into_iter();
    let cmd = args.next().ok_or_else(|| usage("a command is required"))?;
    Ok(match cmd.as_str() {
        "-h" | "--help" => Cmd::Help,
        "-V" | "--version" => Cmd::Version,
        "gated" | "status" | "reset" | "check" => {
            if let Some(a) = args.next() {
                return Err(usage(format!("unknown argument {a}")));
            }
            match cmd.as_str() {
                "gated" => Cmd::Gated,
                "status" => Cmd::Status,
                "reset" => Cmd::Reset,
                _ => Cmd::Check,
            }
        }
        "replay" => {
            let (mut file, mut verbose) = (None, false);
            for a in args {
                match a.as_str() {
                    "-v" => verbose = true,
                    _ if file.is_none() && !a.starts_with('-') => file = Some(a),
                    _ => return Err(usage(format!("unknown argument {a}"))),
                }
            }
            Cmd::Replay { file: file.ok_or_else(|| usage("replay needs a FILE"))?, verbose }
        }
        "run" => {
            let dir = args.next().filter(|d| !d.starts_with('-')).ok_or_else(|| usage("run needs a DIR"))?;
            let mut c = Campaign { dir: dir.into(), cfg: Config { timeout: TIMEOUT, ..Config::default() }, first: 0, seeds: None, time: None, jobs: 1, resume: false, verbose: false };
            loop {
                match args.next().as_deref() {
                    Some("--attacker") => c.cfg.attacker = attacker(&mut args)?,
                    Some("--seeds") => c.seeds = Some(nonzero(&mut args, "--seeds")?),
                    Some("--time") => c.time = Some(time(&mut args)?),
                    Some("--first-seed") => c.first = num(&mut args, "--first-seed")?,
                    Some("--resume") => c.resume = true,
                    Some("--jobs") => c.jobs = nonzero(&mut args, "--jobs")? as usize,
                    Some("--private") => c.cfg.private.push(path(&mut args, "--private")?),
                    Some("--mutator") => c.cfg.mutator = Some(path(&mut args, "--mutator")?),
                    Some("--layout") => c.cfg.layout = Some(path(&mut args, "--layout")?),
                    Some("--scope") => c.cfg.scope.push(path(&mut args, "--scope")?),
                    Some("--timeout") => c.cfg.timeout = Some(num(&mut args, "--timeout")?).filter(|t| (1..=30).contains(t)).ok_or_else(|| usage("--timeout: 1 to 30 seconds"))?,
                    Some("-v") => c.verbose = true,
                    Some("--") => break,
                    Some(a) => return Err(usage(format!("unknown argument {a}"))),
                    None => return Err(usage("run needs -- CMD")),
                }
            }
            c.cfg.cmd = args.collect();
            if c.cfg.attacker.is_empty() {
                return Err(usage("--attacker is required"));
            }
            if c.cfg.cmd.is_empty() {
                return Err(usage("run needs a CMD after --"));
            }
            if c.seeds.is_some_and(|n| c.first.checked_add(n).is_none()) {
                return Err(usage("--first-seed + --seeds overflows"));
            }
            if c.jobs > 1 && c.cfg.private.is_empty() {
                return Err(usage("--jobs N > 1 needs --private DIR: the workers share one filesystem, so their layouts, SUTs and mutators would meet in what the runs write"));
            }
            c.cfg.env = env();
            Cmd::Run(c)
        }
        "containerd" => {
            let mut o = containerd::Opts { dir: "/tmp/crfuzz-containerd".into(), image: "/usr/bin/busybox".into(), attacker: "65534:65534".into(), seeds: None, time: None, jobs: 1, resume: false, verbose: false };
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--dir" => o.dir = val(&mut args, "--dir")?,
                    "--image" => o.image = val(&mut args, "--image")?,
                    "--attacker" => o.attacker = attacker(&mut args)?,
                    "--seeds" => o.seeds = Some(nonzero(&mut args, "--seeds")?),
                    "--jobs" => o.jobs = nonzero(&mut args, "--jobs")? as usize,
                    "--time" => o.time = Some(time(&mut args)?),
                    "--resume" => o.resume = true,
                    "-v" => o.verbose = true,
                    _ => return Err(usage(format!("unknown argument {a}"))),
                }
            }
            Cmd::Containerd(o)
        }
        a => return Err(usage(format!("unknown command {a}"))),
    })
}

/// A preflight check's name and, failed, why and how to fix it.
pub type Check = (&'static str, Result<(), String>);

pub fn preflight() -> Vec<Check> {
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

/// The preflight and a target's own checks: `run`, `replay` and `containerd`
/// stop on their failures.
pub fn preflight_ok(more: Vec<Check>) -> Result<()> {
    let failed: Vec<String> = preflight().into_iter().chain(more).filter_map(|(name, r)| Some(format!("{name}: FAIL: {}", r.err()?))).collect();
    ensure!(failed.is_empty(), "preflight:\n{}", failed.join("\n"));
    Ok(())
}

fn command(all: Vec<String>) -> Result<i32> {
    match parse(all)? {
        Cmd::Help => println!("{USAGE}"),
        Cmd::Version => println!("scx_crfuzz {}", env!("CARGO_PKG_VERSION")),
        Cmd::Gated => {
            engine::stop_on_signals();
            gate::serve(&engine::stopped, |seq| println!("scx_crfuzz gated: attached, enable_seq={seq}"))?;
        }
        Cmd::Status => gate::status()?,
        Cmd::Reset => gate::reset_all()?,
        Cmd::Check => {
            let checks = preflight();
            for (name, r) in &checks {
                println!("{name}: {}", r.as_ref().map_or_else(|e| format!("FAIL: {e}"), |()| "ok".into()));
            }
            return Ok(if checks.iter().all(|(_, r)| r.is_ok()) { 0 } else { 1 });
        }
        Cmd::Replay { file, verbose } => return run::replay(&file, verbose),
        Cmd::Run(c) => return campaign::run(c),
        Cmd::Containerd(o) => return containerd::run(o),
    }
    Ok(0)
}

/// `all`: the arguments after the program name. The exit status: 0, 3 for a
/// confirmed finding, 2 a usage error, 1 any other error, 130 interrupted.
pub fn main(all: Vec<String>) -> i32 {
    match command(all) {
        Ok(code) => code,
        Err(e) if e.is::<Usage>() => {
            eprintln!("{e}");
            2
        }
        Err(e) => {
            eprintln!("Error: {e:?}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        let secs = |s| duration(s).map(|d| d.as_secs());
        assert_eq!([secs("90"), secs("90s"), secs("30m"), secs("2h"), secs("0")], [Some(90), Some(90), Some(1800), Some(7200), Some(0)]);
        for bad in ["", "s", "1d", "1.5h", "+1", "-1", "1 h", "1hs", "2H"] {
            assert_eq!(secs(bad), None, "{bad}");
        }
    }
}
