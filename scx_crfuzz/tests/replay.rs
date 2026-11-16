//! A discovered Violation is written as a schedule, confirmed by replay and
//! minimized to one hold; `replay` does it again from the file. Needs root, a
//! running `scx_crfuzz gated` and cc:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::GateBackend;
use scx_crfuzz::engine::{project, run, End, Replay};
use scx_crfuzz::pos::Pos;
use scx_crfuzz::schedule::Fixed;
use std::fs;
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const D: &str = "/tmp/crfuzz_replay";
const S: &str = "/tmp/crfuzz_scope";

/// crfuzz's stdout; fails unless it exits `code`. Removes the canaries it kept.
fn crfuzz(args: &[&str], code: i32) -> String {
    let child = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz")).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let res = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&res.stdout).into_owned();
    assert_eq!(res.status.code(), Some(code), "{out}\n{}", String::from_utf8_lossy(&res.stderr));
    for e in fs::read_dir("/var/lib/crfuzz").unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with(&format!("canary-{pid}-")) {
            fs::remove_dir_all(e.path()).unwrap();
        }
    }
    out
}

fn line<'a>(out: &'a str, prefix: &str) -> Vec<&'a str> {
    out.lines().filter_map(|l| l.strip_prefix(prefix)).collect()
}

/// check_use (stat then write, as root) on alice's `p`; her mutator swaps `p`
/// for a symlink into the current run's canary (the newest).
#[test]
#[ignore]
fn discover_confirm_minimize() {
    let d = Path::new(D);
    let _ = fs::remove_dir_all(d);
    fs::create_dir_all(d.join("alice")).unwrap();
    let sut = d.join("check_use");
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/check_use.c");
    assert!(Command::new("cc").arg("-o").arg(&sut).arg(src).status().unwrap().success(), "cc failed");
    let p = d.join("alice/p");
    chown(d.join("alice"), Some(65534), Some(65534)).unwrap();
    let m = d.join("swap.sh");
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = {p} ] || exit 0\nc=$(ls -dt /var/lib/crfuzz/canary-* | head -1)\nln -sfn \"$c/file\" {p}.new && mv -f {p}.new {p}\n",
        p = p.display()
    );
    fs::write(&m, script).unwrap();
    fs::set_permissions(&m, fs::Permissions::from_mode(0o755)).unwrap();
    // Run by crfuzz before every run: `p` back to a plain file of alice's dir.
    let layout = d.join("layout.sh");
    fs::write(&layout, format!("#!/bin/sh\nrm -f {p}\n: > {p}\n", p = p.display())).unwrap();
    fs::set_permissions(&layout, fs::Permissions::from_mode(0o755)).unwrap();
    let c = d.join("camp");
    let (c_s, m_s, l_s, sut_s, p_s) = (c.to_str().unwrap(), m.to_str().unwrap(), layout.to_str().unwrap(), sut.to_str().unwrap(), p.to_str().unwrap());

    // Seed 0 runs every window; each new Violation is confirmed and minimized
    // to its one hold, and is finding n. 3: a confirmed finding.
    let out = crfuzz(&["run", c_s, "--seeds", "1", "--timeout", "30", "--attacker", "65534:65534", "--mutator", m_s, "--layout", l_s, "--", sut_s, p_s], 3);
    eprintln!("{out}");
    let new = out.lines().filter(|l| l.ends_with(": Violation, confirming")).count();
    assert!(new > 0 && line(&out, "[1/1] seed 0: ").last() == Some(&"unsafe"), "{out}");
    assert_eq!(line(&out, "  confirmed: "), vec!["Violation"; new], "{out}");
    let guilty = line(&out, "  guilty: step ");
    assert_eq!(guilty.len(), new, "one hold each: {out}");
    // Without -v, no decision log.
    assert!(!out.contains("Decision {"), "{out}");
    let sched = c.join("findings/1/schedule");
    assert!(fs::read_to_string(&sched).unwrap().contains("\ntimeout 30\n"));

    // Left as the last minimization run's SUT made it: replay resets it.
    let again = crfuzz(&["replay", sched.to_str().unwrap(), "-v"], 3);
    eprintln!("{again}");
    assert_eq!(line(&again, "confirmed: "), ["Violation"], "{again}");
    assert_eq!(line(&again, "guilty: step "), guilty[..1], "{again}");
    assert!(again.lines().any(|l| l.starts_with("Decision {")), "-v: {again}");
    // The guilty hold is one of the SUT's own on `p`.
    assert!(guilty[0].contains(p_s), "{}", guilty[0]);
    fs::remove_dir_all(d).unwrap();
}

/// Only the holds in scope are held, recorded and ordered: the root's first
/// `cat` opens another file outside it than discovery's, and the sleeps are
/// swapped, so in/b is held while the expected in/a's process sleeps (the
/// late wait). The root no longer waits for them, but its exit_group, where
/// the oracle probes, keeps its recorded place after both.
#[test]
#[ignore]
fn scoped_replay_waits_for_late_steps() {
    let d = Path::new(S);
    let _ = fs::remove_dir_all(d);
    fs::create_dir_all(d.join("in")).unwrap();
    for f in ["in/a", "in/b", "x", "y"] {
        fs::write(d.join(f), "").unwrap();
    }
    let once = |args: [&str; 4], scope: &[PathBuf], replay: Option<&mut Replay>| {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "cat $0/$3; (sleep $1; cat $0/in/a) & (sleep $2; cat $0/in/b) & $4", S]).args(args);
        let mut be = GateBackend::spawn(cmd, scope).unwrap();
        let mut log = Vec::new();
        let end = run(&mut be, &mut Pos::new(0), &[], None, None, replay, None, Instant::now() + Duration::from_secs(10), &mut log).unwrap();
        (end, log)
    };
    let scope = [d.join("in")];
    let (end, log) = once(["0", "0.3", "x", "wait"], &scope, None);
    assert!(matches!(end, End::Exited), "{end:?}");
    let steps = project(&log);
    let paths: Vec<_> = steps.iter().filter_map(|s| s.id.path.as_deref()).collect();
    assert_eq!(paths, [d.join("in/a"), d.join("in/b")], "nothing out of scope is a step");
    let replay = |scope: &[PathBuf]| {
        let mut r = Replay { fixed: Fixed { steps: &steps, next: 0, deadline: false }, only: None, diverged: None };
        once(["0.3", "0", "y", ":"], scope, Some(&mut r))
    };
    let (end, log) = replay(&scope);
    assert!(matches!(end, End::Exited), "{end:?}");
    let order: Vec<_> = log.iter().filter(|e| e.id.path.as_deref() == Some(&d.join("in/b")) || (e.id.process == "0" && e.id.nr == libc::SYS_exit_group)).map(|e| e.id.nr).collect();
    assert_eq!(order, [libc::SYS_openat, libc::SYS_exit_group], "the root's exit waits for the late in/b");
    let end = replay(&[]).0;
    assert!(matches!(end, End::Diverged(_)), "unscoped, everything else is held and diverges: {end:?}");
    fs::remove_dir_all(d).unwrap();
}

/// A relative path from a cwd below a scope directory is in scope.
#[test]
#[ignore]
fn scope_holds_relative_paths_below_it() {
    let d = Path::new(S);
    let _ = fs::remove_dir_all(d);
    fs::create_dir_all(d.join("in/sub")).unwrap();
    fs::write(d.join("in/sub/f"), "").unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "cd $0/in/sub && cat f", S]);
    let mut be = GateBackend::spawn(cmd, &[d.join("in")]).unwrap();
    let mut log = Vec::new();
    let end = run(&mut be, &mut Pos::new(0), &[], None, None, None, None, Instant::now() + Duration::from_secs(10), &mut log).unwrap();
    assert!(matches!(end, End::Exited), "{end:?}");
    assert!(log.iter().any(|e| e.id.path.as_deref() == Some(Path::new("f"))), "cat's open of f is held");
    fs::remove_dir_all(d).unwrap();
}
