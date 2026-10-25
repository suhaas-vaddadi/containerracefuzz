//! The read half at the final hold (§5) and read before. Needs root, a
//! running scx_crfuzz_gated, `unshare`, `mount` and `setpriv`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::{read_before, GateBackend, SelfCheckFailed};
use scx_crfuzz::engine::{run, Deadline, Judge};
use scx_crfuzz::oracle::{Alice, Canary, Finding};
use scx_crfuzz::pos::Pos;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const WATCHED: &[i64] = &[libc::SYS_openat, libc::SYS_chdir, libc::SYS_exit_group];
const NOBODY: &str = "setpriv --reuid=65534 --regid=65534 --clear-groups";

fn nobody() -> Alice {
    Alice::parse("65534:65534").unwrap()
}

/// Run `sh -c script` judged against nobody; returns its findings.
fn judged(canary: &Canary, script: &str) -> Vec<Finding> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(script);
    let mut be = GateBackend::spawn(cmd, WATCHED).unwrap();
    let mut j = Judge { canary, alice: nobody(), reached: None, task: None };
    let ms = Duration::from_millis;
    run(&mut be, &mut Pos::new(1), None, None, Some(&mut j), ms(1), ms(200), Instant::now() + Duration::from_secs(30), &mut Vec::new()).unwrap();
    assert!(be.child().wait().unwrap().success());
    j.reached.expect("final hold probed")
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new("/tmp").join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("mnt")).unwrap();
    d
}

/// A SUT that drops to nobody with its cwd in a bind mount of `<canary>/dir`:
/// reached through mountinfo and through its cwd.
#[test]
#[ignore]
fn bind_mount_reached() {
    let c = Canary::create(200).unwrap();
    let d = scratch("crfuzz_probe_bind");
    let mnt = d.join("mnt");
    let script = format!("mount --bind {}/dir {m} && cd {m} && exec {NOBODY} true", c.dir.display(), m = mnt.display());
    let found = judged(&c, &format!("exec unshare -m sh -c '{script}'"));
    let dir = PathBuf::from("dir");
    assert!(found.contains(&Finding::Reached { entry: dir.clone(), at: mnt.clone() }), "{found:?}");
    assert!(found.iter().any(|f| matches!(f, Finding::Reached { entry, at } if *entry == dir && at.ends_with("cwd"))), "{found:?}");
    fs::remove_dir_all(d).unwrap();
}

/// A root SUT copies a canary file somewhere alice can read: the token is
/// found there (the read half's `Copy`), and nothing else.
#[test]
#[ignore]
fn copy_found() {
    let c = Canary::create(204).unwrap();
    let d = scratch("crfuzz_probe_copy");
    let leak = d.join("leak");
    let found = judged(&c, &format!("cp {}/file {}", c.dir.display(), leak.display()));
    assert_eq!(found, [Finding::Copy { at: leak }]);
    fs::remove_dir_all(d).unwrap();
}

/// §10.5: a SUT that chroots into `<canary>/dir`, drops to nobody and exits,
/// changing nothing: alice's root is a canary entry, so reached through the
/// task's root handle, not an invalid run.
#[test]
#[ignore]
fn root_in_canary_reached() {
    let c = Canary::create(206).unwrap();
    let d = scratch("crfuzz_probe_chroot");
    let sut = d.join("chroot_drop");
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chroot_drop.c");
    assert!(Command::new("cc").arg("-o").arg(&sut).arg(src).status().unwrap().success(), "cc failed");
    let found = judged(&c, &format!("exec {} {}/dir", sut.display(), c.dir.display()));
    assert!(found.iter().any(|f| matches!(f, Finding::Reached { entry, at } if *entry == PathBuf::from("dir") && at.ends_with("root"))), "{found:?}");
    fs::remove_dir_all(d).unwrap();
}

/// The same SUT with no bind mount: nothing found.
#[test]
#[ignore]
fn no_mount_clean() {
    let c = Canary::create(201).unwrap();
    let d = scratch("crfuzz_probe_clean");
    let found = judged(&c, &format!("cd {} && exec {NOBODY} true", d.join("mnt").display()));
    assert!(found.is_empty(), "{found:?}");
    fs::remove_dir_all(d).unwrap();
}

/// A SUT that stays root with its cwd inside the canary, alice nobody: the
/// handle check is skipped (the task isn't alice), the self-check passes
/// (EACCES), and the relative footprint path `file` is not resolved from the
/// task's cwd, which alice could never have.
#[test]
#[ignore]
fn root_sut_attacker_nobody() {
    let c = Canary::create(202).unwrap();
    let found = judged(&c, &format!("cd {}/dir && cat file >/dev/null && exit 0", c.dir.display()));
    assert!(found.is_empty(), "{found:?}");
}

/// Read before: a fresh canary stops nobody; a gate she can search but not
/// read fails, although §4's open of the gate alone would still pass.
#[test]
#[ignore]
fn read_before_catches_searchable_gate() {
    let c = Canary::create(203).unwrap();
    read_before(&c, &nobody()).unwrap();
    fs::set_permissions(&c.dir, fs::Permissions::from_mode(0o711)).unwrap();
    let e = read_before(&c, &nobody()).unwrap_err();
    assert!(e.is::<SelfCheckFailed>(), "{e:#}");
    // Unchanged again, or drop leaves it.
    fs::set_permissions(&c.dir, fs::Permissions::from_mode(0o700)).unwrap();
}

/// §10.3: a SUT that sleeps past the deadline fails with `Deadline`, and the
/// decisions made before it are kept.
#[test]
#[ignore]
fn deadline_keeps_log() {
    let c = Canary::create(205).unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("cat /dev/null; sleep 10");
    let mut be = GateBackend::spawn(cmd, WATCHED).unwrap();
    let mut j = Judge { canary: &c, alice: nobody(), reached: None, task: None };
    let (ms, mut log) = (Duration::from_millis, Vec::new());
    let e = run(&mut be, &mut Pos::new(1), None, None, Some(&mut j), ms(1), ms(200), Instant::now() + Duration::from_secs(2), &mut log).unwrap_err();
    assert!(e.is::<Deadline>(), "{e:#}");
    assert!(log.iter().any(|d| d.id.path.as_deref() == Some(Path::new("/dev/null"))), "{log:?}");
}
