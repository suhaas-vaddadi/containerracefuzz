//! The mutator runs at a hold as the held task (D6). Needs root, a running
//! scx_crfuzz_gated, `unshare` and `setpriv`:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::{GateBackend, Poll};
use scx_crfuzz::engine::run;
use scx_crfuzz::pos::Pos;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// The SUT drops to nobody in its own mount namespace, then opens a relative
/// path from its cwd: the mutator at that hold must see the same uid, gid,
/// namespace, cwd and path, and run with no seccomp filter.
#[test]
#[ignore]
fn mutator_runs_as_held_task() {
    let d = Path::new("/tmp/crfuzz_mut");
    let _ = fs::remove_dir_all(d);
    fs::create_dir(d).unwrap();
    fs::set_permissions(d, fs::Permissions::from_mode(0o777)).unwrap();
    fs::write(d.join("f"), "").unwrap();
    fs::write(d.join("log"), "").unwrap();
    fs::set_permissions(d.join("log"), fs::Permissions::from_mode(0o666)).unwrap();
    let m = d.join("m.sh");
    fs::write(&m, "#!/bin/sh\necho \"$1 $(id -u) $(id -g) $(pwd) $(readlink /proc/self/ns/mnt) $(awk '/^Seccomp:/ {print $2}' /proc/self/status) $CRFUZZ_SEED\" >> /tmp/crfuzz_mut/log\n").unwrap();
    fs::set_permissions(&m, fs::Permissions::from_mode(0o755)).unwrap();

    let mut cmd = Command::new("unshare");
    cmd.args(["-m", "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "sh", "-c"])
        .arg("readlink /proc/self/ns/mnt > /tmp/crfuzz_mut/ns; cd /tmp/crfuzz_mut && cat f");
    let mut be = GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let ms = Duration::from_millis;
    let log = run(&mut be, &mut Pos::new(1), Some(&m), ms(1), ms(200), deadline).unwrap();
    assert!(be.child().wait().unwrap().success());

    let hold = log.iter().find(|d| d.id.path.as_deref() == Some(Path::new("f"))).expect("cat's open of f decided");
    assert!(hold.mutation.as_ref().is_some_and(|r| r.as_ref().is_ok_and(|s| s.success())), "{:?}", hold.mutation);
    let failed: Vec<_> = log.iter().filter(|d| d.mutation.as_ref().is_some_and(|m| !m.as_ref().is_ok_and(|s| s.success()))).collect();
    assert!(failed.is_empty(), "mutations failed: {failed:?}");
    let lines = fs::read_to_string(d.join("log")).unwrap();
    let fired = log.iter().filter(|d| d.mutation.is_some()).count();
    assert_eq!(lines.lines().count(), fired, "one mutator run per hold it fired at");
    assert!(log.iter().all(|d| d.mutation.is_none() || d.id.path.is_some()), "fired without a path");
    eprintln!("{} mutator runs, {} decisions", lines.lines().count(), log.len());
    let line = lines.lines().find(|l| l.starts_with("f ")).expect("mutator ran on f");
    let f: Vec<&str> = line.split(' ').collect();
    let ns = fs::read_to_string(d.join("ns")).unwrap();
    assert_eq!(&f[1..5], ["65534", "65534", "/tmp/crfuzz_mut", ns.trim()], "{line}");
    // Unfiltered: the SUT's seccomp filter must not reach the mutator.
    assert!(lines.lines().all(|l| l.split(' ').nth(5) == Some("0")), "mutator under seccomp:\n{lines}");
    assert_ne!(ns.trim(), fs::read_link("/proc/self/ns/mnt").unwrap().to_str().unwrap(), "SUT in its own namespace");
    fs::remove_dir_all(d).unwrap();
}

/// A mutator that outlives the timeout is killed and reported, and the call
/// returns on time, so the tree hold around it ends.
#[test]
#[ignore]
fn mutator_timeout_returns() {
    let d = Path::new("/tmp/crfuzz_mut_timeout");
    let _ = fs::remove_dir_all(d);
    fs::create_dir(d).unwrap();
    let (f, m) = (d.join("f"), d.join("m.sh"));
    fs::write(&f, "").unwrap();
    fs::write(&m, "#!/bin/sh\nexec sleep 30\n").unwrap();
    fs::set_permissions(&m, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = Command::new("cat");
    cmd.arg(&f);
    let mut be = GateBackend::spawn(cmd, &[libc::SYS_openat]).unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    let ev = loop {
        assert!(Instant::now() < end, "open of f never trapped");
        let Poll::Events(evs) = be.poll(Duration::from_millis(100)).unwrap() else { continue };
        let mut hit = None;
        for ev in evs {
            if ev.path.as_deref() == Some(f.as_path()) && hit.is_none() {
                hit = Some(ev);
            } else {
                be.release(&ev).unwrap();
            }
        }
        if let Some(ev) = hit {
            break ev;
        }
    };
    let t = Instant::now();
    let err = be.mutate(&ev, &m, 0, Duration::from_millis(300)).unwrap_err();
    eprintln!("{err:#} after {:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(1), "mutate outlived its timeout");
    // "not started" if the exec itself outlived the timeout (a loaded VM).
    assert!(["still running", "not started"].iter().any(|m| format!("{err:#}").contains(m)), "{err:#}");
    be.release(&ev).unwrap();
    assert!(be.child().wait().unwrap().success());
    fs::remove_dir_all(d).unwrap();
}
