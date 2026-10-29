//! M7: a discovered Violation is written as a schedule, confirmed by replay
//! and minimized to one hold. Needs root, a running scx_crfuzz_gated and cc:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

const D: &str = "/tmp/crfuzz_replay";

/// crfuzz's stdout; fails on an invalid run. Removes the canaries it kept.
fn crfuzz(args: &[&str]) -> String {
    let child = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz")).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let res = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&res.stdout).into_owned();
    assert!(res.status.success(), "{out}\n{}", String::from_utf8_lossy(&res.stderr));
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
    let log = d.join("schedule");
    let (log_s, m_s, l_s, sut_s, p_s) = (log.to_str().unwrap(), m.to_str().unwrap(), layout.to_str().unwrap(), sut.to_str().unwrap(), p.to_str().unwrap());

    // One mutation target per seed. Each invocation's baseline runs under its
    // own seed; the SUT is single-threaded, so the targets match and 64 seeds
    // cover every one (16 here, more where the loader searches more paths);
    // stops at the first hit.
    let out = (0..64)
        .map(|seed| {
            let seed = seed.to_string();
            crfuzz(&["--attacker", "65534:65534", "--seed", &seed, "--mutator", m_s, "--layout", l_s, "--log", log_s, "--", sut_s, p_s])
        })
        .find(|o| line(o, "outcome: ").iter().any(|c| c.starts_with("Violation")))
        .expect("no seed found the Violation");
    eprintln!("{out}");
    assert_eq!(line(&out, "confirmed: "), ["Violation"], "{out}");
    let guilty = line(&out, "guilty: step ");
    assert_eq!(guilty.len(), 1, "exactly one hold: {out}");

    // Left as the last minimization run's SUT made it: --replay resets it.
    let again = crfuzz(&["--replay", log_s]);
    eprintln!("{again}");
    assert_eq!(line(&again, "confirmed: "), ["Violation"], "{again}");
    assert_eq!(line(&again, "guilty: step "), guilty, "{again}");
    // The guilty hold is one of the SUT's own on `p`.
    assert!(guilty[0].contains(p_s), "{}", guilty[0]);
    fs::remove_dir_all(d).unwrap();
}
