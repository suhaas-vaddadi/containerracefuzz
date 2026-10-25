//! The judged CLI (§1, §10). `missing_attacker_refused` needs nothing; the
//! rest need root and a running scx_crfuzz_gated:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use std::fs;
use std::process::{Command, Output, Stdio};

/// crfuzz's output and pid (which names its canaries).
fn crfuzz(args: &[&str]) -> (Output, u32) {
    let child = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz")).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    (child.wait_with_output().unwrap(), pid)
}

/// Canaries crfuzz `pid` left in /var/lib/crfuzz.
fn left(pid: u32) -> Vec<String> {
    let Ok(rd) = fs::read_dir("/var/lib/crfuzz") else { return vec![] };
    rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).filter(|n| n.starts_with(&format!("canary-{pid}-"))).collect()
}

/// §10.4: no --attacker, refused with the usage error before any canary.
#[test]
fn missing_attacker_refused() {
    let (out, pid) = crfuzz(&["--", "/bin/true"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("--attacker is required") && err.contains("usage:"), "{err}");
    assert!(left(pid).is_empty());
}

/// §10.2: an invalid run (alice as uid 0 owns the gate: read before fails)
/// leaves no canary behind.
#[test]
#[ignore]
fn invalid_run_leaves_no_canary() {
    let (out, pid) = crfuzz(&["--attacker", "0:0", "--", "/bin/true"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("self-check"), "{err}");
    assert!(left(pid).is_empty(), "{:?}", left(pid));
}

/// §8 acceptance. A root SUT checks `p` (alice's) then writes it; alice's
/// mutator swaps `p` for a symlink into the fuzzed run's canary.
mod accept {
    use super::{crfuzz, left};
    use std::fs;
    use std::os::unix::fs::{chown, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const D: &str = "/tmp/crfuzz_accept";

    /// The fixture, alice's directory holding `p`, and the swap mutator
    /// (into the canary's `file`).
    fn setup() -> (PathBuf, PathBuf, PathBuf) {
        let d = Path::new(D);
        let _ = fs::remove_dir_all(d);
        fs::create_dir(d).unwrap();
        let sut = d.join("check_use");
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/check_use.c");
        assert!(Command::new("cc").arg("-o").arg(&sut).arg(src).status().unwrap().success(), "cc failed");
        let p = d.join("alice/p");
        fs::create_dir(d.join("alice")).unwrap();
        fs::write(&p, "").unwrap();
        chown(d.join("alice"), Some(65534), Some(65534)).unwrap();
        let m = swap(&p, "/file");
        (sut, p, m)
    }

    /// A mutator that, as alice, swaps `p` for a symlink to the fuzzed run's
    /// canary plus `rest` (the newest `-1`: the baseline's is gone by then).
    fn swap(p: &Path, rest: &str) -> PathBuf {
        let m = Path::new(D).join(format!("swap{}.sh", rest.replace('/', "_")));
        let script = format!(
            "#!/bin/sh\n[ \"$1\" = {p} ] || exit 0\nc=$(ls -dt /var/lib/crfuzz/canary-*-1 | head -1)\nln -sfn \"$c{rest}\" {p}.new && mv -f {p}.new {p}\n",
            p = p.display()
        );
        fs::write(&m, script).unwrap();
        fs::set_permissions(&m, fs::Permissions::from_mode(0o755)).unwrap();
        m
    }

    /// The outcome line, after removing any canary this run kept.
    fn outcome(args: &[&str]) -> String {
        let (out, pid) = crfuzz(args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
        for c in left(pid) {
            fs::remove_dir_all(Path::new("/var/lib/crfuzz").join(c)).unwrap();
        }
        stdout.lines().find_map(|l| l.strip_prefix("outcome: ")).expect("an outcome").to_string()
    }

    fn judge(sut: &Path, p: &Path, mutator: Option<&Path>, nofollow: bool, seed: u32) -> String {
        let mut cmd = vec![sut.to_str().unwrap(), p.to_str().unwrap()];
        if nofollow {
            cmd.push("nofollow");
        }
        judge_cmd(&cmd, p, mutator, seed)
    }

    fn judge_cmd(cmd: &[&str], p: &Path, mutator: Option<&Path>, seed: u32) -> String {
        // Each run starts from a regular `p`.
        let _ = fs::remove_file(p);
        fs::write(p, "").unwrap();
        let seed = seed.to_string();
        let mut args = vec!["--attacker", "65534:65534", "--seed", &seed];
        if let Some(m) = mutator {
            args.extend(["--mutator", m.to_str().unwrap()]);
        }
        args.push("--");
        args.extend(cmd);
        outcome(&args)
    }

    #[test]
    #[ignore]
    fn check_then_use() {
        let (sut, p, m) = setup();
        let v = judge(&sut, &p, Some(&m), false, 0);
        assert!(v.starts_with("Violation") && v.contains("\"file\""), "write half: {v}");
        assert_eq!(judge(&sut, &p, Some(&m), true, 0), "RuntimeRefused");
        assert_eq!(judge(&sut, &p, None, true, 0), "Clean");
        for seed in 1..6 {
            let o = judge(&sut, &p, Some(&m), true, seed);
            assert!(!o.starts_with("Violation"), "seed {seed}: {o}");
        }
        fs::remove_dir_all(D).unwrap();
    }

    /// A root SUT chmods `p`, swapped for the gate: the gate opens to alice,
    /// so the self-check fails, but on a changed canary: a Violation, not an
    /// invalid run.
    #[test]
    #[ignore]
    fn exposed_gate_is_violation() {
        let (_, p, _) = setup();
        let m = swap(&p, "");
        let o = judge_cmd(&["sh", "-c", &format!("chmod 777 {}", p.display())], &p, Some(&m), 0);
        assert!(o.starts_with("Violation") && o.contains("entry: \"\""), "{o}");
        fs::remove_dir_all(D).unwrap();
    }

    /// Alice alone points `p` at the gate; the SUT only stats it. She can
    /// stat a 0700 gate anyway: Clean, not Reached.
    #[test]
    #[ignore]
    fn gate_alone_not_reached() {
        let (_, p, _) = setup();
        let m = swap(&p, "");
        assert_eq!(judge_cmd(&["sh", "-c", &format!("test -e {}", p.display())], &p, Some(&m), 0), "Clean");
        fs::remove_dir_all(D).unwrap();
    }
}
