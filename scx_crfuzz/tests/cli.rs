//! The judged CLI (§1, §10). `missing_attacker_refused` and
//! `usage_errors_exit_2` need nothing; the rest need root and a running
//! scx_crfuzz_gated:
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
    let (out, pid) = crfuzz(&["run", "/tmp/crfuzz_cli_none", "--seeds", "1", "--", "/bin/true"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("--attacker is required") && err.contains("usage:"), "{err}");
    assert!(left(pid).is_empty());
}

/// Bad or missing arguments: the usage on stderr, exit 2, never a panic.
/// --help and --version: stdout, exit 0.
#[test]
fn usage_errors_exit_2() {
    fn run<'a>(rest: &[&'a str]) -> Vec<&'a str> {
        [&["run", "/tmp/crfuzz_cli_none", "--attacker", "1:1"], rest].concat()
    }
    for args in [
        vec![],
        vec!["fuzz"],
        vec!["run"],
        run(&["--seeds"]),
        run(&["--seeds", "x", "--", "/bin/true"]),
        run(&["--timeout", "-1", "--seeds", "1", "--", "/bin/true"]),
        run(&["--timeout", "0", "--seeds", "1", "--", "/bin/true"]),
        run(&["--timeout", "31", "--seeds", "1", "--", "/bin/true"]),
        run(&["--seeds", "1", "--bogus", "--", "/bin/true"]),
        run(&["--seeds", "1"]),
        run(&["--seeds", "1", "--"]),
        run(&["--", "/bin/true"]),
        vec!["run", "/tmp/crfuzz_cli_none", "--attacker", "1", "--seeds", "1", "--", "/bin/true"],
        vec!["replay"],
        vec!["replay", "a", "b"],
    ] {
        let (out, _) = crfuzz(&args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("usage:") && !err.contains("panicked"), "{args:?}: {err}");
    }
    for (args, want) in [("--help", "usage:"), ("-h", "usage:"), ("--version", "scx_crfuzz "), ("-V", "scx_crfuzz ")] {
        let (out, _) = crfuzz(&[args]);
        assert_eq!(out.status.code(), Some(0), "{args}");
        assert!(String::from_utf8_lossy(&out.stdout).starts_with(want), "{args}");
    }
}

/// §10.2: an invalid run (alice as uid 0 owns the gate: read before fails)
/// leaves no canary behind; the seed is recorded invalid and the run goes on.
#[test]
#[ignore]
fn invalid_run_leaves_no_canary() {
    let d = "/tmp/crfuzz_cli_invalid";
    let _ = fs::remove_dir_all(d);
    let (out, pid) = crfuzz(&["run", d, "--seeds", "1", "--attacker", "0:0", "--", "/bin/true"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.lines().any(|l| l.starts_with("[1/1] seed 0: incomplete") && l.contains("self-check")), "{stdout}");
    assert!(fs::read_to_string(format!("{d}/runs.tsv")).unwrap().contains("\tinvalid\t"));
    assert!(left(pid).is_empty(), "{:?}", left(pid));
    fs::remove_dir_all(d).unwrap();
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

    /// A mutator that, as alice, swaps `p` for a symlink to the current run's
    /// canary (the newest) plus `rest`.
    fn swap(p: &Path, rest: &str) -> PathBuf {
        let m = Path::new(D).join(format!("swap{}.sh", rest.replace('/', "_")));
        let script = format!(
            "#!/bin/sh\n[ \"$1\" = {p} ] || exit 0\nc=$(ls -dt /var/lib/crfuzz/canary-* | head -1)\nln -sfn \"$c{rest}\" {p}.new && mv -f {p}.new {p}\n",
            p = p.display()
        );
        fs::write(&m, script).unwrap();
        fs::set_permissions(&m, fs::Permissions::from_mode(0o755)).unwrap();
        m
    }

    /// The stdout of `run` over seed 0, after removing any canary it kept;
    /// fails unless it exits 3 (a finding) or 0.
    fn run(args: &[&str]) -> String {
        let dir = Path::new(D).join("out");
        let _ = fs::remove_dir_all(&dir);
        let (out, pid) = crfuzz(&[&["run", dir.to_str().unwrap(), "--seeds", "1"], args].concat());
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let found = stdout.lines().any(|l| l.starts_with("finding #"));
        assert_eq!(out.status.code(), Some(if found { 3 } else { 0 }), "{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
        for c in left(pid) {
            fs::remove_dir_all(Path::new("/var/lib/crfuzz").join(c)).unwrap();
        }
        stdout
    }

    /// Every window's outcome class, and the seed's verdict (its last line).
    fn outcomes(out: &str) -> (Vec<&str>, &str) {
        let v = out.lines().filter_map(|l| l.strip_prefix("[1/1] seed 0: ")).last().unwrap_or_else(|| panic!("a verdict: {out}"));
        // `window k/n: <class> ...`, not `window k: Violation, confirming`.
        let o = out.lines().filter_map(|l| {
            let (w, what) = l.strip_prefix("[1/1] seed 0 window ")?.split_once(": ")?;
            w.contains('/').then_some(what)?.split_whitespace().next()
        });
        (o.collect(), v)
    }

    /// The summary's `finding #n` lines, each with its normalized findings.
    fn findings(out: &str) -> Vec<&str> {
        out.lines().filter(|l| l.starts_with("finding #")).collect()
    }

    fn judge(sut: &Path, p: &Path, mutator: Option<&Path>, nofollow: bool) -> String {
        let mut cmd = vec![sut.to_str().unwrap(), p.to_str().unwrap()];
        if nofollow {
            cmd.push("nofollow");
        }
        judge_cmd(&cmd, p, mutator)
    }

    /// Seed 0 over all its windows.
    fn judge_cmd(cmd: &[&str], p: &Path, mutator: Option<&Path>) -> String {
        // Every run starts from a regular `p`.
        let layout = Path::new(D).join("layout.sh");
        fs::write(&layout, format!("#!/bin/sh\nrm -f {p}\n: > {p}\n", p = p.display())).unwrap();
        fs::set_permissions(&layout, fs::Permissions::from_mode(0o755)).unwrap();
        let mut args = vec!["--attacker", "65534:65534", "--layout", layout.to_str().unwrap()];
        if let Some(m) = mutator {
            args.extend(["--mutator", m.to_str().unwrap()]);
        }
        args.push("--");
        args.extend(cmd);
        run(&args)
    }

    #[test]
    #[ignore]
    fn check_then_use() {
        let (sut, p, m) = setup();
        let out = judge(&sut, &p, Some(&m), false);
        let (o, v) = outcomes(&out);
        assert_eq!(v, "unsafe", "{out}");
        assert!(o.contains(&"Violation"), "{out}");
        assert!(findings(&out).iter().any(|f| f.contains("\"file\"")), "write half: {out}");
        // nofollow: the same windows, the swap refused.
        let out = judge(&sut, &p, Some(&m), true);
        let (o, v) = outcomes(&out);
        assert_eq!(v, "safe", "{out}");
        assert!(o.contains(&"RuntimeRefused"), "{out}");
        assert_eq!(outcomes(&judge(&sut, &p, None, true)), (vec!["Clean"], "no windows"));
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
        let out = judge_cmd(&["sh", "-c", &format!("chmod 777 {}", p.display())], &p, Some(&m));
        let (o, v) = outcomes(&out);
        assert_eq!(v, "unsafe", "{out}");
        assert!(o.contains(&"Violation"), "{out}");
        assert!(findings(&out).iter().any(|f| f.contains("entry: \"\"")), "{out}");
        fs::remove_dir_all(D).unwrap();
    }

    /// Alice alone points `p` at the gate; the SUT only stats it. She can
    /// stat a 0700 gate anyway: Clean, not Reached, in every window.
    #[test]
    #[ignore]
    fn gate_alone_not_reached() {
        let (_, p, _) = setup();
        let m = swap(&p, "");
        let out = judge_cmd(&["sh", "-c", &format!("test -e {}", p.display())], &p, Some(&m));
        let (o, v) = outcomes(&out);
        assert_eq!(v, "safe", "{out}");
        assert!(o.iter().all(|o| *o == "Clean"), "{out}");
        fs::remove_dir_all(D).unwrap();
    }
}
