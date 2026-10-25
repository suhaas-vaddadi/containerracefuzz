//! M8: a campaign over check_use dedups to one finding; over the corrected
//! bundle, none. Needs root, a running scx_crfuzz_gated and cc:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

const D: &str = "/tmp/crfuzz_campaign";

/// A campaign's stdout; fails on a crfuzz error. Removes the canaries it kept.
fn campaign(dir: &Path, cmd: &[&str], m: &Path, layout: &Path) -> String {
    let mut args = vec!["--campaign", dir.to_str().unwrap(), "--seeds", "8", "--attacker", "65534:65534"];
    args.extend(["--mutator", m.to_str().unwrap(), "--layout", layout.to_str().unwrap(), "--"]);
    args.extend(cmd);
    let child = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz")).args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let res = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&res.stdout).into_owned();
    assert!(res.status.success(), "{out}\n{}", String::from_utf8_lossy(&res.stderr));
    for e in fs::read_dir("/var/lib/crfuzz").unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with(&format!("canary-{pid}-")) {
            fs::remove_dir_all(e.path()).unwrap();
        }
    }
    eprintln!("{out}");
    out
}

fn line<'a>(out: &'a str, prefix: &str) -> &'a str {
    out.lines().find_map(|l| l.strip_prefix(prefix)).unwrap_or_else(|| panic!("no {prefix:?}: {out}"))
}

/// The tests/replay.rs scenario: check_use on alice's `p`, her mutator swaps
/// `p` for a symlink into the current run's canary, layout resets `p`.
#[test]
#[ignore]
fn campaign_dedups() {
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
    let layout = d.join("layout.sh");
    fs::write(&layout, format!("#!/bin/sh\nrm -f {p}\n: > {p}\n", p = p.display())).unwrap();
    fs::set_permissions(&layout, fs::Permissions::from_mode(0o755)).unwrap();
    let (sut_s, p_s) = (sut.to_str().unwrap(), p.to_str().unwrap());

    let c = d.join("bug");
    let out = campaign(&c, &[sut_s, p_s], &m, &layout);
    assert!(line(&out, "campaign: ").contains(" 0 invalid"), "{out}");
    assert_eq!(line(&out, "findings: "), "1", "{out}");
    assert!(line(&out, "distinct partial orders: ").parse::<usize>().unwrap() >= 1, "{out}");
    assert_eq!(fs::read_dir(c.join("runs")).unwrap().count(), 8);
    // runs.tsv: header, then seed class status finding ...
    let tsv = fs::read_to_string(c.join("runs.tsv")).unwrap();
    assert_eq!(tsv.lines().count(), 9, "{tsv}");
    let rows: Vec<Vec<&str>> = tsv.lines().skip(1).map(|l| l.split('\t').collect()).collect();
    let mut want: Vec<&str> = rows.iter().filter(|r| matches!(r[2], "new" | "repeat")).map(|r| r[0]).collect();
    assert!(rows.iter().all(|r| !matches!(r[2], "new" | "repeat") || r[3] == "1"), "{tsv}");
    let seeds = fs::read_to_string(c.join("findings/1/seeds")).unwrap();
    let mut got: Vec<&str> = seeds.lines().collect();
    want.sort();
    got.sort();
    assert_eq!(got, want, "{tsv}");
    assert!(fs::read_to_string(c.join("findings/1/schedule")).unwrap().contains("outcome Violation"));

    let c = d.join("fixed");
    let out = campaign(&c, &[sut_s, p_s, "nofollow"], &m, &layout);
    assert_eq!(line(&out, "findings: "), "0", "{out}");
    assert_eq!(fs::read_dir(c.join("runs")).unwrap().count(), 8);
    fs::remove_dir_all(d).unwrap();
}
