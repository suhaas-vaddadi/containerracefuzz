//! M8: a campaign over check_use dedups to findings on `p`; over the corrected
//! bundle, none; at --jobs 4 the same. Needs root, a running `scx_crfuzz gated` and cc:
//!   sudo env PATH=$PATH <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

const D: &str = "/tmp/crfuzz_campaign";
/// Each seed runs every window, so each guilty hold on `p` is hit once per
/// seed: the second seed's are repeats.
const SEEDS: usize = 2;

/// A campaign's stdout, `--seeds` and the like in `opts`; fails unless it
/// exits `code`. Removes the canaries it kept.
fn campaign(dir: &Path, opts: &[&str], cmd: &[&str], m: &Path, layout: &Path, code: i32) -> String {
    let mut args = vec!["run", dir.to_str().unwrap(), "--attacker", "65534:65534"];
    args.extend(opts);
    args.extend(["--mutator", m.to_str().unwrap(), "--layout", layout.to_str().unwrap(), "--"]);
    args.extend(cmd);
    let child = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz")).args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let res = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&res.stdout).into_owned();
    assert_eq!(res.status.code(), Some(code), "{out}\n{}", String::from_utf8_lossy(&res.stderr));
    forget(pid);
    eprintln!("{out}");
    out
}

/// Removes the canaries crfuzz `pid` kept.
fn forget(pid: u32) {
    for e in fs::read_dir("/var/lib/crfuzz").unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with(&format!("canary-{pid}-")) {
            fs::remove_dir_all(e.path()).unwrap();
        }
    }
}

/// Schedules under `DIR/runs/<seed>/`.
fn runs(dir: &Path) -> usize {
    let scheds = |s: fs::DirEntry| fs::read_dir(s.path()).unwrap().filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "sched")).count();
    fs::read_dir(dir.join("runs")).unwrap().map(|s| scheds(s.unwrap())).sum()
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
    // 3: a confirmed finding.
    let out = campaign(&c, &["--seeds", &SEEDS.to_string()], &[sut_s, p_s], &m, &layout, 3);
    assert!(line(&out, "campaign: ").contains(" 0 invalid"), "{out}");
    let n: usize = line(&out, "findings: ").parse().unwrap();
    assert!(n >= 1, "{out}");
    // Every finding's guilty hold is on `p`.
    assert_eq!(out.lines().filter(|l| l.starts_with("finding #") && l.contains(&format!(" {p_s}), "))).count(), n, "{out}");
    assert!(line(&out, "distinct partial orders: ").parse::<usize>().unwrap() >= 1, "{out}");
    assert_eq!(line(&out, "seeds: "), format!("0 safe, {SEEDS} unsafe, 0 incomplete, 0 no windows"), "{out}");
    // runs.tsv: header, then seed window class status finding ..., a row per
    // window and a schedule per row.
    let tsv = fs::read_to_string(c.join("runs.tsv")).unwrap();
    let rows: Vec<Vec<&str>> = tsv.lines().skip(1).map(|l| l.split('\t').collect()).collect();
    assert_eq!(runs(&c), rows.len(), "{tsv}");
    assert!(rows.iter().any(|r| r[3] == "repeat"), "{tsv}");
    // A new finding's window log: its discovery, then its confirm and minimize runs.
    let r = rows.iter().find(|r| r[3] == "new").unwrap();
    let wlog = fs::read_to_string(c.join(format!("runs/{}/{}.log", r[0], r[1]))).unwrap();
    let heads: Vec<&str> = wlog.lines().filter(|l| l.starts_with("== ")).collect();
    assert!(heads.len() >= 3 && heads[..2] == ["== discovery", "== confirm 1/3"] && heads[2].starts_with("== minimize step "), "{wlog}");
    assert!(fs::read_to_string(c.join(format!("runs/{}/baseline.log", r[0]))).unwrap().starts_with("== baseline\n"));
    for i in 1..=n {
        let f = c.join(format!("findings/{i}"));
        let mut want: Vec<String> = rows.iter().filter(|r| r[4] == i.to_string()).map(|r| format!("{}:{}", r[0], r[1])).collect();
        let seeds = fs::read_to_string(f.join("seeds")).unwrap();
        let mut got: Vec<String> = seeds.lines().map(String::from).collect();
        want.sort();
        got.sort();
        assert_eq!(got, want, "{tsv}");
        assert!(fs::read_to_string(f.join("schedule")).unwrap().contains("outcome Violation"));
    }

    let c = d.join("fixed");
    let out = campaign(&c, &["--seeds", &SEEDS.to_string(), "--first-seed", "5"], &[sut_s, p_s, "nofollow"], &m, &layout, 0);
    assert_eq!(line(&out, "findings: "), "0", "{out}");
    assert_eq!(line(&out, "seeds: "), format!("{SEEDS} safe, 0 unsafe, 0 incomplete, 0 no windows"), "{out}");
    // Seeds 5 and 6, counted from 1 within the run.
    let mut seeds: Vec<String> = fs::read_dir(c.join("runs")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    seeds.sort();
    assert_eq!(seeds, ["5", "6"]);
    assert_eq!(out.lines().filter_map(|l| l.strip_prefix("[2/2] seed 6: ")).last(), Some("safe"), "{out}");
    fs::remove_dir_all(d).unwrap();
}

/// A campaign's findings as `guilty <hold>, <findings>`, sorted: what dedup compares.
fn deduped(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out.lines().filter(|l| l.starts_with("finding #")).map(|l| l[l.find("guilty ").unwrap()..l.rfind(", /").unwrap()].into()).collect();
    v.sort();
    v
}

/// The design's --jobs acceptance: check_use at --jobs 4 with `alice` private
/// finds what --jobs 1 finds, the fixed SUT nothing, a finding replays on its
/// own, and the shared `alice` is never touched. The mutator finds its canary
/// by $CRFUZZ_CANARY; the layout restores `alice`'s contents in place.
#[test]
#[ignore]
fn campaign_jobs() {
    let d = Path::new("/tmp/crfuzz_jobs");
    let _ = fs::remove_dir_all(d);
    let alice = d.join("alice");
    fs::create_dir_all(&alice).unwrap();
    let sut = d.join("check_use");
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/check_use.c");
    assert!(Command::new("cc").arg("-o").arg(&sut).arg(src).status().unwrap().success(), "cc failed");
    let p = alice.join("p");
    fs::write(&p, "shared\n").unwrap();
    chown(&alice, Some(65534), Some(65534)).unwrap();
    let m = d.join("swap.sh");
    fs::write(&m, format!("#!/bin/sh\n[ \"$1\" = {p} ] || exit 0\nln -sfn \"$CRFUZZ_CANARY/file\" {p}.new && mv -f {p}.new {p}\n", p = p.display())).unwrap();
    let layout = d.join("layout.sh");
    fs::write(&layout, format!("#!/bin/sh\nrm -f {p}\n: > {p}\n", p = p.display())).unwrap();
    for f in [&m, &layout] {
        fs::set_permissions(f, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (sut_s, p_s, a_s) = (sut.to_str().unwrap(), p.to_str().unwrap(), alice.to_str().unwrap());

    let one = campaign(&d.join("j1"), &["--seeds", "4", "--private", a_s], &[sut_s, p_s], &m, &layout, 3);
    let c = d.join("j4");
    let four = campaign(&c, &["--seeds", "4", "--jobs", "4", "--private", a_s], &[sut_s, p_s], &m, &layout, 3);
    assert!(!deduped(&one).is_empty());
    assert_eq!(deduped(&four), deduped(&one), "{one}\n{four}");
    assert!(line(&four, "campaign: ").contains(" 0 invalid"), "{four}");
    assert_eq!(line(&four, "seeds: "), "0 safe, 4 unsafe, 0 incomplete, 0 no windows", "{four}");
    let tsv = fs::read_to_string(c.join("runs.tsv")).unwrap();
    assert_eq!(runs(&c), tsv.lines().count() - 1, "{tsv}");
    assert_eq!(fs::read_to_string(&p).unwrap(), "shared\n", "a worker's layout reached the shared alice");
    assert!(!Path::new("/var/lib/crfuzz/work").read_dir().is_ok_and(|mut e| e.next().is_some()), "private copies left");

    // A J=4 finding replays alone, its `private` line set up again.
    let f = c.join("findings/1/schedule");
    assert!(fs::read_to_string(&f).unwrap().contains(&format!("\nprivate {a_s}\n")));
    let r = Command::new(env!("CARGO_BIN_EXE_scx_crfuzz")).arg("replay").arg(&f).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = r.id();
    let r = r.wait_with_output().unwrap();
    forget(pid);
    let out = String::from_utf8_lossy(&r.stdout);
    assert_eq!(r.status.code(), Some(3), "{out}");
    assert!(out.contains("\nconfirmed: Violation\n"), "{out}");

    let fixed = campaign(&d.join("fixed"), &["--seeds", "4", "--jobs", "4", "--private", a_s], &[sut_s, p_s, "nofollow"], &m, &layout, 0);
    assert_eq!(line(&fixed, "findings: "), "0", "{fixed}");
    fs::remove_dir_all(d).unwrap();
}
