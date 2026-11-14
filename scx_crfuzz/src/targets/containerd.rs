//! The built-in target: containerd -> shim -> runc starting a busybox
//! container from a rootfs alice owns, the embedded mutator at every hold
//! under it. Sets its scenario up in D, then runs the
//! campaign `D/campaign`.

use crate::campaign::{self, Campaign};
use crate::cli::{self, Check};
use anyhow::{ensure, Context, Result};
use scx_crfuzz::oracle::Alice;
use scx_crfuzz::schedule::Config;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Static, so it runs in the held task's view, the container's rootfs included.
const MUTATOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mutator_all"));
const SUT: &str = include_str!("../../targets/containerd/sut.sh");
const LAYOUT: &str = include_str!("../../targets/containerd/layout.sh");

/// `containerd`'s arguments.
pub struct Opts {
    /// The scenario directory D.
    pub dir: String,
    /// The static busybox copied into the rootfs.
    pub image: String,
    /// `UID:GID`: alice, who owns the rootfs.
    pub attacker: String,
    pub seeds: Option<u64>,
    pub time: Option<Duration>,
    pub jobs: usize,
    pub resume: bool,
    pub verbose: bool,
}

/// Whether an ELF64 little-endian image names an interpreter (PT_INTERP):
/// dynamically linked. None: not one.
fn dynamic(elf: &[u8]) -> Option<bool> {
    let u = |o: usize, n: usize| Some(elf.get(o..o.checked_add(n)?)?.iter().rev().fold(0u64, |a, &b| a << 8 | b as u64));
    if elf.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let (off, size) = (u(0x20, 8)?, u(0x36, 2)?);
    for i in 0..u(0x38, 2)? {
        if u(usize::try_from(off.checked_add(i * size)?).ok()?, 4)? == 3 {
            return Some(true);
        }
    }
    Some(false)
}

/// `name` in PATH: a file with an execute bit.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(name)).find(|p| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// The target's own preflight: its programs, and a busybox the container
/// (which holds no libc) can run.
fn checks(busybox: &Path) -> Vec<Check> {
    let missing = || "not on PATH; install it, or keep PATH through sudo (sudo env PATH=$PATH ...)".to_string();
    let mut checks: Vec<Check> = ["containerd", "ctr", "runc"].into_iter().map(|p| (p, on_path(p).map(drop).ok_or_else(missing))).collect();
    let image = match std::fs::read(busybox) {
        Err(e) => Err(format!("{}: {e}; pass --image a static busybox", busybox.display())),
        Ok(elf) => match dynamic(&elf) {
            Some(false) => Ok(()),
            Some(true) => Err(format!("{} is dynamically linked, but the container holds no libc; pass --image a static busybox", busybox.display())),
            None => Err(format!("{} is not an ELF64 executable; pass --image a static busybox", busybox.display())),
        },
    };
    checks.push(("busybox image", image));
    checks
}

/// Recreate D (its parent must exist; refused unless it and its ancestors
/// are root-only, and it is empty or a former D, marked by
/// `.crfuzz-containerd`): `rootfs/` and its pristine `rootfs.orig/`,
/// `mut/mutator_all` (mirrored at the same path inside the rootfs, so the
/// held task's view has it), `sut.sh`, `layout.sh`, `run/` (the daemon's
/// state) and `logs/` (`mutator.log`, writable by alice, and
/// `containerd.log`); then, from D, run the campaign `D/campaign` with the
/// rootfs, `run/`, /run/containerd/s and /run/nri private and the rootfs the
/// scope. `--resume` keeps `campaign/` and `logs/`; without it, a nonempty
/// `campaign/` is refused.
pub fn run(o: Opts) -> Result<i32> {
    let alice = Alice::parse(&o.attacker)?;
    cli::preflight_ok(checks(Path::new(&o.image)))?;
    // Root runs sut.sh and layout.sh from D: D is root's alone, and so
    // is every ancestor, none writable by another user but a sticky
    // one (as /tmp), so none can be swapped. Checked on the canonical
    // parent (no symlink to re-point), before D is created.
    let d = std::path::absolute(&o.dir)?;
    let (parent, name) = d.parent().zip(d.file_name()).with_context(|| format!("--dir {}: not a scratch directory", d.display()))?;
    let parent = std::fs::canonicalize(parent).with_context(|| format!("--dir {}: its parent", d.display()))?;
    for a in parent.ancestors() {
        let m = std::fs::symlink_metadata(a).with_context(|| a.display().to_string())?;
        ensure!(m.uid() == 0 && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0), "--dir {}: {} is not root-only; pass another", d.display(), a.display());
    }
    let d = parent.join(name);
    match std::fs::DirBuilder::new().mode(0o755).create(&d) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e).context(d.display().to_string()),
        _ => {}
    }
    let m = std::fs::symlink_metadata(&d)?;
    ensure!(m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0, "--dir {}: not root-only; pass another", d.display());
    // Only ever a former D is wiped: the marker, written before anything
    // else, says it is one, even after a setup that failed.
    let marker = d.join(".crfuzz-containerd");
    let mut rd = std::fs::read_dir(&d)?.peekable();
    ensure!(rd.peek().is_none() || marker.exists(), "--dir {}: not empty and not a containerd scenario (no {}); pass another", d.display(), marker.display());
    let old = d.join("campaign");
    ensure!(o.resume || std::fs::read_dir(&old).map_or(true, |mut e| e.next().is_none()), "--dir {}: holds a campaign; rerun with --resume, or remove {}", d.display(), old.display());
    std::fs::write(&marker, "")?;
    for e in rd {
        let e = e?;
        if e.path() == marker || o.resume && (e.file_name() == "campaign" || e.file_name() == "logs") {
            continue;
        }
        if e.file_type()?.is_dir() { std::fs::remove_dir_all(e.path()) } else { std::fs::remove_file(e.path()) }.with_context(|| e.path().display().to_string())?;
    }
    let (rootfs, mutator, state) = (d.join("rootfs"), d.join("mut/mutator_all"), d.join("run"));
    let shared = [PathBuf::from("/run/containerd/s"), PathBuf::from("/run/nri")];
    for p in [rootfs.join("bin"), rootfs.join("proc"), rootfs.join("dev"), rootfs.join("tmp"), d.join("mut"), d.join("logs"), state.clone()].iter().chain(&shared) {
        std::fs::create_dir_all(p).with_context(|| p.display().to_string())?;
    }
    // alice's log is hers to write; logs/ stays root's, or she could
    // redirect the SUT's own log into the canary.
    let log = d.join("logs/mutator.log");
    std::fs::File::options().create(true).append(true).open(&log)?;
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o666))?;
    std::fs::copy(&o.image, rootfs.join("bin/busybox")).with_context(|| o.image.clone())?;
    // Also at its own path in the rootfs: the held task's view after pivot_root.
    let mirror = rootfs.join(mutator.strip_prefix("/")?);
    std::fs::create_dir_all(mirror.parent().context("mutator dir")?)?;
    for (p, body) in [(&mutator, MUTATOR), (&mirror, MUTATOR), (&d.join("sut.sh"), SUT.as_bytes()), (&d.join("layout.sh"), LAYOUT.as_bytes())] {
        std::fs::write(p, body).with_context(|| p.display().to_string())?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))?;
    }
    let sh = |c: &mut Command| -> Result<()> {
        let st = c.status().with_context(|| format!("{c:?}"))?;
        ensure!(st.success(), "{c:?}: {st}");
        Ok(())
    };
    sh(Command::new("chown").arg("-R").arg(format!("{}:{}", alice.uid, alice.gid)).arg("--").arg(&rootfs))?;
    // Pristine copy; layout.sh restores the rootfs from it before each run.
    sh(Command::new("cp").arg("-a").arg("--").arg(&rootfs).arg(d.join("rootfs.orig")))?;
    // sut.sh's and layout.sh's inputs; the mutator's scope and log. Other
    // CRFUZZ_* pass through to the mutator. One thread yet: set_var is sound.
    std::env::set_var("CRFUZZ_DIR", &d);
    std::env::set_var("CRFUZZ_ROOTFS", &rootfs);
    std::env::set_var("CRFUZZ_SCOPE", &rootfs);
    std::env::set_var("CRFUZZ_LOG", &log);
    std::env::set_var("CRFUZZ_CONTAINERD", on_path("containerd").context("containerd")?);
    std::env::set_var("CRFUZZ_CTR", on_path("ctr").context("ctr")?);
    // The SUT inherits the cwd: relative paths stay in D.
    std::env::set_current_dir(&d)?;
    println!("scenario: containerd -> shim -> runc startup; busy busybox rootfs owned by {}", o.attacker);
    println!("campaign: {}", d.join("campaign").display());
    let cfg = Config {
        attacker: o.attacker,
        mutator: Some(mutator),
        layout: Some(d.join("layout.sh")),
        timeout: cli::TIMEOUT,
        // Everything the runs write, so --jobs > 1 works.
        private: [rootfs.clone(), state].into_iter().chain(shared).collect(),
        scope: vec![rootfs],
        env: cli::env(),
        cmd: vec![d.join("sut.sh").to_str().context("--dir: not UTF-8")?.into()],
    };
    campaign::run(Campaign { dir: d.join("campaign"), cfg, first: 0, seeds: o.seeds, time: o.time, jobs: o.jobs, resume: o.resume, verbose: o.verbose })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_interp() {
        // A header with one program header at 64 of type `t`.
        let elf = |t: u8| {
            let mut b = vec![0; 120];
            b[..6].copy_from_slice(b"\x7fELF\x02\x01");
            (b[0x20], b[0x36], b[0x38], b[64]) = (64, 56, 1, t);
            b
        };
        assert_eq!([dynamic(&elf(3)), dynamic(&elf(1)), dynamic(&elf(3)[..66]), dynamic(b"#!/bin/sh")], [Some(true), Some(false), None, None]);
    }
}
