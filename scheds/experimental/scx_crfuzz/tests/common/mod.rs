// SPDX-License-Identifier: GPL-2.0
//
// Helpers shared by the Linux integration tests. Each test binary uses a
// different subset, hence the allow.
#![allow(dead_code)]

use std::path::PathBuf;

/// Whether to skip `test` for lack of root, which the seccomp listener and the
/// `sched_ext` gate require. Skipping rather than failing keeps a plain
/// `cargo test` green; the VM runs these under sudo.
pub fn skip_unless_root(test: &str) -> bool {
    // SAFETY: getuid is always safe.
    if unsafe { libc::getuid() } == 0 {
        return false;
    }
    eprintln!("skipping {test}: needs root");
    true
}

/// The scenario fixtures (`make -C scenarios` builds them).
pub fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scenarios")
}

/// A live task's thread group, from `/proc/<pid>/status`.
pub fn tgid_of(pid: i32) -> i32 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("the task is live")
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
        .expect("a Tgid line")
}

/// Abort the test binary if it is still running after `d`: a poll that
/// waits forever would otherwise hang the suite.
pub fn abort_after(d: std::time::Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(d);
        eprintln!("still running after {d:?}: a blocking poll never woke");
        std::process::abort();
    });
}
