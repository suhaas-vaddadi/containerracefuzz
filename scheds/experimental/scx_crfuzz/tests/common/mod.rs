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
