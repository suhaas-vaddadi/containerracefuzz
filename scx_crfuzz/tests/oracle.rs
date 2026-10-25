//! The canary (§2). Needs root:
//!   sudo <test-binary> --ignored --test-threads=1 --nocapture
#![cfg(target_os = "linux")]

use scx_crfuzz::oracle::{Canary, Finding};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
#[ignore]
fn canary_snapshot_and_teardown() {
    let c = Canary::create(100).unwrap();
    assert_eq!(fs::metadata(&c.dir).unwrap().permissions().mode() & 0o7777, 0o700, "the gate");
    assert_eq!(fs::read_to_string(c.dir.join("dir/file")).unwrap(), format!("{} dir/file\n", c.token));
    assert!(c.changed().is_empty(), "a fresh snapshot equals `before`");
    fs::set_permissions(c.dir.join("dir/file"), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(c.changed(), [Finding::Changed { entry: "dir/file".into() }]);
    fs::set_permissions(c.dir.join("dir/file"), fs::Permissions::from_mode(0o644)).unwrap();
    let dir = c.dir.clone();
    drop(c);
    assert!(!dir.exists(), "removed on drop");
}

/// A changed canary is never removed: a mount left inside would be emptied.
#[test]
#[ignore]
fn changed_canary_stays() {
    let c = Canary::create(102).unwrap();
    let dir = c.dir.clone();
    fs::write(dir.join("empty/new"), "").unwrap();
    drop(c);
    assert!(dir.join("empty/new").exists(), "left");
    fs::remove_dir_all(dir).unwrap();
}

/// §10.2: kept, the directory outlives the canary.
#[test]
#[ignore]
fn canary_keep() {
    let mut c = Canary::create(101).unwrap();
    let dir = c.dir.clone();
    c.keep();
    drop(c);
    assert!(dir.join("dir/file").exists(), "kept");
    fs::remove_dir_all(dir).unwrap();
}

/// A bind mount from the same filesystem over `empty` keeps every field but
/// the inode: still a change.
#[test]
#[ignore]
fn same_fs_bind_mount_changed() {
    let c = Canary::create(103).unwrap();
    // Beside the canary: the same filesystem, an empty root-owned 0755 dir.
    let src = c.dir.with_extension("src");
    fs::create_dir(&src).unwrap();
    fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();
    let dst = c.dir.join("empty");
    assert!(Command::new("mount").arg("--bind").arg(&src).arg(&dst).status().unwrap().success());
    let changed = c.changed();
    assert!(Command::new("umount").arg(&dst).status().unwrap().success());
    fs::remove_dir(&src).unwrap();
    assert_eq!(changed, [Finding::Changed { entry: "empty".into() }]);
}
