// SPDX-License-Identifier: GPL-2.0
//
// Fresh conflict keys (spec section 4): an earlier release can rebind a name
// on a parked syscall's path, and the parked syscall then resolves to
// different objects. `recapture` re-walks the parked thread's path from the
// arguments it parked with, so the keys follow the rebind.
//
// Requires root (the seccomp listener fd is privileged) and Linux.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::event::ConflictKey;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

#[test]
fn recapture_follows_a_rename_of_the_parked_path_and_ends_at_the_answer() {
    if skip_unless_root("recapture_follows_a_rename_of_the_parked_path_and_ends_at_the_answer") {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("a")).unwrap();
    let file = dir.path().join("a/file");
    std::fs::write(&file, b"x").unwrap();

    let spec = ProcessSpec::parse(&format!("/bin/cat {}", file.display())).expect("spec");
    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/recapture");
    backend
        .attach(&[CheckpointDecl::syscall("openat")])
        .expect("attach");

    // Release the loader's openats until cat parks on the file.
    let deadline = Instant::now() + Duration::from_secs(30);
    let (handle, keys): (NotifyHandle, Vec<ConflictKey>) = 'parked: loop {
        assert!(Instant::now() < deadline, "cat never opened the file");
        if let Poll::Events(events) = backend.poll(Some(Duration::from_millis(50))).unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit {
                    handle, path, keys, ..
                } = e
                {
                    if path.as_deref() == Some(file.as_path()) {
                        break 'parked (handle, keys);
                    }
                    backend.release(handle).unwrap();
                }
            }
        }
    };

    assert_eq!(
        backend.recapture(handle).unwrap(),
        Some(keys.clone()),
        "nothing moved: the same keys"
    );
    std::fs::rename(dir.path().join("a"), dir.path().join("b")).unwrap();
    let fresh = backend
        .recapture(handle)
        .unwrap()
        .expect("still parked, so still recapturable");
    assert_eq!(fresh.len(), 1);
    assert_ne!(fresh, keys, "the rename moved the parked path: the keys must follow");

    backend.release(handle).unwrap();
    assert_eq!(
        backend.recapture(handle).unwrap(),
        None,
        "an answered notification has nothing to recapture"
    );
}
