// SPDX-License-Identifier: GPL-2.0
//
// Key capture (plan `plans/2026-10-01-crfuzz-pos-policy.md`, Phase 1).
//
// The host-side conflict-key algebra is unit-tested in `src/event.rs`; what it
// cannot test is `capture_keys`, which walks the target's `/proc` and therefore
// needs a real Linux process. This test holds a real `openat` and checks that
// the captured resolution key separates two independent paths.
//
// The first cut populates the token to the leaf only (plan Decision #1), so an
// *ancestor* swap is deliberately not distinguishable here; that is the
// follow-up the `FileToken::chain` field exists for.
//
// Requires root (the seccomp listener fd is privileged) and Linux.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::event::keys_conflict;
use scx_crfuzz::event::ConflictKey;
use scx_crfuzz::event::Direction;
use scx_crfuzz::event::FileToken;
use scx_crfuzz::event::Token;
use std::time::Duration;
use std::time::Instant;

mod common;
use common::*;

#[test]
fn an_openat_hit_carries_a_resolution_key_that_separates_independent_paths() {
    if skip_unless_root("an_openat_hit_carries_a_resolution_key_that_separates_independent_paths") {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("associate");
    let second = dir.path().join("brother");
    std::fs::write(&first, b"a").expect("write first");
    std::fs::write(&second, b"b").expect("write second");

    let spec = ProcessSpec::parse(&format!(
        "/bin/cat {} {}",
        first.display(),
        second.display()
    ))
    .expect("spec");
    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/keycapture");
    backend
        .attach(&[CheckpointDecl::syscall("openat")])
        .expect("attach");

    let first_s = first.to_string_lossy().to_string();
    let second_s = second.to_string_lossy().to_string();
    let mut first_keys: Option<Vec<ConflictKey>> = None;
    let mut second_keys: Option<Vec<ConflictKey>> = None;

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match backend.poll(Some(Duration::from_millis(50))).expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {}
            Poll::Events(events) => {
                for event in events {
                    if let BackendEvent::CheckpointHit {
                        path, keys, handle, ..
                    } = event
                    {
                        if let Some(p) = &path {
                            let p = p.to_string_lossy();
                            if p == first_s {
                                first_keys = Some(keys.clone());
                            } else if p == second_s {
                                second_keys = Some(keys.clone());
                            }
                        }
                        backend.release(handle).expect("release");
                    }
                }
            }
        }
    }

    let a = first_keys.expect("the first openat was captured");
    let b = second_keys.expect("the second openat was captured");
    assert_eq!(a.len(), 1, "one path argument yields one key");
    assert_eq!(b.len(), 1);
    assert!(
        !a[0].is_rebind(),
        "cat opens read-only: no O_CREAT/O_TRUNC, so its key is a resolve"
    );
    assert_ne!(
        a, b,
        "two independent paths must yield different resolution keys, not the \
         same resolved-object key"
    );
}

#[test]
fn a_captured_chain_lets_an_ancestor_rebind_conflict() {
    if skip_unless_root("a_captured_chain_lets_an_ancestor_rebind_conflict") {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("a");
    let b = a.join("b");
    std::fs::create_dir_all(&b).expect("mkdir");
    let file = b.join("file");
    std::fs::write(&file, b"x").expect("write");

    let spec = ProcessSpec::parse(&format!("/bin/cat {}", file.display())).expect("spec");
    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/keycapture-chain");
    backend
        .attach(&[CheckpointDecl::syscall("openat")])
        .expect("attach");

    let target = file.to_string_lossy().to_string();
    let mut victim: Option<Vec<ConflictKey>> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match backend.poll(Some(Duration::from_millis(50))).expect("poll") {
            Poll::Closed => break,
            Poll::Idle => {}
            Poll::Events(events) => {
                for event in events {
                    if let BackendEvent::CheckpointHit {
                        path, keys, handle, ..
                    } = event
                    {
                        if path
                            .as_deref()
                            .map(|p| p.to_string_lossy() == target)
                            .unwrap_or(false)
                        {
                            victim = Some(keys.clone());
                        }
                        backend.release(handle).expect("release");
                    }
                }
            }
        }
    }

    let victim = victim.expect("the openat of the nested file was captured");
    let Token::File(token) = &victim[0].obj.token;
    let names: Vec<String> = token
        .chain
        .iter()
        .map(|c| String::from_utf8_lossy(&c.name).into_owned())
        .collect();
    assert_eq!(names.last().map(String::as_str), Some("file"), "{names:?}");
    assert!(
        names.contains(&"b".to_string()) && names.contains(&"a".to_string()),
        "the chain must carry the full prefix, not just the leaf: {names:?}"
    );

    // The attacker rebinds the ancestor `b`; the victim resolved `/a/b/file`.
    // Their keys must conflict, which leaf-only keying could not do.
    let idx = token
        .chain
        .iter()
        .position(|c| c.name == b"b")
        .expect("the ancestor is in the chain");
    let ancestor = FileToken::new(
        token.anchor_dev,
        token.anchor_ino,
        token.chain[..=idx].to_vec(),
    );
    let rebind = ConflictKey::file(ancestor, Direction::Rebind);
    assert!(
        keys_conflict(&victim, std::slice::from_ref(&rebind)),
        "an ancestor rebind must conflict with the nested path"
    );
}
