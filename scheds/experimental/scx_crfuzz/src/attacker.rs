// SPDX-License-Identifier: GPL-2.0
//
// The attacker runner: the engine's side of invoking a user-authored attacker
// inside the selected window (attacker brainstorm, "the attacker and the oracle are
// separate"; attacker.md).
//
// In this orchestration the attacker is *not* a held role. The victim is frozen
// at the use-syscall's entry, so the attacker cannot lose the race (attacker.md,
// "The attacker never loses the race"); the engine simply runs the attacker to
// completion and only then releases the victim. Keeping it an external program
// -- rather than an in-engine hook -- is what lets an attacker perform real
// filesystem syscalls (symlink swap, `renameat2(RENAME_EXCHANGE)`, mount-over)
// in the victim's own filesystem view, and lets a user add a new known-CVE
// attack as a small program without recompiling the engine.
//
// The path the victim's syscall resolved is substituted into the attacker's
// argv wherever the `{path}` token appears, and exported as
// `CRFUZZ_TARGET_PATH`; the checkpoint name is exported as `CRFUZZ_CHECKPOINT`.
// Setup (planting the evil symlink, the secret file) happens ahead of the run,
// not here (attacker.md, "Setup happens ahead of time").
//
// `std::process` is portable, so the runner and its argv/env construction test
// on any host; only the seccomp path-capture that produces the path is
// Linux-only.

use crate::config::AttackDecl;
use std::path::Path;
use std::process::Command;

/// The token in an attacker's argv replaced by the captured path.
pub const PATH_TOKEN: &str = "{path}";

/// How an attacker invocation turned out.
///
/// A non-zero exit or a failure to spawn is an attacker *primitive* failure
/// (attacker brainstorm's ACTION-FAILED, e.g. `EPERM`/`EROFS`), a setup
/// problem -- never a finding, and never a lost race, which is impossible here.
/// The engine logs it and carries on; only the oracle produces findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackOutcome {
    /// The attacker ran and exited with this code (`None` if killed by a
    /// signal).
    Ran { code: Option<i32> },
    /// The attacker could not be spawned at all (bad path, not executable).
    Failed { error: String },
}

/// Build the concrete argv for one window from the template and the path.
pub fn build_argv(spec: &AttackDecl, path: Option<&Path>) -> Vec<String> {
    let path = path.map(|p| p.to_string_lossy()).unwrap_or_default();
    spec.argv
        .iter()
        .map(|a| a.replace(PATH_TOKEN, &path))
        .collect()
}

/// Run the attacker for one window and wait for it to finish.
///
/// The victim stays frozen for the whole of this call, so ordering is not a
/// concern -- only whether the primitive succeeded.
pub fn run(spec: &AttackDecl, checkpoint: &str, path: Option<&Path>) -> AttackOutcome {
    let argv = build_argv(spec, path);
    if argv.is_empty() {
        return AttackOutcome::Failed {
            error: "attacker argv is empty".to_string(),
        };
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.env("CRFUZZ_CHECKPOINT", checkpoint);
    if let Some(p) = path {
        cmd.env("CRFUZZ_TARGET_PATH", p);
    }

    match cmd.status() {
        Ok(status) => AttackOutcome::Ran {
            code: status.code(),
        },
        Err(e) => AttackOutcome::Failed {
            error: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(argv: &[&str]) -> AttackDecl {
        AttackDecl {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            at: None,
        }
    }

    #[test]
    fn the_path_token_is_substituted_everywhere_it_appears() {
        let s = spec(&["/bin/racer", "--target", "{path}", "--also={path}"]);
        let argv = build_argv(&s, Some(&PathBuf::from("/tmp/evil")));
        assert_eq!(
            argv,
            vec!["/bin/racer", "--target", "/tmp/evil", "--also=/tmp/evil"]
        );
    }

    #[test]
    fn a_missing_path_substitutes_empty_rather_than_leaving_the_token() {
        let s = spec(&["/bin/racer", "{path}"]);
        let argv = build_argv(&s, None);
        assert_eq!(argv, vec!["/bin/racer", ""]);
    }

    #[test]
    fn args_without_the_token_pass_through_unchanged() {
        let s = spec(&["/bin/racer", "--flag"]);
        assert_eq!(
            build_argv(&s, Some(&PathBuf::from("/p"))),
            vec!["/bin/racer", "--flag"]
        );
    }

    #[test]
    fn a_zero_exit_attacker_is_a_succeeded_run() {
        // `true` exists on every unix host the suite runs on.
        let out = run(&spec(&["true"]), "openat", Some(&PathBuf::from("/tmp/x")));
        assert_eq!(out, AttackOutcome::Ran { code: Some(0) });
    }

    #[test]
    fn a_non_zero_exit_is_a_run_that_did_not_succeed() {
        let out = run(&spec(&["false"]), "openat", None);
        assert!(matches!(out, AttackOutcome::Ran { code: Some(c) } if c != 0));
    }

    #[test]
    fn an_unspawnable_attacker_reports_failed_not_a_finding() {
        let out = run(&spec(&["/nonexistent/attacker/binary"]), "openat", None);
        assert!(matches!(out, AttackOutcome::Failed { .. }));
    }

    #[test]
    fn an_empty_argv_fails_rather_than_panicking() {
        let out = run(&spec(&[]), "openat", None);
        assert!(matches!(out, AttackOutcome::Failed { .. }));
    }
}
