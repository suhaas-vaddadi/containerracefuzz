// SPDX-License-Identifier: GPL-2.0
//
//! Does the container's own seccomp profile silently erase our checkpoints?
//!
//! Seccomp filters stack: installing one never removes another, every filter
//! runs on every syscall, and the kernel takes the most restrictive action any
//! of them returned. The precedence order is
//!
//! ```text
//! KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW
//! ```
//!
//! `USER_NOTIF` -- this engine's entire holding mechanism -- sits low on that
//! list. `ERRNO` beats it. So when a bundle carries a `linux.seccomp` block
//! that denies a syscall we hold at, runc installs that filter in the container
//! init before `exec`ing the entrypoint, and from then on our checkpoint simply
//! does not fire. Measured: a fixture that added `openat -> ERRNO` to itself
//! dropped the engine from 5 observed `openat` checkpoints to 4, with no error,
//! no warning and no failed release.
//!
//! That silence is the whole problem. The erased checkpoint's windows never
//! appear in the dry run, so the sweep never attacks them and reports "no
//! escape" over a space quietly smaller than it appears. That is worse than a
//! refusal to start, which is what this module produces instead.
//!
//! **This lives in the binary, not the library.** The crate docs are explicit
//! that the mutator is upstream and "the engine never learns what OCI is"; a
//! preflight check on a bundle is harness work, like `--spawn` and
//! `--cgroup-path`, so it sits beside them rather than inside the engine.
//!
//! ## Why this compares numbers rather than names
//!
//! A string comparison produces false alarms. Against a real resolved profile
//! from a running container, the only structural syscall that appeared to be
//! denied was `fstatat` -- and `fstatat` is not a syscall on aarch64 at all.
//! The profile lists `newfstatat`, which is the same thing under the name the
//! architecture actually uses. libseccomp resolves `fstatat` to -1 and
//! `newfstatat` to 79.
//!
//! libseccomp reports two distinct failures here and both have to be caught.
//! A name it does not know at all -- `fstatat` on aarch64 -- comes back as an
//! error. A name it knows but that the running architecture does not have
//! comes back *successfully*, as a negative pseudo-number: `stat`, `lstat`,
//! `access`, `readlink`, `rename`, `symlink`, `unlink`, `mknod` and `umount`
//! all land there on aarch64, which has only the `*at` variants. A checkpoint
//! on any of them can never fire regardless of any profile, so reporting it as
//! "masked by the profile" would be blaming the wrong thing.

use anyhow::Context;
use anyhow::Result;
use libseccomp::ScmpSyscall;
use scx_crfuzz::checkpoint::CheckpointDecl;
use serde::Deserialize;
use std::collections::HashMap;

/// One checkpoint the profile would erase, or conditionally erase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Masked {
    pub checkpoint: String,
    pub syscall: String,
    pub action: String,
    /// Why this could not be decided outright, if it could not.
    pub caveat: Option<String>,
}

/// What a bundle's profile does to the configured checkpoints.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub profile_present: bool,
    /// Checkpoints the profile erases. A run configured this way cannot do what
    /// it claims, so the caller should refuse rather than proceed.
    pub masked: Vec<Masked>,
    /// Checkpoints that survive under some arguments and not others, or that
    /// the profile also claims with its own notification listener. Not decidable
    /// statically, so reported rather than enforced.
    pub conditional: Vec<Masked>,
    /// Checkpoints naming a syscall this architecture does not have. Nothing to
    /// do with the profile, but worth saying out loud, because such a checkpoint
    /// can never fire.
    pub absent_on_this_arch: Vec<String>,
}

#[derive(Deserialize)]
struct OciConfig {
    linux: Option<OciLinux>,
}

#[derive(Deserialize)]
struct OciLinux {
    seccomp: Option<OciSeccomp>,
    #[serde(rename = "cgroupsPath")]
    cgroups_path: Option<String>,
}

#[derive(Deserialize)]
struct OciSeccomp {
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(default)]
    syscalls: Vec<OciSyscallGroup>,
}

#[derive(Deserialize)]
struct OciSyscallGroup {
    #[serde(default)]
    names: Vec<String>,
    action: String,
    /// Present when the rule applies only to particular argument values, which
    /// makes the outcome depend on the call rather than the configuration.
    #[serde(default)]
    args: Vec<serde_json::Value>,
}

/// Whether an action wins against `SCMP_ACT_NOTIFY` and so erases a checkpoint.
///
/// The order is the kernel's: `KILL_PROCESS > KILL_THREAD > TRAP > ERRNO >
/// USER_NOTIF > TRACE > LOG > ALLOW`. `TRACE` sits *below* `USER_NOTIF`, so it
/// loses to our notify filter and does not erase a checkpoint; listing it here
/// would refuse a run that would in fact work.
fn outranks_notify(action: &str) -> bool {
    matches!(
        action,
        "SCMP_ACT_KILL_PROCESS"
            | "SCMP_ACT_KILL_THREAD"
            | "SCMP_ACT_KILL"
            | "SCMP_ACT_TRAP"
            | "SCMP_ACT_ERRNO"
    )
}

/// Resolve a syscall name to its number on this architecture, or `None` when
/// the architecture has no such syscall.
///
/// libseccomp reports both cases negatively: -1 for a name it does not know,
/// and a negative pseudo-number for a name that exists in its tables but not on
/// this architecture.
fn syscall_number(name: &str) -> Option<i32> {
    let nr: i32 = ScmpSyscall::from_name(name).ok()?.into();
    (nr >= 0).then_some(nr)
}

/// Check a bundle's `config.json` against the checkpoints a scenario declares.
pub fn check(config_json: &str, checkpoints: &[CheckpointDecl]) -> Result<Report> {
    let cfg: OciConfig =
        serde_json::from_str(config_json).context("parsing the bundle's config.json")?;

    let Some(profile) = cfg.linux.and_then(|l| l.seccomp) else {
        return Ok(Report::default());
    };

    // Later groups win: that is the order runc adds the rules in.
    let mut by_nr: HashMap<i32, (&str, bool)> = HashMap::new();
    for group in &profile.syscalls {
        for name in &group.names {
            if let Some(nr) = syscall_number(name) {
                by_nr.insert(nr, (group.action.as_str(), !group.args.is_empty()));
            }
        }
    }

    let mut report = Report {
        profile_present: true,
        ..Report::default()
    };

    for decl in checkpoints {
        let Some(nr) = syscall_number(&decl.target) else {
            report.absent_on_this_arch.push(decl.target.clone());
            continue;
        };

        let (action, conditional) = by_nr
            .get(&nr)
            .copied()
            .unwrap_or((profile.default_action.as_str(), false));

        let entry = |caveat: Option<&str>| Masked {
            checkpoint: decl.id.as_str().to_string(),
            syscall: decl.target.clone(),
            action: action.to_string(),
            caveat: caveat.map(str::to_string),
        };

        if outranks_notify(action) {
            if conditional {
                report.conditional.push(entry(Some(
                    "only for particular argument values, which cannot be decided here",
                )));
            } else {
                report.masked.push(entry(None));
            }
        } else if action == "SCMP_ACT_NOTIFY" {
            report.conditional.push(entry(Some(
                "the profile installs its own notification listener for this syscall",
            )));
        } else if conditional {
            report.conditional.push(entry(Some(
                "allowed only for particular argument values; other values fall through \
                 to the default action",
            )));
        }
    }

    Ok(report)
}

/// The cgroup runc moves the container into, as `/proc/<pid>/cgroup` spells it.
///
// ponytail: absolute cgroupfs paths only (what ctr and attack_run.sh write);
// add the systemd `slice:prefix:name` form and runc's default when a bundle
// needs them.
pub fn container_cgroup(config_json: &str) -> Result<Option<String>> {
    let cfg: OciConfig =
        serde_json::from_str(config_json).context("parsing the bundle's config.json")?;
    let path = cfg.linux.and_then(|l| l.cgroups_path);
    Ok(match path {
        Some(p) if p.starts_with('/') => Some(p),
        Some(p) => {
            log::warn!(
                "linux.cgroupsPath `{p}` is not an absolute cgroupfs path: tasks in the \
                 container's cgroup are the victim's only by genealogy"
            );
            None
        }
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(target: &str) -> CheckpointDecl {
        CheckpointDecl::syscall(target)
    }

    fn bundle(seccomp: &str) -> String {
        format!(r#"{{ "ociVersion": "1.0.0", "linux": {{ "seccomp": {seccomp} }} }}"#)
    }

    #[test]
    fn the_container_cgroup_is_read_when_absolute() {
        let abs = r#"{ "linux": { "cgroupsPath": "/default/ctr1" } }"#;
        assert_eq!(container_cgroup(abs).unwrap().as_deref(), Some("/default/ctr1"));
        let systemd = r#"{ "linux": { "cgroupsPath": "system.slice:cri:ctr1" } }"#;
        assert_eq!(container_cgroup(systemd).unwrap(), None);
        assert_eq!(container_cgroup(r#"{ "linux": {} }"#).unwrap(), None);
    }

    #[test]
    fn a_bundle_without_a_profile_has_nothing_to_check() {
        let r = check(r#"{ "ociVersion": "1.0.0", "linux": {} }"#, &[cp("openat")]).unwrap();
        assert!(!r.profile_present);
        assert!(r.masked.is_empty());
    }

    #[test]
    fn a_denied_syscall_erases_its_checkpoint() {
        let r = check(
            &bundle(r#"{ "defaultAction": "SCMP_ACT_ERRNO", "syscalls": [] }"#),
            &[cp("openat")],
        )
        .unwrap();
        assert_eq!(
            r.masked.len(),
            1,
            "openat falls through to the default ERRNO"
        );
        assert_eq!(r.masked[0].syscall, "openat");
    }

    #[test]
    fn an_allowed_syscall_keeps_its_checkpoint() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ERRNO",
                     "syscalls": [{ "names": ["openat"], "action": "SCMP_ACT_ALLOW" }] }"#,
            ),
            &[cp("openat")],
        )
        .unwrap();
        assert!(
            r.masked.is_empty(),
            "ALLOW loses to NOTIFY, so we still hold"
        );
        assert!(r.conditional.is_empty());
    }

    #[test]
    fn an_explicit_deny_beats_a_permissive_default() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ALLOW",
                     "syscalls": [{ "names": ["openat"], "action": "SCMP_ACT_ERRNO" }] }"#,
            ),
            &[cp("openat")],
        )
        .unwrap();
        assert_eq!(r.masked.len(), 1);
    }

    #[test]
    fn a_kill_action_erases_a_checkpoint_just_as_errno_does() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ALLOW",
                     "syscalls": [{ "names": ["openat"], "action": "SCMP_ACT_KILL_PROCESS" }] }"#,
            ),
            &[cp("openat")],
        )
        .unwrap();
        assert_eq!(r.masked.len(), 1);
    }

    /// `TRACE` sits *below* `USER_NOTIF` in the kernel's precedence order, so a
    /// profile rule with `TRACE` loses to our notify filter and the checkpoint
    /// still fires. Counting it as an erasure refused runs that would work.
    #[test]
    fn a_trace_action_does_not_erase_a_checkpoint() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ALLOW",
                     "syscalls": [{ "names": ["openat"], "action": "SCMP_ACT_TRACE" }] }"#,
            ),
            &[cp("openat")],
        )
        .unwrap();
        assert!(
            r.masked.is_empty(),
            "USER_NOTIF outranks TRACE, so openat still notifies: {:?}",
            r.masked
        );
        assert!(r.conditional.is_empty(), "{:?}", r.conditional);
    }

    /// The regression that motivated comparing numbers instead of names. A real
    /// profile lists `newfstatat`; a scenario may well declare `fstatat`. On
    /// aarch64 neither the profile's name nor ours is the other's string, and
    /// only one of them is a syscall at all.
    #[test]
    fn a_syscall_this_architecture_does_not_have_is_not_blamed_on_the_profile() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ERRNO",
                     "syscalls": [{ "names": ["newfstatat"], "action": "SCMP_ACT_ALLOW" }] }"#,
            ),
            &[cp("fstatat")],
        )
        .unwrap();
        assert!(
            r.masked.is_empty(),
            "fstatat is not a syscall here, so the profile did not erase it: {:?}",
            r.masked
        );
        assert_eq!(r.absent_on_this_arch, vec!["fstatat".to_string()]);
    }

    /// And the other half: the name the architecture does use must be matched
    /// against the profile by number, not by string.
    #[test]
    fn the_architectures_own_name_for_a_syscall_is_matched() {
        let allowed = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ERRNO",
                     "syscalls": [{ "names": ["newfstatat"], "action": "SCMP_ACT_ALLOW" }] }"#,
            ),
            &[cp("newfstatat")],
        )
        .unwrap();
        assert!(allowed.masked.is_empty());

        let denied = check(
            &bundle(r#"{ "defaultAction": "SCMP_ACT_ERRNO", "syscalls": [] }"#),
            &[cp("newfstatat")],
        )
        .unwrap();
        assert_eq!(denied.masked.len(), 1);
    }

    /// Covers the second of libseccomp's two failure modes: a name it resolves
    /// *successfully* to a negative pseudo-number because this architecture has
    /// no such syscall. Distinct from the `fstatat` case above, which fails to
    /// resolve at all -- and the one that a naive `from_name(..).ok()` would
    /// wave through as a real syscall number.
    ///
    /// Which names these are is architecture-dependent, so the test finds one
    /// rather than hard-coding it.
    #[test]
    fn a_syscall_this_architecture_lacks_but_libseccomp_knows_is_not_blamed_either() {
        let legacy = [
            "stat", "lstat", "access", "readlink", "rename", "symlink", "unlink", "mknod", "umount",
        ];
        let found = legacy.iter().find(|n| {
            ScmpSyscall::from_name(n)
                .map(|s| i32::from(s) < 0)
                .unwrap_or(false)
        });
        let Some(name) = found else {
            eprintln!("skipping: this architecture has every legacy syscall");
            return;
        };

        let r = check(
            &bundle(r#"{ "defaultAction": "SCMP_ACT_ERRNO", "syscalls": [] }"#),
            &[cp(name)],
        )
        .unwrap();
        assert!(
            r.masked.is_empty(),
            "`{name}` is not a syscall on this architecture, so the profile did not \
             erase it: {:?}",
            r.masked
        );
        assert_eq!(r.absent_on_this_arch, vec![name.to_string()]);
    }

    #[test]
    fn an_argument_conditional_rule_is_reported_rather_than_decided() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ERRNO",
                     "syscalls": [{ "names": ["openat"], "action": "SCMP_ACT_ALLOW",
                                    "args": [{ "index": 2, "value": 0,
                                               "op": "SCMP_CMP_EQ" }] }] }"#,
            ),
            &[cp("openat")],
        )
        .unwrap();
        assert!(
            r.masked.is_empty(),
            "not decidable, so not an outright refusal"
        );
        assert_eq!(r.conditional.len(), 1);
        assert!(r.conditional[0].caveat.is_some());
    }

    #[test]
    fn a_profile_with_its_own_listener_is_flagged_as_competing() {
        let r = check(
            &bundle(
                r#"{ "defaultAction": "SCMP_ACT_ALLOW",
                     "syscalls": [{ "names": ["openat"], "action": "SCMP_ACT_NOTIFY" }] }"#,
            ),
            &[cp("openat")],
        )
        .unwrap();
        assert!(r.masked.is_empty());
        assert_eq!(r.conditional.len(), 1);
    }
}
