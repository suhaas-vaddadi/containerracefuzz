// SPDX-License-Identifier: GPL-2.0
//
// Pure derivation: turn per-role traces into a discovery-mode
// ScenarioConfig. No I/O, no strace -- unit-tested against hand-written
// fixtures. See docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md.

use anyhow::bail;
use anyhow::Result;
use scx_crfuzz::checkpoint::structural_category;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::PathCategory;
use scx_crfuzz::config::DivergencePolicy;
use scx_crfuzz::config::Mode;
use scx_crfuzz::config::PolicyDecl;
use scx_crfuzz::config::PolicyType;
use scx_crfuzz::config::RoleDecl;
use scx_crfuzz::config::ScenarioConfig;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;

/// One path-touching syscall observed for a role, as reported by a tracer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEvent {
    pub syscall: String,
    pub path: String,
}

/// Everything traced for one `--role name:cmd` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTrace {
    pub name: String,
    pub comm: String,
    pub events: Vec<PathEvent>,
}

/// Build a discovery-mode `ScenarioConfig` from a set of role traces.
///
/// Only use-shaped events count (`PathCategory::Mutating`, design doc
/// section 4.2): a check-shaped syscall is never a checkpoint, and a race
/// always has a use on the contended path, so dropping checks up front loses
/// no contended path.
///
/// Checkpoints then come from the contention filter: a path touched by only
/// one role can't be raced, so it contributes nothing. A path touched by two
/// or more roles has every use-shaped syscall seen on it -- from any role --
/// turned into a checkpoint, since any of them may be the victim's use or the
/// racer's swap.
pub fn build_config(
    scenario_id: impl Into<String>,
    cgroup: impl Into<String>,
    seed: u64,
    traces: &[RoleTrace],
) -> Result<ScenarioConfig> {
    let roles: Vec<RoleDecl> = traces
        .iter()
        .map(|t| RoleDecl::one(t.name.clone(), t.comm.clone()))
        .collect();

    // path -> (roles touching it, use-shaped syscalls seen on it)
    let mut by_path: HashMap<&str, (HashSet<&str>, HashSet<&str>)> = HashMap::new();
    for trace in traces {
        for event in trace
            .events
            .iter()
            .filter(|e| structural_category(&e.syscall) == Some(PathCategory::Mutating))
        {
            let (roles, syscalls) = by_path.entry(&event.path).or_default();
            roles.insert(&trace.name);
            syscalls.insert(&event.syscall);
        }
    }

    // A BTreeSet, so the checkpoints come out sorted.
    let checkpoint_syscalls: BTreeSet<&str> = by_path
        .values()
        .filter(|(roles, _)| roles.len() >= 2)
        .flat_map(|(_, syscalls)| syscalls.iter().copied())
        .collect();

    if checkpoint_syscalls.is_empty() {
        bail!(
            "no path was touched by a use-shaped syscall in two or more of the traced roles ({:?}); nothing to checkpoint",
            traces.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    let checkpoints: Vec<CheckpointDecl> = checkpoint_syscalls
        .into_iter()
        .map(CheckpointDecl::syscall)
        .collect();

    Ok(ScenarioConfig {
        scenario_id: scenario_id.into(),
        cgroup: cgroup.into(),
        roles,
        checkpoints,
        on_divergence: DivergencePolicy::Block,
        attack: None,
        watchdog_cpu_secs: 15,
        mode: Mode::Discovery {
            policy: PolicyDecl {
                policy_type: PolicyType::Pos,
                seed,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(name: &str, events: Vec<(&str, &str)>) -> RoleTrace {
        RoleTrace {
            name: name.to_string(),
            comm: name.to_string(),
            events: events
                .into_iter()
                .map(|(syscall, path)| PathEvent {
                    syscall: syscall.to_string(),
                    path: path.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn two_roles_sharing_a_path_produce_checkpoints_for_its_use_shaped_syscalls_only() {
        let victim = trace(
            "victim",
            vec![
                ("newfstatat", "/tmp/crfuzz/target"),
                ("openat", "/tmp/crfuzz/target"),
            ],
        );
        let racer = trace(
            "racer",
            vec![
                ("renameat", "/tmp/crfuzz/evil"),
                ("renameat", "/tmp/crfuzz/target"),
            ],
        );
        let cfg = build_config("toctou-rename-swap", "/crfuzz", 42, &[victim, racer]).unwrap();
        let mut ids: Vec<_> = cfg
            .checkpoints
            .iter()
            .map(|c| c.id.as_str().to_string())
            .collect();
        ids.sort();
        // The victim's `newfstatat` is its check: seen, but never a checkpoint.
        assert_eq!(ids, vec!["openat", "renameat"]);
    }

    #[test]
    fn a_path_touched_by_only_one_role_is_dropped() {
        let victim = trace("victim", vec![("openat", "/tmp/crfuzz/target")]);
        let racer = trace("racer", vec![("renameat", "/tmp/crfuzz/evil")]);
        let err = build_config("s", "/c", 1, &[victim, racer]).unwrap_err();
        assert!(
            err.to_string().contains("no path was touched"),
            "got: {err}"
        );
    }

    #[test]
    fn roles_are_declared_with_their_observed_comm() {
        let victim = trace("victim", vec![("openat", "/p")]);
        let racer = trace("racer", vec![("renameat", "/p")]);
        let cfg = build_config("s", "/c", 1, &[victim, racer]).unwrap();
        assert_eq!(cfg.roles.len(), 2);
        assert_eq!(cfg.roles[0].id, "victim");
        assert_eq!(cfg.roles[0].comm, "victim");
        assert_eq!(cfg.roles[1].id, "racer");
    }

    #[test]
    fn every_checkpoint_is_tagged_use_shaped() {
        let victim = trace("victim", vec![("openat", "/p")]);
        let racer = trace("racer", vec![("renameat", "/p")]);
        let cfg = build_config("s", "/c", 1, &[victim, racer]).unwrap();
        assert!(cfg
            .checkpoints
            .iter()
            .all(|c| c.category == Some(PathCategory::Mutating)));
    }

    #[test]
    fn a_path_shared_only_through_checks_is_not_contention() {
        let victim = trace("victim", vec![("newfstatat", "/p")]);
        let racer = trace("racer", vec![("readlinkat", "/p")]);
        let err = build_config("s", "/c", 1, &[victim, racer]).unwrap_err();
        assert!(
            err.to_string().contains("no path was touched"),
            "got: {err}"
        );
    }

    #[test]
    fn policy_defaults_to_pos_with_the_given_seed() {
        let victim = trace("victim", vec![("openat", "/p")]);
        let racer = trace("racer", vec![("openat", "/p")]);
        let cfg = build_config("s", "/c", 99, &[victim, racer]).unwrap();
        match cfg.mode {
            Mode::Discovery { policy } => {
                assert_eq!(policy.policy_type, PolicyType::Pos);
                assert_eq!(policy.seed, 99);
            }
            _ => panic!("expected discovery mode"),
        }
    }
}
