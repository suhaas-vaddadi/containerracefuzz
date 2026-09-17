// SPDX-License-Identifier: GPL-2.0
//
// Pure derivation: turn per-role traces into a discovery-mode
// ScenarioConfig. No I/O, no strace -- unit-tested against hand-written
// fixtures. See docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md.

use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use scx_crfuzz::checkpoint::STRUCTURAL_SYSCALLS;
use scx_crfuzz::config::DivergencePolicy;
use scx_crfuzz::config::Mode;
use scx_crfuzz::config::PolicyDecl;
use scx_crfuzz::config::PolicyParams;
use scx_crfuzz::config::PolicyType;
use scx_crfuzz::config::RoleDecl;
use scx_crfuzz::config::ScenarioConfig;
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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeriveError {
    #[error(
        "no path was touched by two or more of the traced roles ({0:?}); nothing to checkpoint"
    )]
    NoSharedPaths(Vec<String>),
}

/// The design doc's table spells this syscall `fstatat`; this crate only
/// ever observes real strace/kernel output, which spells it `newfstatat`
/// (scx_crfuzz::backend_seccomp has a private, non-reusable ARCH_ALIASES
/// hitting the identical mismatch from the other direction). Category
/// still comes from nowhere but STRUCTURAL_SYSCALLS -- this only
/// normalizes the key used to look it up.
const CATEGORY_LOOKUP_ALIASES: &[(&str, &str)] = &[("newfstatat", "fstatat")];

fn structural_category(name: &str) -> Option<scx_crfuzz::checkpoint::PathCategory> {
    let canonical = CATEGORY_LOOKUP_ALIASES
        .iter()
        .find(|(observed, _)| *observed == name)
        .map_or(name, |(_, canonical)| *canonical);
    STRUCTURAL_SYSCALLS
        .iter()
        .find(|(n, _)| *n == canonical)
        .map(|(_, c)| *c)
}

/// Build a discovery-mode `ScenarioConfig` from a set of role traces.
///
/// Checkpoints come from the contention filter: a path touched by only one
/// role can't be raced, so it contributes nothing. A path touched by two or
/// more roles has every syscall seen on it -- from any role -- turned into a
/// checkpoint, because once a path is a contention candidate, every
/// path-touching syscall against it is potentially the check or the act.
pub fn build_config(
    scenario_id: impl Into<String>,
    cgroup: impl Into<String>,
    seed: u64,
    traces: &[RoleTrace],
) -> Result<ScenarioConfig, DeriveError> {
    let roles: Vec<RoleDecl> = traces
        .iter()
        .map(|t| RoleDecl::one(t.name.clone(), t.comm.clone()))
        .collect();

    let mut roles_by_path: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut syscalls_by_path: HashMap<&str, HashSet<&str>> = HashMap::new();
    for trace in traces {
        for event in &trace.events {
            roles_by_path
                .entry(&event.path)
                .or_default()
                .insert(&trace.name);
            syscalls_by_path
                .entry(&event.path)
                .or_default()
                .insert(&event.syscall);
        }
    }

    let mut checkpoint_syscalls: HashSet<&str> = HashSet::new();
    for (path, roles_touching) in &roles_by_path {
        if roles_touching.len() >= 2 {
            if let Some(set) = syscalls_by_path.get(path) {
                checkpoint_syscalls.extend(set.iter().copied());
            }
        }
    }

    if checkpoint_syscalls.is_empty() {
        return Err(DeriveError::NoSharedPaths(
            traces.iter().map(|t| t.name.clone()).collect(),
        ));
    }

    let mut checkpoint_syscalls: Vec<&str> = checkpoint_syscalls.into_iter().collect();
    checkpoint_syscalls.sort_unstable();

    let checkpoints: Vec<CheckpointDecl> = checkpoint_syscalls
        .into_iter()
        .map(|name| CheckpointDecl {
            id: CheckpointId::new(name),
            kind: CheckpointKind::Syscall,
            target: name.to_string(),
            category: structural_category(name),
        })
        .collect();

    Ok(ScenarioConfig {
        scenario_id: scenario_id.into(),
        cgroup: cgroup.into(),
        roles,
        checkpoints,
        on_divergence: DivergencePolicy::Block,
        mode: Mode::Discovery {
            policy: PolicyDecl {
                policy_type: PolicyType::OrderedWalk,
                seed,
                params: PolicyParams::default(),
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
    fn two_roles_sharing_a_path_produce_checkpoints_for_every_syscall_on_that_path() {
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
        assert_eq!(ids, vec!["newfstatat", "openat", "renameat"]);
    }

    #[test]
    fn a_path_touched_by_only_one_role_is_dropped() {
        let victim = trace("victim", vec![("openat", "/tmp/crfuzz/target")]);
        let racer = trace("racer", vec![("renameat", "/tmp/crfuzz/evil")]);
        let err = build_config("s", "/c", 1, &[victim, racer]).unwrap_err();
        assert_eq!(
            err,
            DeriveError::NoSharedPaths(vec!["victim".into(), "racer".into()])
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
    fn checkpoint_category_is_looked_up_from_the_engines_structural_table() {
        let victim = trace("victim", vec![("newfstatat", "/p")]);
        let racer = trace("racer", vec![("newfstatat", "/p")]);
        let cfg = build_config("s", "/c", 1, &[victim, racer]).unwrap();
        assert_eq!(
            cfg.checkpoints[0].category,
            Some(scx_crfuzz::checkpoint::PathCategory::Resolving)
        );
    }

    #[test]
    fn policy_defaults_to_ordered_walk_with_the_given_seed() {
        let victim = trace("victim", vec![("openat", "/p")]);
        let racer = trace("racer", vec![("openat", "/p")]);
        let cfg = build_config("s", "/c", 99, &[victim, racer]).unwrap();
        match cfg.mode {
            Mode::Discovery { policy } => {
                assert_eq!(policy.policy_type, PolicyType::OrderedWalk);
                assert_eq!(policy.seed, 99);
            }
            _ => panic!("expected discovery mode"),
        }
    }
}
