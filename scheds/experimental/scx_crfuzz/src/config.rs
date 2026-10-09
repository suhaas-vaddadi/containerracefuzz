// SPDX-License-Identifier: GPL-2.0
//
// The scenario config schema: one victim, the checkpoints it is held at, the
// attacker run inside the selected window, and the oracle's options.

use crate::checkpoint::default_checkpoints;
use crate::checkpoint::CheckpointDecl;
use crate::oracle::OracleDecl;
use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// Whether the victim's `comm` is matched exactly or by substring.
///
/// Exact by default; substring is an explicit opt-in, because it is easy to
/// write a substring matcher that quietly captures more processes than
/// intended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommMatch {
    #[default]
    Exact,
    Substring,
}

/// Which processes are the victim: any thread group in the scenario cgroup
/// whose `comm` matches, plus its threads and descendants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VictimDecl {
    pub comm: String,
    #[serde(default)]
    pub comm_match: CommMatch,
}

/// The external attacker, and the one window it runs in.
///
/// `argv[0]` is the program, executed directly. The token `{path}` in any
/// element is replaced by the path the victim's syscall resolved
/// (`attacker::PATH_TOKEN`); the path is also exported as `CRFUZZ_TARGET_PATH`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackDecl {
    pub argv: Vec<String>,
    /// The window to attack, as `<checkpoint>#<n>`: the victim's nth hit (from
    /// 0) of that checkpoint. `None` is a dry run: no attack, so the oracle
    /// diffs nothing and every window is only listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// A parsed, validated scenario config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioConfig {
    /// The scenario's scope. The victim is only recognised within it, and
    /// tasks outside it are released unmodified.
    pub cgroup: String,
    /// The cgroup runc moves the container into, as `/proc/<pid>/cgroup`
    /// spells it. Every task in it is the victim's, whatever its `comm`:
    /// `runc init` can land there, outside `cgroup`, before its first
    /// checkpoint. `--oci-bundle` fills it from `linux.cgroupsPath`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_cgroup: Option<String>,
    pub victim: VictimDecl,
    /// Defaults to the whole structural set (`checkpoint::STRUCTURAL_SYSCALLS`).
    #[serde(default = "default_checkpoints")]
    pub checkpoints: Vec<CheckpointDecl>,
    pub attack: AttackDecl,
    /// The oracle's options. Empty by default; the object diff always runs.
    #[serde(default)]
    pub oracle: OracleDecl,
}

impl ScenarioConfig {
    pub fn from_json(s: &str) -> Result<Self> {
        let c: ScenarioConfig = serde_json::from_str(s)?;
        if c.attack.argv.is_empty() {
            bail!("`attack.argv` must not be empty");
        }
        let mut seen = HashSet::new();
        for cp in &c.checkpoints {
            if !seen.insert(cp.id.as_str()) {
                bail!("duplicate checkpoint id `{}`", cp.id);
            }
        }
        Ok(c)
    }
}

/// Whether cgroup `path` is `scope` or lies beneath it. A bare prefix test
/// would put `/crfuzz/12` under `/crfuzz/1`.
pub fn under_cgroup(path: &str, scope: &str) -> bool {
    let scope = scope.trim_end_matches('/');
    path == scope || path.starts_with(&format!("{scope}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{
        "cgroup": "/crfuzz",
        "victim": { "comm": "runc", "comm_match": "substring" },
        "attack": { "argv": ["/bin/racer", "{path}"], "at": "mount#3" }
    }"#;

    #[test]
    fn a_config_parses_with_defaults() {
        let c = ScenarioConfig::from_json(CONFIG).unwrap();
        assert_eq!(c.victim.comm_match, CommMatch::Substring);
        assert_eq!(c.attack.at.as_deref(), Some("mount#3"));
        assert_eq!(c.checkpoints, default_checkpoints());
        assert_eq!(c.oracle, OracleDecl::default());
    }

    #[test]
    fn an_empty_attacker_is_rejected() {
        let bad = CONFIG.replace(r#"["/bin/racer", "{path}"]"#, "[]");
        assert!(ScenarioConfig::from_json(&bad).is_err());
    }

    #[test]
    fn duplicate_checkpoint_ids_are_rejected() {
        let dup = CONFIG.replace(
            r#""attack""#,
            r#""checkpoints": [
                { "id": "m", "kind": "syscall", "target": "mount" },
                { "id": "m", "kind": "syscall", "target": "umount2" }
            ], "attack""#,
        );
        let err = ScenarioConfig::from_json(&dup).unwrap_err().to_string();
        assert!(err.contains("duplicate checkpoint"), "got: {err}");
    }

    #[test]
    fn cgroup_scope_stops_at_a_path_boundary() {
        assert!(under_cgroup("/crfuzz/1", "/crfuzz/1"));
        assert!(under_cgroup("/crfuzz/1/ctr", "/crfuzz/1"));
        assert!(under_cgroup("/crfuzz/1", "/crfuzz/"));
        assert!(!under_cgroup("/crfuzz/12", "/crfuzz/1"));
    }
}
