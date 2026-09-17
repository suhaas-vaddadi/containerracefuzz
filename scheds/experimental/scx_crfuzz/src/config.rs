// SPDX-License-Identifier: GPL-2.0
//
// The scenario config schema.
//
// Design doc: section 8 ("Schema changes"), plus Background for the parts the
// base design already specified. Mode selection lives in the config, not in a
// command-line flag, because section 3.1's whole argument is that replay and
// discovery are one engine answering one question two ways -- not two tools.

use crate::checkpoint::default_discovery_checkpoints;
use crate::checkpoint::CheckpointDecl;
use crate::checkpoint::CheckpointId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;

/// Whether a role's `comm` is matched exactly or by substring.
///
/// Exact by default; substring is an explicit opt-in (Background, "Role"),
/// because it is easy to write a substring matcher that quietly captures more
/// processes than intended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommMatch {
    #[default]
    Exact,
    Substring,
}

/// How many thread groups a role declaration admits (design doc section 5).
///
/// Defaults to `One`, so every schedule written against the base design stays
/// valid unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cardinality {
    #[default]
    One,
    /// An open-ended number of thread groups matching one matcher, for the
    /// concurrency-mutation dimension (N concurrent racers, count chosen per
    /// iteration by the mutator).
    Pool,
}

/// One entry of `roles[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDecl {
    pub id: String,
    pub comm: String,
    #[serde(default)]
    pub comm_match: CommMatch,
    #[serde(default)]
    pub cardinality: Cardinality,
    /// Overrides the scenario-wide cgroup for this role. Usually omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
}

impl RoleDecl {
    pub fn one(id: impl Into<String>, comm: impl Into<String>) -> Self {
        RoleDecl {
            id: id.into(),
            comm: comm.into(),
            comm_match: CommMatch::Exact,
            cardinality: Cardinality::One,
            cgroup: None,
        }
    }

    pub fn pool(id: impl Into<String>, comm: impl Into<String>) -> Self {
        RoleDecl {
            cardinality: Cardinality::Pool,
            ..RoleDecl::one(id, comm)
        }
    }

    pub fn with_substring_match(mut self) -> Self {
        self.comm_match = CommMatch::Substring;
        self
    }
}

/// A step's stopping condition: a checkpoint, or "run until the role exits".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopCondition {
    Checkpoint(CheckpointId),
    Exit,
}

impl fmt::Display for StopCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopCondition::Exit => f.write_str("exit"),
            StopCondition::Checkpoint(c) => write!(f, "{c}"),
        }
    }
}

impl From<String> for StopCondition {
    fn from(s: String) -> Self {
        if s == "exit" {
            StopCondition::Exit
        } else {
            StopCondition::Checkpoint(CheckpointId::new(s))
        }
    }
}

impl From<StopCondition> for String {
    fn from(s: StopCondition) -> String {
        s.to_string()
    }
}

impl Serialize for StopCondition {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for StopCondition {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(StopCondition::from(String::deserialize(de)?))
    }
}

/// One entry of a replay schedule's `steps[]`.
///
/// `role` is spelled the way `RoleTable::render` spells it -- `victim`, or
/// `racer#2` for a pool member. This is exactly the pair of fields a canonical
/// log entry carries, which is what makes section 3.5's projection a matter of
/// dropping a field rather than a translation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub role: String,
    pub until: StopCondition,
}

impl Step {
    pub fn new(role: impl Into<String>, until: StopCondition) -> Self {
        Step {
            role: role.into(),
            until,
        }
    }
}

/// Which algorithmic policy a discovery-mode run uses (section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    RandomWalk,
    OrderedWalk,
    Pct,
}

/// Tunables for `PCT`. Ignored by `RandomWalk`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyParams {
    /// Bug depth: the number of ordering constraints PCT assumes a bug needs.
    /// `d - 1` priority-inversion points are placed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<u32>,
    /// Estimated total decision points in the run, used to place the inversion
    /// points along the logical decision index.
    ///
    /// Section 3.4: this is estimated by one throwaway counting run of the same
    /// scenario under `RandomWalk`. Performing that counting run is harness
    /// work, not the engine's -- the engine takes `k` as given. Section 14-I
    /// notes the throughput cost of that extra run is unreconciled against the
    /// project's iterations/hour target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<u64>,
}

/// The `policy` block that replaces `steps[]` in a discovery-mode config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecl {
    #[serde(rename = "type")]
    pub policy_type: PolicyType,
    pub seed: u64,
    #[serde(default)]
    pub params: PolicyParams,
}

/// What happens when a step's condition cannot be satisfied (Background).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergencePolicy {
    /// Keep waiting -- the expected role may still arrive.
    #[default]
    Block,
    /// Advance past the unsatisfiable step and carry on.
    Skip,
    /// End the run with outcome `Diverged`.
    Abort,
}

/// Replay or discovery. Exactly one, never both (section 8).
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Replay { steps: Vec<Step> },
    Discovery { policy: PolicyDecl },
}

/// A parsed, validated scenario config.
///
/// `mode` is an enum rather than two `Option` fields, so a config carrying both
/// `steps[]` and `policy` cannot be represented at all. That mutual exclusion
/// is enforced during deserialization by `TryFrom<RawScenarioConfig>`, not by a
/// check some later caller has to remember to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawScenarioConfig", into = "RawScenarioConfig")]
pub struct ScenarioConfig {
    pub scenario_id: String,
    /// The scenario's execution scope. Roles are only recognised within it, and
    /// tasks outside it are dispatched unmodified.
    pub cgroup: String,
    pub roles: Vec<RoleDecl>,
    /// Always populated after validation: from the config if given, otherwise
    /// from the structural default set for a discovery-mode config.
    pub checkpoints: Vec<CheckpointDecl>,
    pub on_divergence: DivergencePolicy,
    pub mode: Mode,
}

impl ScenarioConfig {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn is_discovery(&self) -> bool {
        matches!(self.mode, Mode::Discovery { .. })
    }

    /// Build a replay config from a projected `steps[]` (section 3.5).
    ///
    /// Everything except the mode is carried over from the discovery-mode
    /// config the log came from, which is what lets the section 10.3 check --
    /// replay the projection, confirm the same outcome -- run against the same
    /// scenario rather than an approximation of it.
    pub fn as_replay_with(&self, steps: Vec<Step>) -> Self {
        ScenarioConfig {
            mode: Mode::Replay { steps },
            ..self.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Deserialization shim: the on-disk shape, plus validation.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawScenarioConfig {
    scenario_id: String,
    cgroup: String,
    roles: Vec<RoleDecl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoints: Option<Vec<CheckpointDecl>>,
    #[serde(default)]
    on_divergence: DivergencePolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    steps: Option<Vec<Step>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyDecl>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error(
        "a config must declare exactly one of `steps` (replay) or `policy` (discovery); found both"
    )]
    BothModes,
    #[error("a config must declare exactly one of `steps` (replay) or `policy` (discovery); found neither")]
    NoMode,
    #[error("`roles` must declare at least one role")]
    NoRoles,
    #[error("duplicate role id `{0}`")]
    DuplicateRole(String),
    #[error("duplicate checkpoint id `{0}`")]
    DuplicateCheckpoint(String),
    #[error("`exit` is a reserved stop condition and cannot be declared as a checkpoint id")]
    ReservedCheckpointId,
    #[error("step {index} names role `{role}`, which is not declared")]
    UnknownStepRole { index: usize, role: String },
    #[error("step {index} names `{role}` with a member index, but `{base}` is not a `pool` role")]
    MemberIndexOnNonPool {
        index: usize,
        role: String,
        base: String,
    },
    #[error("step {index} names pool role `{role}` without a member index; a pool step must say which member (e.g. `{role}#0`)")]
    PoolRoleWithoutMember { index: usize, role: String },
    #[error(
        "step {index} names checkpoint `{checkpoint}`, which is not declared in `checkpoints`"
    )]
    UnknownStepCheckpoint { index: usize, checkpoint: String },
    #[error(
        "policy `pct` requires `params.d` (bug depth) and `params.k` (estimated decision points)"
    )]
    PctMissingParams,
    #[error("policy `pct` requires `params.d` >= 1")]
    PctBadDepth,
}

impl TryFrom<RawScenarioConfig> for ScenarioConfig {
    type Error = ConfigError;

    fn try_from(raw: RawScenarioConfig) -> Result<Self, ConfigError> {
        let mode = match (raw.steps, raw.policy) {
            (Some(_), Some(_)) => return Err(ConfigError::BothModes),
            (None, None) => return Err(ConfigError::NoMode),
            (Some(steps), None) => Mode::Replay { steps },
            (None, Some(policy)) => {
                if policy.policy_type == PolicyType::Pct {
                    let (d, k) = (policy.params.d, policy.params.k);
                    if d.is_none() || k.is_none() {
                        return Err(ConfigError::PctMissingParams);
                    }
                    if d == Some(0) {
                        return Err(ConfigError::PctBadDepth);
                    }
                }
                Mode::Discovery { policy }
            }
        };

        if raw.roles.is_empty() {
            return Err(ConfigError::NoRoles);
        }
        let mut seen_roles = HashSet::new();
        for r in &raw.roles {
            if !seen_roles.insert(r.id.as_str()) {
                return Err(ConfigError::DuplicateRole(r.id.clone()));
            }
        }

        // Section 8: a discovery-mode config defaults to the full structural
        // set rather than making an operator type out every entry. An explicit
        // list always wins, which is how a campaign narrows its overhead
        // (section 4.4). Replay mode gets no default: a hand-authored schedule
        // names the checkpoints it cares about, and silently inventing twenty
        // more would change what the schedule enforces.
        let checkpoints = match (raw.checkpoints, &mode) {
            (Some(c), _) => c,
            (None, Mode::Discovery { .. }) => default_discovery_checkpoints(),
            (None, Mode::Replay { .. }) => Vec::new(),
        };

        let mut seen_cp = HashSet::new();
        for c in &checkpoints {
            if c.id.is_exit() {
                return Err(ConfigError::ReservedCheckpointId);
            }
            if !seen_cp.insert(c.id.as_str()) {
                return Err(ConfigError::DuplicateCheckpoint(c.id.0.clone()));
            }
        }

        if let Mode::Replay { steps } = &mode {
            validate_steps(steps, &raw.roles, &seen_cp)?;
        }

        Ok(ScenarioConfig {
            scenario_id: raw.scenario_id,
            cgroup: raw.cgroup,
            roles: raw.roles,
            checkpoints,
            on_divergence: raw.on_divergence,
            mode,
        })
    }
}

/// Check that every step refers to something that exists.
///
/// Worth doing at parse time rather than at first divergence: a typo'd role or
/// checkpoint name in a hand-authored schedule would otherwise surface as an
/// unsatisfiable step midway through a run, which under the default
/// `on_divergence: block` looks exactly like a scenario that is merely slow.
fn validate_steps(
    steps: &[Step],
    roles: &[RoleDecl],
    checkpoints: &HashSet<&str>,
) -> Result<(), ConfigError> {
    for (index, step) in steps.iter().enumerate() {
        let (base, member) = split_role_ref(&step.role);
        let decl =
            roles
                .iter()
                .find(|r| r.id == base)
                .ok_or_else(|| ConfigError::UnknownStepRole {
                    index,
                    role: step.role.clone(),
                })?;
        match (decl.cardinality, member) {
            (Cardinality::One, Some(_)) => {
                return Err(ConfigError::MemberIndexOnNonPool {
                    index,
                    role: step.role.clone(),
                    base: base.to_string(),
                })
            }
            (Cardinality::Pool, None) => {
                return Err(ConfigError::PoolRoleWithoutMember {
                    index,
                    role: step.role.clone(),
                })
            }
            _ => {}
        }
        if let StopCondition::Checkpoint(c) = &step.until {
            if !checkpoints.contains(c.as_str()) {
                return Err(ConfigError::UnknownStepCheckpoint {
                    index,
                    checkpoint: c.0.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Split `racer#2` into `("racer", Some(2))`, `victim` into `("victim", None)`.
pub fn split_role_ref(s: &str) -> (&str, Option<u32>) {
    match s.rsplit_once('#') {
        Some((base, idx)) => match idx.parse() {
            Ok(n) => (base, Some(n)),
            Err(_) => (s, None),
        },
        None => (s, None),
    }
}

impl From<ScenarioConfig> for RawScenarioConfig {
    fn from(c: ScenarioConfig) -> Self {
        let (steps, policy) = match c.mode {
            Mode::Replay { steps } => (Some(steps), None),
            Mode::Discovery { policy } => (None, Some(policy)),
        };
        RawScenarioConfig {
            scenario_id: c.scenario_id,
            cgroup: c.cgroup,
            roles: c.roles,
            checkpoints: Some(c.checkpoints),
            on_divergence: c.on_divergence,
            steps,
            policy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVERY: &str = r#"{
        "scenario_id": "runc-exec-symlink",
        "cgroup": "/sys/fs/cgroup/crfuzz",
        "roles": [
            { "id": "victim", "comm": "runc" },
            { "id": "racer", "comm": "racer", "cardinality": "pool" }
        ],
        "policy": { "type": "random_walk", "seed": 42 }
    }"#;

    const REPLAY: &str = r#"{
        "scenario_id": "runc-exec-symlink",
        "cgroup": "/sys/fs/cgroup/crfuzz",
        "roles": [{ "id": "victim", "comm": "runc" }],
        "checkpoints": [
            { "id": "pre_mount", "kind": "uprobe", "target": "runc:mount" }
        ],
        "steps": [
            { "role": "victim", "until": "pre_mount" },
            { "role": "victim", "until": "exit" }
        ]
    }"#;

    #[test]
    fn discovery_config_parses_and_selects_discovery_mode() {
        let c = ScenarioConfig::from_json(DISCOVERY).unwrap();
        assert!(c.is_discovery());
        assert_eq!(c.on_divergence, DivergencePolicy::Block, "default is block");
    }

    #[test]
    fn cardinality_defaults_to_one() {
        let c = ScenarioConfig::from_json(DISCOVERY).unwrap();
        assert_eq!(c.roles[0].cardinality, Cardinality::One);
        assert_eq!(c.roles[1].cardinality, Cardinality::Pool);
    }

    #[test]
    fn discovery_mode_populates_the_structural_checkpoint_set_by_default() {
        let c = ScenarioConfig::from_json(DISCOVERY).unwrap();
        assert_eq!(c.checkpoints, default_discovery_checkpoints());
        assert!(c.checkpoints.iter().any(|c| c.id.as_str() == "openat"));
    }

    #[test]
    fn an_explicit_checkpoint_list_overrides_the_default() {
        let narrowed = DISCOVERY.replace(
            r#""policy""#,
            r#""checkpoints": [{ "id": "mount", "kind": "syscall", "target": "mount" }], "policy""#,
        );
        let c = ScenarioConfig::from_json(&narrowed).unwrap();
        assert_eq!(c.checkpoints.len(), 1);
    }

    #[test]
    fn replay_mode_gets_no_default_checkpoint_set() {
        let c = ScenarioConfig::from_json(REPLAY).unwrap();
        assert_eq!(c.checkpoints.len(), 1);
    }

    #[test]
    fn a_config_with_both_steps_and_policy_fails_to_deserialize() {
        let both = REPLAY.replace(
            r#""steps""#,
            r#""policy": { "type": "random_walk", "seed": 1 }, "steps""#,
        );
        let err = ScenarioConfig::from_json(&both).unwrap_err().to_string();
        assert!(err.contains("found both"), "got: {err}");
    }

    #[test]
    fn a_config_with_neither_steps_nor_policy_fails_to_deserialize() {
        let neither = r#"{
            "scenario_id": "x", "cgroup": "/c",
            "roles": [{ "id": "victim", "comm": "runc" }]
        }"#;
        let err = ScenarioConfig::from_json(neither).unwrap_err().to_string();
        assert!(err.contains("found neither"), "got: {err}");
    }

    #[test]
    fn a_step_naming_an_undeclared_checkpoint_is_rejected_at_parse_time() {
        let typo = REPLAY.replace(r#""until": "pre_mount""#, r#""until": "pre_moutn""#);
        let err = ScenarioConfig::from_json(&typo).unwrap_err().to_string();
        assert!(err.contains("pre_moutn"), "got: {err}");
    }

    #[test]
    fn a_step_naming_an_undeclared_role_is_rejected_at_parse_time() {
        let typo = REPLAY.replace(
            r#""role": "victim", "until": "exit""#,
            r#""role": "vitcim", "until": "exit""#,
        );
        let err = ScenarioConfig::from_json(&typo).unwrap_err().to_string();
        assert!(err.contains("vitcim"), "got: {err}");
    }

    #[test]
    fn a_pool_step_must_name_a_member() {
        let cfg = REPLAY.replace(
            r#"{ "id": "victim", "comm": "runc" }"#,
            r#"{ "id": "victim", "comm": "runc", "cardinality": "pool" }"#,
        );
        let err = ScenarioConfig::from_json(&cfg).unwrap_err().to_string();
        assert!(err.contains("without a member index"), "got: {err}");
    }

    #[test]
    fn a_one_role_step_must_not_name_a_member() {
        let cfg = REPLAY.replace(
            r#""role": "victim", "until": "exit""#,
            r#""role": "victim#0", "until": "exit""#,
        );
        let err = ScenarioConfig::from_json(&cfg).unwrap_err().to_string();
        assert!(err.contains("not a `pool` role"), "got: {err}");
    }

    #[test]
    fn pct_requires_both_d_and_k() {
        let missing = DISCOVERY.replace(
            r#"{ "type": "random_walk", "seed": 42 }"#,
            r#"{ "type": "pct", "seed": 42, "params": { "d": 3 } }"#,
        );
        assert!(ScenarioConfig::from_json(&missing).is_err());

        let ok = DISCOVERY.replace(
            r#"{ "type": "random_walk", "seed": 42 }"#,
            r#"{ "type": "pct", "seed": 42, "params": { "d": 3, "k": 200 } }"#,
        );
        assert!(ScenarioConfig::from_json(&ok).is_ok());
    }

    #[test]
    fn ordered_walk_policy_parses() {
        let ow = DISCOVERY.replace(r#""random_walk""#, r#""ordered_walk""#);
        let c = ScenarioConfig::from_json(&ow).unwrap();
        let Mode::Discovery { policy } = &c.mode else {
            panic!("expected discovery mode")
        };
        assert_eq!(policy.policy_type, PolicyType::OrderedWalk);
    }

    #[test]
    fn duplicate_role_ids_are_rejected() {
        let dup = DISCOVERY.replace(r#""id": "racer""#, r#""id": "victim""#);
        let err = ScenarioConfig::from_json(&dup).unwrap_err().to_string();
        assert!(err.contains("duplicate role"), "got: {err}");
    }

    #[test]
    fn exit_cannot_be_declared_as_a_checkpoint_id() {
        let bad = REPLAY.replace(r#""id": "pre_mount""#, r#""id": "exit""#);
        assert!(ScenarioConfig::from_json(&bad).is_err());
    }

    #[test]
    fn config_round_trips_through_json() {
        for src in [DISCOVERY, REPLAY] {
            let c = ScenarioConfig::from_json(src).unwrap();
            let back = ScenarioConfig::from_json(&c.to_json().unwrap()).unwrap();
            assert_eq!(back.mode, c.mode);
            assert_eq!(back.checkpoints, c.checkpoints);
            assert_eq!(back.roles, c.roles);
        }
    }

    #[test]
    fn role_ref_splitting_handles_members_and_stray_hashes() {
        assert_eq!(split_role_ref("victim"), ("victim", None));
        assert_eq!(split_role_ref("racer#2"), ("racer", Some(2)));
        assert_eq!(split_role_ref("weird#name"), ("weird#name", None));
    }
}
