# `scx_crfuzz_gen` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `scx_crfuzz_gen`, a standalone crate that traces a pair of role commands with `strace`, derives which syscalls the traced roles contend on, and emits a schema-valid discovery-mode `scx_crfuzz` scenario config — with zero changes to the `scx_crfuzz` engine crate.

**Architecture:** A new crate `scheds/experimental/scx_crfuzz_gen`, depending on `scx_crfuzz` only for its config types (`ScenarioConfig`, `RoleDecl`, `CheckpointDecl`, `STRUCTURAL_SYSCALLS`, etc.). Three layers, each independently testable: pure derivation logic (`derive.rs`, no I/O), a pure `strace` text parser (`tracer.rs`), and a thin I/O wrapper around the real `strace` binary (`tracer.rs`, same file, separate test tier). A CLI (`main.rs`) wires them together and round-trips the generated config through the engine's own `ScenarioConfig::to_json()`/`from_json()` before writing it, so the output is schema-valid by construction.

**Tech Stack:** Rust (edition 2021), `clap` (CLI), `anyhow`/`thiserror` (errors), `tempfile` (strace output capture), the real `strace` binary (Linux, invoked as a subprocess — no library binding).

**Spec:** `docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md`

## Global Constraints

- **Zero changes to `scheds/experimental/scx_crfuzz/src/**`.** Every task in this plan only adds files under `scheds/experimental/scx_crfuzz_gen/` and edits the root `Cargo.toml` workspace member list. If any task seems to need an engine-crate change, stop and flag it rather than making it.
- Every new source file starts with the `SPDX-License-Identifier: GPL-2.0` header, matching every existing file in `scheds/experimental/scx_crfuzz/src/`.
- Checkpoint `category` always comes from `scx_crfuzz::checkpoint::STRUCTURAL_SYSCALLS` — never a second, independently maintained table.
- Generated configs are always discovery-mode (`Mode::Discovery`), policy `OrderedWalk`. Replay-schedule (`steps[]`) generation is explicitly out of scope (spec, "Non-goals").
- Linux-only tests (anything that shells out to the real `strace` binary, or the fixture integration test) are gated `#[cfg(target_os = "linux")]`, matching the convention already used by `scx_crfuzz`'s own seccomp-backend tests.
- **Known deviation from the spec, by design, not oversight:** the spec described capturing a role's `comm` by parsing `execve` out of the trace. This plan instead derives it directly from the `--role name:cmd` command's own `argv[0]` (basename, truncated to 15 bytes — the kernel's own `TASK_COMM_LEN - 1` truncation of `/proc/<pid>/comm`). This is simpler, doesn't require widening the `strace -e trace=...` filter to include `execve`, and is at least as accurate. Task 3 implements this.
- **Known limitation, carried forward, not solved here:** `dirfd`-relative path resolution (spec's "Open questions"). The parser takes the path string exactly as `strace` prints it; it does not resolve a relative path against its `dirfd` via `/proc/<pid>/fd/<dirfd>`. This doesn't block the ground-truth scenario in Task 5 (the traced victim/racer already receive absolute paths as `argv`), but a target that constructs relative paths at a non-cwd `dirfd` would produce path strings the contention filter can't match against each other. Out of scope for this plan.

---

### Task 1: Crate scaffold + pure derivation logic

**Files:**
- Create: `scheds/experimental/scx_crfuzz_gen/Cargo.toml`
- Create: `scheds/experimental/scx_crfuzz_gen/src/lib.rs`
- Create: `scheds/experimental/scx_crfuzz_gen/src/main.rs`
- Create: `scheds/experimental/scx_crfuzz_gen/src/derive.rs`
- Modify: `Cargo.toml:27` (root workspace member list — add the new crate right after `"scheds/experimental/scx_crfuzz"`)

**Interfaces:**
- Consumes: `scx_crfuzz::checkpoint::{CheckpointDecl, CheckpointId, CheckpointKind, PathCategory, STRUCTURAL_SYSCALLS}`, `scx_crfuzz::config::{ScenarioConfig, RoleDecl, DivergencePolicy, Mode, PolicyDecl, PolicyType, PolicyParams}` — all `pub`, already exist, unmodified.
- Produces (for Tasks 2-5):
  - `pub struct PathEvent { pub syscall: String, pub path: String }` (derives `Debug, Clone, PartialEq, Eq`)
  - `pub struct RoleTrace { pub name: String, pub comm: String, pub events: Vec<PathEvent> }` (same derives)
  - `pub enum DeriveError { NoSharedPaths(Vec<String>) }` (derives `Debug, thiserror::Error, PartialEq, Eq`)
  - `pub fn build_config(scenario_id: impl Into<String>, cgroup: impl Into<String>, seed: u64, traces: &[RoleTrace]) -> Result<ScenarioConfig, DeriveError>`

- [ ] **Step 1: Scaffold the crate**

Create `scheds/experimental/scx_crfuzz_gen/Cargo.toml`:

```toml
[package]
name = "scx_crfuzz_gen"
version = "0.1.0"
edition = "2021"
description = "Standalone strace-based scenario config generator for scx_crfuzz."
license = "GPL-2.0-only"

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
scx_crfuzz = { path = "../scx_crfuzz" }
tempfile = "3"
thiserror = "2"
```

Create `scheds/experimental/scx_crfuzz_gen/src/lib.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0
//
// scx_crfuzz_gen: a standalone tool that derives a discovery-mode
// scx_crfuzz scenario config from real traced behavior. Depends on
// scx_crfuzz only for its config types (see the crate's design doc,
// docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md) --
// never for Engine, CheckpointBackend, or DecisionPolicy.

pub mod derive;
```

Create `scheds/experimental/scx_crfuzz_gen/src/main.rs` (placeholder body; Task 4 replaces this):

```rust
// SPDX-License-Identifier: GPL-2.0

fn main() {
    println!("scx_crfuzz_gen: CLI not yet wired up (see Task 4 of the implementation plan)");
}
```

Create an empty `scheds/experimental/scx_crfuzz_gen/src/derive.rs` with just the SPDX header:

```rust
// SPDX-License-Identifier: GPL-2.0
```

In the root `Cargo.toml`, add a new line right after the `scx_crfuzz` member:

```toml
    "scheds/experimental/scx_crfuzz",
    "scheds/experimental/scx_crfuzz_gen",
```

- [ ] **Step 2: Verify the scaffold builds**

Run: `cargo build -p scx_crfuzz_gen`
Expected: builds successfully (the binary prints its placeholder message; not run yet).

- [ ] **Step 3: Write the failing tests for `build_config`**

Replace the contents of `scheds/experimental/scx_crfuzz_gen/src/derive.rs` with:

```rust
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

/// Build a discovery-mode `ScenarioConfig` from a set of role traces.
///
/// Checkpoints come from the contention filter: a path touched by only one
/// role can't be raced, so it contributes nothing. A path touched by two or
/// more roles has every syscall seen on it -- from any role -- turned into a
/// checkpoint, because once a path is a contention candidate, every
/// path-touching syscall against it is potentially the check or the act.
pub fn build_config(
    _scenario_id: impl Into<String>,
    _cgroup: impl Into<String>,
    _seed: u64,
    _traces: &[RoleTrace],
) -> Result<ScenarioConfig, DeriveError> {
    unimplemented!("Task 1, Step 5 of the implementation plan")
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
```

- [ ] **Step 4: Run the tests and confirm they fail**

Run: `cargo test -p scx_crfuzz_gen derive::`
Expected: FAIL — every test panics at runtime with `not implemented: Task 1, Step 5 of the implementation plan` (the function compiles, since `unimplemented!()` type-checks as any return type, but every call panics).

- [ ] **Step 5: Implement `build_config`**

Replace the `unimplemented!()` stub with:

```rust
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
            category: STRUCTURAL_SYSCALLS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, c)| *c),
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
```

Also delete the two leading underscores from the function's parameter names in the signature you just replaced (they were only there so the stub compiled without "unused parameter" warnings).

- [ ] **Step 6: Run the tests again and confirm they pass**

Run: `cargo test -p scx_crfuzz_gen derive::`
Expected: PASS — all 5 tests green.

- [ ] **Step 7: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gen Cargo.toml
git commit -m "$(cat <<'EOF'
scx_crfuzz_gen: scaffold the crate and implement config derivation

Pure logic only: given per-role traces, apply the shared-path contention
filter and build a discovery-mode ScenarioConfig using scx_crfuzz's own
config types. No I/O yet -- tracing lands in the next task.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `strace` output parser (pure)

**Files:**
- Create: `scheds/experimental/scx_crfuzz_gen/src/tracer.rs`
- Modify: `scheds/experimental/scx_crfuzz_gen/src/lib.rs` (add `pub mod tracer;`)

**Interfaces:**
- Consumes: `crate::derive::PathEvent` (Task 1).
- Produces (for Task 3): `pub fn parse_strace_output(text: &str) -> Vec<PathEvent>`.

- [ ] **Step 1: Add the module declaration**

In `scheds/experimental/scx_crfuzz_gen/src/lib.rs`, add below `pub mod derive;`:

```rust
pub mod tracer;
```

- [ ] **Step 2: Write the failing tests**

Create `scheds/experimental/scx_crfuzz_gen/src/tracer.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0
//
// Turns strace(1) output into PathEvents, and (further down this file, in
// Task 3) actually invokes strace against a role's command.

use crate::derive::PathEvent;

/// How many of a syscall's arguments are path-shaped, in the order they
/// appear -- restricted to the syscalls scx_crfuzz's `STRUCTURAL_SYSCALLS`
/// set already declares (design doc section 4.2). `mount`'s third string
/// argument, `filesystemtype`, is deliberately not counted: it names a
/// filesystem driver, not a path.
const PATH_ARG_COUNT: &[(&str, usize)] = &[
    ("stat", 1),
    ("lstat", 1),
    ("fstatat", 1),
    ("newfstatat", 1),
    ("access", 1),
    ("faccessat", 1),
    ("faccessat2", 1),
    ("readlink", 1),
    ("readlinkat", 1),
    ("openat", 1),
    ("rename", 2),
    ("renameat", 2),
    ("renameat2", 2),
    ("symlink", 2),
    ("symlinkat", 2),
    ("unlink", 1),
    ("unlinkat", 1),
    ("mknod", 1),
    ("mknodat", 1),
    ("mount", 2),
    ("umount", 1),
    ("umount2", 1),
];

/// Parse one `strace -f` output file's text into path-touching events.
///
/// Deliberately does not do general syscall-argument parsing: it finds the
/// syscall name at the start of each line, looks up how many of that
/// syscall's arguments are paths, and takes that many double-quoted strings
/// off the line in order. Every syscall in `PATH_ARG_COUNT` has only path
/// arguments among its quoted strings -- none has a free-text quoted
/// argument that isn't a path -- so this is exact for the syscall set in
/// scope, not an approximation of a general parser.
pub fn parse_strace_output(text: &str) -> Vec<PathEvent> {
    let mut events = Vec::new();
    for raw_line in text.lines() {
        // `strace -f` prefixes a line with `[pid NNNN] ` once more than one
        // process/thread is being traced. Strip it; which pid a checkpoint
        // came from doesn't matter here -- only which role's *command* was
        // traced does, and that's a whole separate invocation per role.
        let line = match raw_line.strip_prefix("[pid ") {
            Some(rest) => rest.split_once("] ").map_or(raw_line, |(_, after)| after),
            None => raw_line,
        };

        let Some(paren) = line.find('(') else {
            continue;
        };
        let syscall = line[..paren].trim();
        let Some(&(_, n_paths)) = PATH_ARG_COUNT.iter().find(|(name, _)| *name == syscall) else {
            continue;
        };

        let paths = extract_quoted_strings(&line[paren..]);
        for path in paths.into_iter().take(n_paths) {
            events.push(PathEvent {
                syscall: syscall.to_string(),
                path,
            });
        }
    }
    events
}

/// Extract every double-quoted string from `s`, unescaped. Good enough for
/// strace's own quoting (`\"`, `\\`, `\n`, ...) because we only ever care
/// about the string's content, never about distinguishing e.g. a literal
/// backslash from an escaped one.
fn extract_quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut cur = String::new();
        while let Some(&next) = chars.peek() {
            chars.next();
            match next {
                '"' => break,
                '\\' => {
                    if let Some(&escaped) = chars.peek() {
                        cur.push(escaped);
                        chars.next();
                    }
                }
                other => cur.push(other),
            }
        }
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openat_renameat_and_newfstatat_lines() {
        let text = concat!(
            "newfstatat(AT_FDCWD, \"/tmp/crfuzz/target\", {st_mode=S_IFREG|0644, st_size=7, ...}, AT_SYMLINK_NOFOLLOW) = 0\n",
            "openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY) = 3\n",
            "renameat(AT_FDCWD, \"/tmp/crfuzz/evil\", AT_FDCWD, \"/tmp/crfuzz/target\") = 0\n",
        );
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![
                PathEvent {
                    syscall: "newfstatat".into(),
                    path: "/tmp/crfuzz/target".into()
                },
                PathEvent {
                    syscall: "openat".into(),
                    path: "/tmp/crfuzz/target".into()
                },
                PathEvent {
                    syscall: "renameat".into(),
                    path: "/tmp/crfuzz/evil".into()
                },
                PathEvent {
                    syscall: "renameat".into(),
                    path: "/tmp/crfuzz/target".into()
                },
            ]
        );
    }

    #[test]
    fn pid_prefixed_lines_from_follow_forks_are_still_parsed() {
        let text = "[pid 4821] openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY) = 3\n";
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![PathEvent {
                syscall: "openat".into(),
                path: "/tmp/crfuzz/target".into()
            }]
        );
    }

    #[test]
    fn lines_for_untracked_syscalls_are_ignored() {
        let text = "write(1, \"VERDICT:read=SECRET\\n\", 20) = 20\n";
        assert_eq!(parse_strace_output(text), vec![]);
    }

    #[test]
    fn unfinished_and_resumed_call_lines_do_not_double_count_or_panic() {
        let text = concat!(
            "openat(AT_FDCWD, \"/tmp/crfuzz/target\", O_RDONLY <unfinished ...>\n",
            "<... openat resumed>) = 3\n",
        );
        let events = parse_strace_output(text);
        assert_eq!(
            events,
            vec![PathEvent {
                syscall: "openat".into(),
                path: "/tmp/crfuzz/target".into()
            }]
        );
    }
}
```

- [ ] **Step 3: Run the tests and confirm they pass**

`parse_strace_output` is fully implemented in the file you just wrote — there's no separate red step here, since the function isn't a stub this time. Run: `cargo test -p scx_crfuzz_gen tracer::tests::`
Expected: PASS — all 4 tests green. (If any fails, fix `parse_strace_output` or `extract_quoted_strings` above — don't change the tests to match a wrong implementation.)

- [ ] **Step 4: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gen/src/tracer.rs scheds/experimental/scx_crfuzz_gen/src/lib.rs
git commit -m "$(cat <<'EOF'
scx_crfuzz_gen: parse strace -f output into PathEvents

Positional quoted-string extraction keyed by a syscall's known path-arg
count, not general argument parsing -- exact for the structural syscall
set scx_crfuzz already declares, and unbothered by the <unfinished ...>
/ <... resumed> split strace -f produces for interleaved processes.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `StraceTracer` (real `strace` invocation) + comm derivation

**Files:**
- Modify: `scheds/experimental/scx_crfuzz_gen/src/tracer.rs` (append to the file Task 2 created)

**Interfaces:**
- Consumes: `parse_strace_output` (Task 2), `PATH_ARG_COUNT` (Task 2, same file), `crate::derive::PathEvent` (Task 1).
- Produces (for Tasks 4-5):
  - `pub trait ProcessTracer { fn trace(&self, cmd: &str) -> anyhow::Result<Vec<PathEvent>>; }`
  - `pub struct StraceTracer;` implementing it
  - `pub fn derive_comm(cmd: &str) -> Option<String>`

- [ ] **Step 1: Write the failing tests for `derive_comm`**

Append to `scheds/experimental/scx_crfuzz_gen/src/tracer.rs`, **above** the existing `#[cfg(test)] mod tests` block (Rust doesn't care about order, but keep new non-test code together):

```rust
/// The `comm` a kernel would report for this role's command -- the executed
/// binary's basename, truncated to `TASK_COMM_LEN - 1` (15) bytes the same
/// way the kernel truncates `/proc/<pid>/comm`. Derived from the command
/// itself rather than parsed out of a trace: `execve` isn't in
/// `PATH_ARG_COUNT`, and the traced command's own `argv[0]` already carries
/// this information without widening what gets traced.
pub fn derive_comm(cmd: &str) -> Option<String> {
    unimplemented!("Task 3, Step 2 of the implementation plan: {cmd}")
}
```

Add these tests inside the existing `mod tests` block, alongside the Task 2 tests:

```rust
    #[test]
    fn derive_comm_strips_directory_components() {
        assert_eq!(
            derive_comm("./victim /tmp/crfuzz/target").as_deref(),
            Some("victim")
        );
    }

    #[test]
    fn derive_comm_truncates_to_the_kernel_comm_length() {
        assert_eq!(
            derive_comm("./containerd-shim-runc-v2 --arg").as_deref(),
            Some("containerd-shim")
        );
    }

    #[test]
    fn derive_comm_rejects_an_empty_command() {
        assert_eq!(derive_comm(""), None);
    }
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo test -p scx_crfuzz_gen tracer::tests::derive_comm`
Expected: FAIL — panics with `not implemented: Task 3, Step 2 of the implementation plan: ...`.

- [ ] **Step 3: Implement `derive_comm`**

Replace the stub with:

```rust
pub fn derive_comm(cmd: &str) -> Option<String> {
    let program = cmd.split_whitespace().next()?;
    let base = program.rsplit('/').next().unwrap_or(program);
    Some(base.chars().take(15).collect())
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test -p scx_crfuzz_gen tracer::tests::derive_comm`
Expected: PASS — all 3 tests green.

- [ ] **Step 5: Implement `ProcessTracer` and `StraceTracer`**

No TDD cycle for this step — it shells out to a real binary, so it's covered by the smoke test in Step 6, not a fixture-driven unit test. Append to `scheds/experimental/scx_crfuzz_gen/src/tracer.rs`:

```rust
use anyhow::Context;
use anyhow::Result;
use std::process::Command;

/// Something that can observe a command's path-touching syscalls. One
/// implementation for now (`StraceTracer`); the seam exists so a future
/// tracer (ptrace directly, or something else) can be swapped in without
/// touching `derive::build_config` or the CLI, both of which are written
/// against `Vec<PathEvent>`, never against strace.
pub trait ProcessTracer {
    fn trace(&self, cmd: &str) -> Result<Vec<PathEvent>>;
}

pub struct StraceTracer;

impl ProcessTracer for StraceTracer {
    fn trace(&self, cmd: &str) -> Result<Vec<PathEvent>> {
        let out = tempfile::NamedTempFile::new().context("creating strace output tempfile")?;
        let syscalls: Vec<&str> = PATH_ARG_COUNT.iter().map(|(name, _)| *name).collect();
        let mut words = cmd.split_whitespace();
        let program = words.next().context("empty role command")?;
        let args: Vec<&str> = words.collect();

        let status = Command::new("strace")
            .arg("-f")
            .arg("-e")
            .arg(format!("trace={}", syscalls.join(",")))
            .arg("-o")
            .arg(out.path())
            .arg("--")
            .arg(program)
            .args(&args)
            .status()
            .context("spawning strace -- is it installed?")?;
        if !status.success() {
            anyhow::bail!("strace exited with {status} while tracing `{cmd}`");
        }

        let text =
            std::fs::read_to_string(out.path()).context("reading strace output file")?;
        Ok(parse_strace_output(&text))
    }
}
```

- [ ] **Step 6: Add the Linux-gated smoke test**

Add to the `mod tests` block:

```rust
    #[test]
    #[cfg(target_os = "linux")]
    fn strace_tracer_observes_a_real_openat_call() {
        let events = StraceTracer
            .trace("/bin/cat /etc/hostname")
            .expect("strace must be installed in the VM");
        assert!(
            events.iter().any(|e| e.path == "/etc/hostname"),
            "expected an openat-family event for /etc/hostname, got {events:?}"
        );
    }
```

- [ ] **Step 7: Build, and run the smoke test if on Linux**

Run: `cargo build -p scx_crfuzz_gen`
Expected: builds cleanly on any host (macOS included — `StraceTracer` only fails at *run* time without `strace`, not at compile time).

If you're in the Linux VM: run `cargo test -p scx_crfuzz_gen tracer::tests::strace_tracer` and expect PASS. If you're on macOS, skip this — the test is compiled out by the `#[cfg(target_os = "linux")]` gate, so `cargo test` on macOS won't even see it.

- [ ] **Step 8: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gen/src/tracer.rs
git commit -m "$(cat <<'EOF'
scx_crfuzz_gen: add StraceTracer and comm derivation

ProcessTracer is the seam for a future non-strace tracer. comm comes
from the role command's own argv[0], truncated the way the kernel
truncates /proc/<pid>/comm -- not from parsing execve out of the trace,
which would have required widening the strace -e filter.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: CLI

**Files:**
- Modify: `scheds/experimental/scx_crfuzz_gen/src/main.rs` (replace the Task 1 placeholder)

**Interfaces:**
- Consumes: `scx_crfuzz_gen::derive::{build_config, RoleTrace}` (Task 1), `scx_crfuzz_gen::tracer::{ProcessTracer, StraceTracer, derive_comm}` (Task 3), `scx_crfuzz::config::ScenarioConfig::{to_json, from_json}` (existing engine API).
- Produces: the `crfuzz_gen` binary; `parse_role_arg` is private to `main.rs`, not consumed elsewhere.

- [ ] **Step 1: Write the failing tests for role-argument parsing**

Replace `scheds/experimental/scx_crfuzz_gen/src/main.rs` with:

```rust
// SPDX-License-Identifier: GPL-2.0
//
// CLI entry point. See
// docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md.

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use scx_crfuzz::config::ScenarioConfig;
use scx_crfuzz_gen::derive::build_config;
use scx_crfuzz_gen::derive::RoleTrace;
use scx_crfuzz_gen::tracer::derive_comm;
use scx_crfuzz_gen::tracer::ProcessTracer;
use scx_crfuzz_gen::tracer::StraceTracer;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "crfuzz_gen",
    about = "Generate a discovery-mode scx_crfuzz scenario config from real traced behavior"
)]
struct Args {
    #[arg(long)]
    scenario_id: String,

    #[arg(long)]
    cgroup: String,

    /// `name:command line`, repeatable -- one per role. At least two are
    /// required, since contention needs two roles to contend.
    #[arg(long = "role")]
    role: Vec<String>,

    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Write the generated config here. Defaults to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Split a `--role name:cmd` argument into `(name, cmd)`.
fn parse_role_arg(_s: &str) -> Result<(String, String)> {
    unimplemented!("Task 4, Step 2 of the implementation plan")
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.role.len() < 2 {
        bail!("need at least two `--role name:cmd` entries to find contention between them");
    }

    let tracer = StraceTracer;
    let mut traces = Vec::new();
    for r in &args.role {
        let (name, cmd) = parse_role_arg(r)?;
        let comm =
            derive_comm(&cmd).with_context(|| format!("role `{name}` has an empty command"))?;
        let events = tracer
            .trace(&cmd)
            .with_context(|| format!("tracing role `{name}` (`{cmd}`)"))?;
        traces.push(RoleTrace {
            name,
            comm,
            events,
        });
    }

    let config = build_config(args.scenario_id, args.cgroup, args.seed, &traces)?;

    // Round-trip through the engine's own parser: this is what makes the
    // output schema-valid by construction rather than by convention. The
    // exact validation `scx_crfuzz --config` applies runs here too, before
    // anything is written to disk.
    let json = config.to_json().context("serializing generated config")?;
    ScenarioConfig::from_json(&json)
        .context("generated config failed the engine's own validation -- this is a bug in scx_crfuzz_gen, not in your target")?;

    match args.output {
        Some(path) => std::fs::write(&path, json)
            .with_context(|| format!("writing {}", path.display()))?,
        None => println!("{json}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_role_arg_splits_on_first_colon() {
        let (name, cmd) = parse_role_arg("victim:./victim /tmp/crfuzz/target").unwrap();
        assert_eq!(name, "victim");
        assert_eq!(cmd, "./victim /tmp/crfuzz/target");
    }

    #[test]
    fn parse_role_arg_rejects_a_missing_colon() {
        assert!(parse_role_arg("victim").is_err());
    }

    #[test]
    fn parse_role_arg_rejects_an_empty_command() {
        assert!(parse_role_arg("victim:   ").is_err());
    }

    #[test]
    fn parse_role_arg_rejects_an_empty_name() {
        assert!(parse_role_arg(":./victim").is_err());
    }
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo test -p scx_crfuzz_gen --bin scx_crfuzz_gen parse_role_arg`
Expected: FAIL — panics with `not implemented: Task 4, Step 2 of the implementation plan`.

- [ ] **Step 3: Implement `parse_role_arg`**

Replace the stub with:

```rust
fn parse_role_arg(s: &str) -> Result<(String, String)> {
    let (name, cmd) = s
        .split_once(':')
        .with_context(|| format!("`--role {s}` must be `name:command`"))?;
    if name.is_empty() || cmd.trim().is_empty() {
        bail!("`--role {s}` must be `name:command`, with both non-empty");
    }
    Ok((name.to_string(), cmd.to_string()))
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo test -p scx_crfuzz_gen --bin scx_crfuzz_gen parse_role_arg`
Expected: PASS — all 4 tests green.

- [ ] **Step 5: Verify the whole crate still builds**

Run: `cargo build -p scx_crfuzz_gen`
Expected: builds cleanly. Run `cargo run -p scx_crfuzz_gen -- --help` and confirm clap prints usage listing `--scenario-id`, `--cgroup`, `--role`, `--seed`, `--output`.

- [ ] **Step 6: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gen/src/main.rs
git commit -m "$(cat <<'EOF'
scx_crfuzz_gen: wire up the CLI

Traces each --role command, derives the config, and round-trips it
through ScenarioConfig::to_json()/from_json() before writing -- the
same validation `scx_crfuzz --config` applies, run here first so a
malformed generated config is caught at generation time, not first-run
time.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Integration test against the real `victim`/`racer` fixture

**Files:**
- Create: `scheds/experimental/scx_crfuzz_gen/tests/generate_matches_hand_written_scenario.rs`

**Interfaces:**
- Consumes: `scx_crfuzz_gen::derive::{build_config, RoleTrace}` (Task 1), `scx_crfuzz_gen::tracer::{ProcessTracer, StraceTracer, derive_comm}` (Task 3).
- Produces: nothing further downstream — this is the plan's closing verification task.

This is the test the spec calls for: run the generator's actual pipeline against the *existing, already-built* `scenarios/victim` / `scenarios/racer` binaries, and assert its output checkpoint set matches what `scenarios/race_wins.json` declares by hand today (`newfstatat`, `openat`, `renameat`) — using the hand-written scenario as ground truth.

- [ ] **Step 1: Build the fixture binaries** (prerequisite, not a test step)

This test needs `scheds/experimental/scx_crfuzz/scenarios/victim` and `.../racer` to already exist as compiled binaries. In the Linux VM:

```bash
cd scheds/experimental/scx_crfuzz/scenarios && make
```

- [ ] **Step 2: Write the integration test**

Create `scheds/experimental/scx_crfuzz_gen/tests/generate_matches_hand_written_scenario.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0
//
// Closes the loop between scx_crfuzz_gen and the hand-written scenario it's
// meant to replace the boilerplate of: traces the same victim/racer pair
// scenarios/race_wins.json declares by hand, and checks the generator
// arrives at the same checkpoints.
#![cfg(target_os = "linux")]

use scx_crfuzz_gen::derive::build_config;
use scx_crfuzz_gen::derive::RoleTrace;
use scx_crfuzz_gen::tracer::derive_comm;
use scx_crfuzz_gen::tracer::ProcessTracer;
use scx_crfuzz_gen::tracer::StraceTracer;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

/// scheds/experimental/scx_crfuzz/scenarios/race_wins.json declares exactly
/// these three checkpoints by hand. This test's ground truth.
const EXPECTED_CHECKPOINTS: &[&str] = &["newfstatat", "openat", "renameat"];

#[test]
fn generated_checkpoints_match_the_hand_written_race_wins_scenario() {
    let scenarios_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scx_crfuzz/scenarios");
    let victim_bin = scenarios_dir.join("victim");
    let racer_bin = scenarios_dir.join("racer");
    assert!(
        victim_bin.exists() && racer_bin.exists(),
        "build the fixture first: `cd {} && make`",
        scenarios_dir.display()
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    let secret = dir.path().join("secret");
    let evil = dir.path().join("evil");
    std::fs::write(&target, "BENIGN\n").unwrap();
    std::fs::write(&secret, "SECRET\n").unwrap();
    symlink(&secret, &evil).unwrap();

    let victim_cmd = format!("{} {}", victim_bin.display(), target.display());
    let racer_cmd = format!("{} {} {}", racer_bin.display(), evil.display(), target.display());

    let tracer = StraceTracer;
    let traces = vec![
        RoleTrace {
            name: "victim".into(),
            comm: derive_comm(&victim_cmd).unwrap(),
            events: tracer.trace(&victim_cmd).expect("tracing victim"),
        },
        RoleTrace {
            name: "racer".into(),
            comm: derive_comm(&racer_cmd).unwrap(),
            events: tracer.trace(&racer_cmd).expect("tracing racer"),
        },
    ];

    let config = build_config("toctou-rename-swap", "/crfuzz", 42, &traces).unwrap();
    let mut ids: Vec<_> = config
        .checkpoints
        .iter()
        .map(|c| c.id.as_str().to_string())
        .collect();
    ids.sort();
    assert_eq!(ids, EXPECTED_CHECKPOINTS);
}
```

- [ ] **Step 3: Run it**

In the Linux VM, with the fixture binaries built (Step 1) and `strace` installed:

```bash
cargo test -p scx_crfuzz_gen --test generate_matches_hand_written_scenario
```

Expected: PASS. If it fails on the racer's rename event, double check `victim_cmd`/`racer_cmd` are built with the exact same argument order `scenarios/run.sh` uses (`racer <evil> <target>`, not `<target> <evil>`) — see `scheds/experimental/scx_crfuzz/scenarios/racer.c`'s own argv comment.

On macOS: this test is compiled out entirely by `#![cfg(target_os = "linux")]`; `cargo test -p scx_crfuzz_gen` will simply not list it.

- [ ] **Step 4: Run the full crate test suite one more time**

Run: `cargo test -p scx_crfuzz_gen`
Expected: PASS (all of Tasks 1-5's tests; on macOS, the Linux-gated tests from Task 3 and this task are absent rather than failing).

- [ ] **Step 5: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gen/tests
git commit -m "$(cat <<'EOF'
scx_crfuzz_gen: add integration test against the real victim/racer fixture

Traces the same pair scenarios/race_wins.json declares by hand and
checks the generator arrives at the same three checkpoints
(newfstatat, openat, renameat) -- the hand-written scenario as ground
truth for the generator, closing the loop the design doc's mutator
seam left open.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Self-review notes

- **Spec coverage:** Motivation/Goals (Task 1's dependency-direction constraint + Global Constraints); Non-goals (no `steps[]`/pool/OCI-spec code anywhere in this plan; explicitly no engine-crate edits); Architecture (`ProcessTracer` seam in Task 3); Tracing pipeline (Tasks 2-3); Derivation (Task 1, contention filter matches spec's algorithm exactly); CLI (Task 4, same flag names as the spec); Error handling (`DeriveError::NoSharedPaths` in Task 1, surfaced through `main`'s `Result` in Task 4); Testing (all three tiers from the spec's Testing section map 1:1 to Tasks 1/2-3/5). Both "Open questions" are carried forward explicitly in Global Constraints rather than silently dropped.
- **Deviation flagged:** comm capture via `argv[0]` instead of `execve`-trace-parsing — documented in Global Constraints with rationale, not a silent contradiction of the spec.
- **No placeholders** remain in any step's final code — every `unimplemented!()` is a deliberate, temporary TDD red-step scaffold, always followed by a concrete implementation step in the same task.
