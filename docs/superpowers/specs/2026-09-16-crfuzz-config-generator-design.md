# `scx_crfuzz_gen`: a standalone scenario config generator

Status: approved design, not yet implemented.

## Motivation

Every `scx_crfuzz` scenario config today is hand-written. `scenarios/race_wins.json` and `scenarios/race_loses.json` share roughly 80% of their content (`roles[]`, `checkpoints[]`, `cgroup`), and every new target requires manually declaring which syscalls matter for it. That's fine for one synthetic scenario; it doesn't scale to new targets, and the design doc's own "mutator" (section 6.1) already anticipates a separate, upstream piece that produces a `ScenarioConfig` — it was scaffolded as an explicit seam and deliberately left unimplemented (`lib.rs`'s "Seams" section, `README.md`'s status table).

This spec covers building that piece: a tool that observes a target's real behavior and generates a discovery-mode `ScenarioConfig`, without changing the engine.

## Goals

- Generate `roles[]` and `checkpoints[]` for a target from real observed behavior, not hand-authored declarations.
- Stay general across arbitrary processes — not container-specific. A container runtime is one target this tool can be pointed at, not a special case it's built around.
- Zero changes to the `scx_crfuzz` engine crate. The generator is a separate, standalone tool.
- Produce output that is schema-valid by construction, not by convention.

## Non-goals

- Discovering `steps[]` (replay schedules). The generator only emits discovery-mode configs (`policy` block); a replay schedule already has a mechanism — `--project-schedule`, turning a discovery run's canonical log into `steps[]` — and duplicating that here would be redundant, not additive.
- Pool (`cardinality: pool`) role inference. Tracing one instance of a command gives no basis for inferring "N of these can exist concurrently"; pool roles remain a manual edit.
- Static/spec-based path discovery (e.g. reading an OCI bundle's `config.json` for mounts). That's container-specific and directly opposed to the portability goal.
- Any new mode on `CheckpointBackend` or other engine-crate change. Considered and rejected — see "Rejected approach" below.

## Rejected approach: engine reconnaissance mode

The most *accurate* discovery mechanism would be a passive "observe, don't hold" mode added to `SeccompNotifyBackend`/`CheckpointBackend`, reused by the generator — guaranteed checkpoint-naming consistency with the real enforcement path, since it would be the same instrumentation. This was rejected because it requires extending the engine crate's interface, which conflicts with the explicit requirement to keep the engine unchanged. The chosen approach (below) accepts a small, well-understood gap instead: syscall names are the same string in `strace` output and in the engine's `CheckpointDecl.target` field, so the "two implementations must agree" risk is a trivial string-matching concern, not a semantic one.

## Architecture

A new crate, `scx_crfuzz_gen`, alongside `scx_crfuzz` under `scheds/experimental/`.

**Dependency direction:** `scx_crfuzz_gen` depends on `scx_crfuzz` as a library, but only for config types — `ScenarioConfig`, `RoleDecl`, `CheckpointDecl`, `PolicyDecl`, and `checkpoint::default_discovery_checkpoints()`. It never touches `Engine`, `CheckpointBackend`, or `DecisionPolicy`. This is a one-way, compile-time-only dependency: the generator builds the same typed struct the engine parses and calls the engine's own `ScenarioConfig::to_json()`, so it cannot produce a config that's shaped wrong — but `scx_crfuzz` itself has zero lines changed and no awareness the generator exists.

**Portability seam.** Because generality across arbitrary processes (not just containers) is a stated requirement, the tracing mechanism sits behind one trait:

```rust
trait ProcessTracer {
    fn trace(&self, cmd: &str) -> Result<Vec<PathEvent>>;
}

struct PathEvent {
    syscall: String,
    path: String,
}
```

One implementation exists for now: `StraceTracer`. This is the minimum seam that lets a future tracer (ptrace directly, or something else) be swapped in without touching role/checkpoint derivation or output assembly, which are written against `Vec<PathEvent>`, not against `strace`.

## Tracing pipeline

Input: one traced command per role, given on the CLI — mirroring how `run.sh` already spawns each role via `--spawn`:

```
--role victim:"./victim /tmp/crfuzz/target"
--role racer:"./racer /tmp/crfuzz/evil /tmp/crfuzz/target"
```

For each role, `StraceTracer::trace` runs:

```
strace -f -e trace=<syscall-set> -o <tmpfile> -- <cmd>
```

`<syscall-set>` is exactly the syscall names present in `scx_crfuzz::checkpoint::default_discovery_checkpoints()` — reusing the engine's own §4.2 structural set as the definition of "path-touching," rather than re-deriving an independent list. The trace output is parsed into `PathEvent { syscall, path }` per role. The role's `comm` is captured from the traced process's own `execve` argv0 basename — the same value that ends up in `/proc/pid/comm` at run time, matching what `RoleDecl.comm` expects at match time.

## Derivation

Once every role has been traced:

1. **Roles.** One `RoleDecl::one(role_name, observed_comm)` per `--role` entry.
2. **Checkpoints — the contention filter.** Group all `PathEvent`s across all roles by `path`. Keep only paths touched by two or more distinct roles. For each surviving `(syscall, path)` pair, emit one `CheckpointDecl { id: syscall_name, kind: Syscall, target: syscall_name, category }`, with `category` looked up in `scx_crfuzz::checkpoint::STRUCTURAL_SYSCALLS` (`pub const &[(&str, PathCategory)]`) — the same table `default_discovery_checkpoints()` itself builds from, so no separate syscall→category mapping is maintained by the generator. This is deliberately narrower than the generic structural default: it's evidence that *this specific pair of roles* contends on the same path, which is the actual signature of a race candidate — not a guess.
3. **Policy.** A fixed default (`ordered_walk`), with `seed` from a `--seed` flag (default `42`).
4. **`scenario_id` / `cgroup`.** CLI flags, no inference — there's no behavioral signal to derive these from.

## CLI

```
crfuzz_gen \
  --scenario-id toctou-rename-swap \
  --cgroup /crfuzz \
  --role victim:"./victim /tmp/crfuzz/target" \
  --role racer:"./racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
  --seed 42 \
  -o scenarios/generated.json
```

Output is `ScenarioConfig::to_json()`, written to `-o` (stdout if omitted) — the same serializer the engine uses for its own config round-tripping. No hand-formatted JSON text anywhere in the generator; it only ever builds the typed struct.

## Error handling

If the contention filter finds zero shared paths across all traced roles, that is a reportable outcome, not something to paper over: the tool exits non-zero with a message naming which roles were traced and that no shared paths were found. Emitting a checkpoint-less config that would trivially find nothing is worse than failing loudly.

## Testing

- **Derivation unit tests** against hand-written `PathEvent` fixtures — no real `strace` invocation needed. This covers the interesting logic: the contention filter, comm capture, category assignment.
- **One Linux-gated integration test** (`#[cfg(target_os = "linux")]`, same gating convention as the engine's own seccomp tests): run `crfuzz_gen` against the existing `scenarios/victim.c` / `racer.c` pair and assert the generated `checkpoints[]` matches what `race_wins.json` hand-declares today (`newfstatat`, `openat`, `renameat`) — using the existing hand-written scenario as ground truth for the generator, closing the loop between the two.
- **A thin smoke test for `StraceTracer`** — does it invoke `strace` and parse *something* — not exhaustive coverage; the tracer-agnostic derivation logic above is where real coverage should live.

## Open questions carried forward

- Whether `strace`'s path-argument extraction needs special handling for syscalls that take a dirfd + relative path (`openat`, `renameat`, `newfstatat` all do) versus an absolute path — `strace -f` renders both, but resolving a relative path to something comparable across roles (for the contention filter) needs the dirfd's own path, which `strace` reports but the parser has to thread through.
- Whether a role's comm should be captured from the *first* `execve` only, or needs to handle a role command that itself execs into something else (a wrapper script calling the real binary) — the current design assumes the traced command execs directly into the binary being profiled.
