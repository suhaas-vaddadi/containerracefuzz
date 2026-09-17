# scx_crfuzz — ContainerRaceFuzz scheduling engine

A `sched_ext` scheduling engine that enforces a chosen ordering of process
execution against a real, running container lifecycle, so that a TOCTOU race
can be triggered on demand rather than by chance.

One engine, two modes:

- **Replay** enforces a schedule someone already wrote — for *reproducing* a
  known vulnerability (e.g. one of the runc/containerd TOCTOU CVEs).
- **Discovery** has no such schedule and must *decide* which of several roles
  sitting at their own checkpoints moves next, systematically enough that a
  violation gets found rather than hoped for.

They differ in exactly one place — the answer to "what happens next" — which
is why that answer is an interface (`DecisionPolicy`) inside one engine rather
than a second binary. Because both modes write the same canonical log, turning
a discovery finding into a replayable schedule is a field drop, not a
translation step that would itself need validating.

Design: [`docs/sched_replay/design_doc.md`](../../../../docs/sched_replay/design_doc.md).

## Status

| Piece | State |
|---|---|
| Config schema, role resolution, checkpoint set | implemented, tested |
| `DecisionPolicy` + `FixedSchedule` / `RandomWalk` / `PCT` | implemented, tested |
| Barrier → Enforcing → Draining state machine | implemented, tested |
| Canonical log + projection back to `steps[]` | implemented, tested |
| `SeccompNotifyBackend` — holds real processes | implemented, **Linux only**, validated against a synthetic scenario |
| `sched_ext` `struct_ops` backend (`ops.dispatch` gating) | **not implemented** — needed before any multi-threaded target |
| Mutator, racer, oracle, harness, Class B PID-reuse module | out of scope — see "Seams" in the crate docs |

`SeccompNotifyBackend` covers every `syscall` checkpoint, which is the whole of
§4.2's default set, and needs neither eBPF nor a `sched_ext` attach. It holds a
target at a real syscall boundary: the kernel suspends the calling thread and
will not resume it until the engine answers the notification.

**It holds a thread, not a thread group.** Background requires that holding a
role hold every OS thread in it. For a single-threaded target those coincide.
For a Go binary — runc, containerd, the actual targets — they do not: sibling
goroutine threads keep running while one thread sits in a notification. That is
what the `ops.dispatch` half of the base design is for. Until it exists, results
against multi-threaded targets are unsound.

## Build and test

The engine is pure Rust — no `build.rs`, no BPF, no `libbpf`. It builds and
tests anywhere, macOS included:

```bash
cargo test -p scx_crfuzz          # 80 tests, no kernel needed
```

The seccomp backend is behind `#[cfg(target_os = "linux")]`, and its
dependencies behind a target cfg in `Cargo.toml`, so none of it reaches the host
build. Inside the VM (see `docs/environment/SCHED_EXT_VM.md`):

```bash
CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz
```

**Use a separate target dir for the guest.** Host and guest share the checkout
over the VM mount; without it, a `cargo build` on macOS drops Mach-O binaries
into `./target` and every subsequent run in the VM dies with "cannot execute
binary file".

## Run

```bash
# Held for real, in the VM, as root (the listener fd needs privilege):
cd scheds/experimental/scx_crfuzz/scenarios && make
./run.sh race_wins.json      # the swap lands between check and use
./run.sh race_loses.json     # the swap lands after the use
```

There is no `--replay` / `--discover` flag. The mode is a property of the
config, which carries either `steps[]` or a `policy` block and never both:

| | Replay | Discovery |
|---|---|---|
| Schedule | `steps[]`, hand-authored | `policy: { type, seed, params }` |
| Checkpoints | declared explicitly | defaults to the structural syscall set |
| Answer to "what next" | `FixedSchedule` | `RandomWalk` or `PCT` |

`--spawn <cmdline>` (repeatable) launches and instruments a process;
`--cgroup-path` places it. Both are placeholders for the harness, which is why
neither is in §8's schema. `--project-schedule <path>` writes the canonical log
back out as a replay schedule — the discovery→replay loop in one flag.

## Two things worth knowing before you read the code

**A step is one release, not a "run until".** `{ "role": "victim", "until":
"mount" }` means *let the victim past exactly this `mount`*, not *let the
victim run freely until it reaches a `mount`*. So a hand-authored schedule has
to name every release, not only the interesting ones. The reasoning, and why
the other reading would break the discovery→replay guarantee, is in the header
comment of `src/policy/fixed.rs`.

**Same-seed runs are not reproducible against real processes.** The unit tests
show `decide()` is a pure function of `(seed, ready-set-sequence)` — §10.1's
stated precondition — and that is true and still not enough. Roughly one run in
a few hundred has two roles reach their first checkpoint in the opposite order;
the ready set then reaches `decide()` with its members in the other position, a
different one is released, and the whole run diverges, security verdict
included. §14-A asked whether the ready-set sequence is itself reproducible. It
is not. See `scenarios/flake.sh` and the crate docs.

Four of the design doc's §14 open questions remain, marked at the declaration
each touches: §14-C (`RoleRef`, `Pct`), §14-D (`CanonicalLog`), §14-H
(`RunOutcome`), §14-J (`CheckpointBackend::attach`). §14-A is answered, in the
negative.
