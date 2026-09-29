# scx_crfuzz — ContainerRaceFuzz engine

Enforces a chosen ordering of execution across the processes of a real
container lifecycle, so a TOCTOU race happens on demand rather than by chance.

- **Replay** enforces a written schedule — to reproduce a known bug.
- **Discovery** decides which held role moves next — to find one.

The modes differ only in the answer to "what runs next", which is the
`DecisionPolicy` interface. Both write the same canonical log, so a discovery
finding becomes a replay schedule by dropping a field. A config carries either
`steps[]` (replay) or a `policy` block (discovery), never both.

Design doc: `docs/sched_replay/design_doc.md`, one level above this checkout.

## How it works

A scenario names **roles** (thread groups, matched by cgroup and `comm`) and
**checkpoints** (syscalls). A **backend** holds each role at its checkpoints;
the **engine** keeps the held roles in a **ready set** and asks a **policy**
which to release, one at a time. Tasks that match no role are released
immediately — the engine can't hang unrelated work, but a mismatched `comm`
silently lets a target run free.

| Backend | Holds | Notes |
|---|---|---|
| `StubBackend` | nothing (scripted) | any host; engine tests |
| `SeccompNotifyBackend` | the calling **thread** | seccomp user-notification; siblings keep running |
| `FreezerBackend` (`--freezer`) | the thread group | cgroup freezer; restarts the held syscall; ~350 µs to converge. Baseline only. |
| `GateBackend` (`--gate`) | the thread group | `sched_ext` scheduler in [`scx_crfuzz_gate`](../scx_crfuzz_gate); no restart; needs `scx_crfuzz_gated` running |

Why the thread group matters: runc and containerd are Go, and parking one Go
thread prompts the runtime to run more on others. Sibling bytes written during
a 300 ms hold:

| Fixture | OS threads | seccomp alone | `--freezer` | `--gate` |
|---|---|---|---|---|
| `threaded_victim.c` | 2 | 255 | 0 | 0 |
| `go_victim.go` | 11 | 920 | 0 | 0 |

Policies: `FixedSchedule` (replay), `RandomWalk`, `OrderedWalk`, `Pct`
(discovery).

## Build and test

```bash
cargo test -p scx_crfuzz      # 90 tests; any host, macOS included
```

The engine is pure Rust with no `build.rs`. The seccomp, freezer and gate
backends are `#[cfg(target_os = "linux")]`. On Linux the same command runs
120; the Linux-only integration tests skip unless root, and the gate cases
unless `scx_crfuzz_gated` is attached. In the VM:

```bash
CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz -p scx_crfuzz_gate
make -C scheds/experimental/scx_crfuzz/scenarios
sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated &
sudo CARGO_TARGET_DIR=/workspace/scx/target-linux cargo test -p scx_crfuzz
```

Use a separate target dir in the guest: host and guest share the checkout, and
macOS binaries in `./target` fail in the VM with "cannot execute binary file".

## Run

In the VM, as root:

```bash
cd scheds/experimental/scx_crfuzz/scenarios && make
./run.sh race_wins.json            # swap lands between check and use
./run.sh race_loses.json           # swap lands after the use
./run.sh race_wins.json --gate     # hold whole thread groups
./go_run.sh --gate                 # Go victim; defaults to --freezer
```

### runc

```bash
sudo scx_crfuzz --config scenarios/runc.json --cgroup-path /crfuzz/runc0 \
    --freezer --spawn "/usr/bin/runc run -b /tmp/bundle ctr1"
```

All runc measurements used `--freezer`; `--gate` is unmeasured against runc.

Use `comm_match: substring` (`runc init`'s comm is `runc:[2:INIT]`). A full
`runc run` is 279 structural syscalls across 31 tasks; two tasks notify, and
both resolve to one role through the parent-thread-group rule.

### containerd

Intercept the `runc` the shim execs; containerd is unchanged:

```bash
sudo ctr run --rm --runc-binary scenarios/runc_wrapper.sh \
    docker.io/library/busybox:latest ctr1 /bin/echo hello
```

The wrapper instruments only `runc create`, under `--freezer`. It passes
`--exit-with-child` so the shim sees runc's exit status rather than the
engine's verdict, and `--oci-bundle` from runc's `--bundle`.
`--exit-with-child` allows one `--spawn`, so no racer can run alongside yet.

### `--oci-bundle`

Seccomp filters stack and `ERRNO` beats `USER_NOTIF`, so a bundle profile that
denies a checkpoint's syscall erases it silently. `--oci-bundle <dir>` compares
syscall numbers against the bundle's profile and refuses to start if any
checkpoint is masked. Only denied syscalls in the container payload are
affected; runc's own work happens before the profile is installed.

## Things to know before reading the code

- **A step is one release, not "run until".** `{ "role": "victim", "until":
  "mount" }` lets the victim past exactly one `mount`, so a schedule names
  every release (the Go victim needs five leading `openat`s). Use
  `--project-schedule` or `scx_crfuzz_gen` instead of writing them by hand.
- **Same seed ≠ same run** for position-indexing policies. About one run in a
  few hundred, two roles reach their first checkpoint in the other order
  (§14-A, `scenarios/flake.sh`). `OrderedWalk` draws its target role from the
  seed alone and is unaffected.
- **The gate caps holds at 30 s.** Longer trips the `sched_ext` watchdog, which
  ejects the scheduler and releases every gate on the machine. `GateBackend`
  detects the ejection and fails the run.
- **On aarch64, 9 of the 21 structural syscalls don't exist**; checkpoints on
  them never fire. `fstatat` is aliased to `newfstatat`.
- **Open design questions** are marked where they bite: §14-C (`RoleRef`,
  `Pct`), §14-D (`CanonicalLog`), §14-H (`RunOutcome`), §14-J
  (`CheckpointBackend::attach`).

Not built: mutator, oracle, campaign driver, Class B PID-reuse (see "Seams" in
`src/lib.rs`).
