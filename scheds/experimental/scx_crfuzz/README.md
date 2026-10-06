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
**checkpoints** (syscalls). Seccomp user-notification parks the calling thread
at a checkpoint, before the syscall runs. The **engine** keeps parked hits in a
**ready set** and releases them one at a time. Hits of tasks that match no role
are released immediately — the engine can't hang unrelated work, but a
mismatched `comm` silently lets a target run free.

Every run needs `scx_crfuzz_gated` attached
([`scx_crfuzz_gate`](../scx_crfuzz_gate)). Its BPF sensor reports every
thread's state in the run's cgroup (created, waking, asleep, exited,
joined/left) into a ringbuf the run claims as a **slot**; a crashed run's slot
is freed by `scx_crfuzz_gated --reset`, which also clears gates. Its gate keeps
a thread or thread group runnable but off the CPU when the engine asks.

**Full readout.** The engine decides only when every thread in the cgroup —
matched to a role or not — is **at rest**: parked at a checkpoint, or asleep
with no wakeup in progress. The ready set is then exactly the parked threads,
and each thread is named by its clone path (`t0`, `t0.1`, ...: the n-th
thread its creator made), so the same seed gives the same decisions. Two kinds
of decision are counted and reported as not seed-reproducible:
`timed_sleep_decisions` (taken while some sleeping thread will wake on its own:
a sleep with a timeout, an I/O wait) and `frozen_decisions` (taken while the
watchdog has a thread frozen). Memory races between checkpoints are out of
scope. A lost sensor record (ringbuf full) aborts the run.

**Watchdog.** A thread that keeps running while others wait is frozen through
the gate once it has used `watchdog_cpu_secs` of CPU (config field, default
15) since the last decision. It is thawed once the next decision's released
thread is back at rest, or after 20 s (under `sched_ext`'s own 30 s limit).

**Outcomes.** `Completed` once every thread has exited. `Deadlocked` when
everything is at rest, no decision is possible, and nothing will wake on a
timer: the run lists each waiting thread's `wchan` and syscall. No wall-clock
grace period is involved, so a thread in an untimed wait on something outside
the cgroup (a socket, a pipe from outside) makes the run `Deadlocked`. Exits
are not decision points.

What a hit holds is decided by the driver, not a flag:

| Driver | Checkpoints | A hit holds | Actor |
|---|---|---|---|
| `auto_attack` | use-shaped syscalls | the thread that hit, plus its whole thread group (gated) while the attacker acts | the role |
| `pos` | every path-based check and use | the thread that hit | one per thread |
| replay (`steps[]`) | as declared | the thread that hit | one per thread |

`auto_attack` runs the configured attacker on the path of each use the single
victim reaches, then releases the victim and runs the oracle (see
`docs/arch/policies.md`). The victim is frozen whole because runc and
containerd are Go, and parking one Go thread prompts the runtime to run more on
others. Sibling bytes written during a 300 ms hold:

| Fixture | OS threads | one thread held | thread group held |
|---|---|---|---|
| `threaded_victim.c` | 2 | 255 | 0 |
| `go_victim.go` | 11 | 920 | 0 |

`pos` is POS (Yuan et al., CAV 2018): seeded per-event priorities, release the
highest, redraw only the ready events that conflict with it. Each thread is a
process in the paper's sense, so siblings stay runnable and reach their own
checkpoints; the next decision waits for the full readout. The oracle is
`oracle::observe` (`src/oracle.rs`): it flags a path whose object identity
changed across the attacker's turn — type or inode — the signature of a
substitution. The full invariant battery is future work.

## Build and test

```bash
cargo test -p scx_crfuzz      # any host, macOS included
```

The engine is pure Rust with no `build.rs`. The seccomp and gate backends are
`#[cfg(target_os = "linux")]`. On Linux the Linux-only integration tests
skip unless root, and the gate cases unless `scx_crfuzz_gated` is attached. In the VM:

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
make run-01 && make run-02 && make run-03   # see scenarios/README.md
```

The CLI is `--config`, `--spawn` (repeatable), `--oci-bundle DIR`,
`--exit-with-spawn [INDEX]`, `--out DIR` and `-v`. `--out` writes `log`,
`schedule.json` (the projected replay schedule) and `debug` (with the
per-decision ready sets); without it the canonical log goes to stdout.
`--exit-with-spawn` requires `--out`. The decision count, `timed_sleep_decisions`
and `frozen_decisions` go to stderr. Each run places its spawns in
`<config cgroup>/<engine pid>`.

### runc

```bash
sudo scx_crfuzz --config my-runc-scenario.json --out /tmp/runc0 \
    --spawn "/usr/bin/runc run -b /tmp/bundle ctr1"
```

The gate is validated against runc: one `runc run` issues 37 holds across its
`mount`/`symlinkat` setup.

Use `comm_match: substring` (`runc init`'s comm is `runc:[2:INIT]`). A full
`runc run` is 279 structural syscalls across 31 tasks; two tasks notify, and
both resolve to one role through the parent-thread-group rule.

### containerd

Intercept the `runc` the shim execs; containerd is unchanged:

```bash
make -C scenarios run-03
```

`scenarios/03-containerd-runc/runc_wrapper_attackers.sh` instruments only
`runc create`, alongside two attackers. It passes `--exit-with-spawn 0` so the
shim sees runc's exit status rather than the engine's verdict, and
`--oci-bundle` from runc's `--bundle`.

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
  `--out`'s `schedule.json` or `scx_crfuzz_gen` instead of writing them by hand.
  An optional `"thread": "t0.1"` names one thread of the role; without it any
  thread matches. Exits are not releases: `"until": "exit"` is rejected.
- **Same seed = same run, with counted exceptions** (§14-A): see "Full
  readout" above. Check `timed_sleep_decisions` and `frozen_decisions` before
  comparing two runs.
- **The gate caps holds at 30 s.** Longer trips the `sched_ext` watchdog, which
  ejects the scheduler and releases every gate on the machine. `GateBackend`
  detects the ejection, or bypass mode, and fails the run.
- **On aarch64, 15 of the 44 structural syscalls don't exist** (the legacy
  x86_64 names); each has an `*at` form in the set that does, and the backend
  warns about the rest. `auto_attack`'s set holds only syscalls that can be the
  *use* in a check-then-use race (design doc §4.2); `pos` adds the checks.
- **Open design questions** are marked where they bite: §14-C (`RoleRef`), §14-D (`CanonicalLog`), §14-H (`RunOutcome`), §14-J
  (`CheckpointBackend::attach`).

Not built: mutator, campaign driver, Class B PID-reuse (see "Seams" in
`src/lib.rs`). The oracle is the first real one; its full invariant battery is
still future work.
