# scx_crfuzz_gate — the ContainerRaceFuzz gate

A `sched_ext` scheduler that holds a thread group by declining to dispatch
it: `ops.enqueue` routes a gated tgid's tasks into a dispatch queue nothing
else consumes, and `ops.dispatch` moves them back out the moment they're
ungated. It is `scx_crfuzz`'s answer to "hold every OS thread in a role, not
just the one that made the syscall" — the gap `FreezerBackend` (the cgroup
freezer proof of concept) papers over by restarting the syscall it holds.
See `scheds/experimental/scx_crfuzz/README.md`'s "Holding a thread group: the
gate" section and `docs/arch/backends.md`'s `GateBackend` section for the
full picture; this file covers only the daemon.

## Why a separate crate

`scx_crfuzz` is pure Rust and builds and tests on any host, macOS included.
A `sched_ext` `struct_ops` scheduler needs a BPF program, and BPF needs a
`build.rs` — one runs on every host regardless of target, which would break
that property. Splitting the gate out here is what keeps it out of the host
build entirely.

`scx_crfuzz`'s own `src/backend_gate.rs` implements `GateBackend`
(`CheckpointBackend`) against this crate's pinned maps; it does not link this
crate's BPF machinery, only `scx_crfuzz_gate::GateMap`, the userspace client
in `src/client.rs`.

## Running it

The daemon must be attached **before** any `scx_crfuzz --gate` run. A spawn
enrolled in `SCHED_EXT` with no scheduler loaded is not gated — it is
silently unheld — so `GateBackend::attach` fails the run outright rather than
letting that happen quietly:

```bash
sudo scx_crfuzz_gated            # attach, pin, run until Ctrl-C
```

It prints its pin directory, verifies the kick mechanism over every CPU, and
then blocks until `SIGINT` or the kernel's watchdog ejects it.

## CLI

| Flag | Purpose |
|---|---|
| *(none)* | attach the scheduler, pin the maps, and run until `SIGINT` |
| `--reset` | clear every gate in the pinned map and exit. Operates on the map directly, so it neither requires nor replaces a running daemon — the recovery tool for a crashed daemon's leftovers |
| `--status` | report whether a `sched_ext` scheduler is attached and how many gates are currently live |

Only one `sched_ext` scheduler can be attached at a time; a second
`scx_crfuzz_gated` (or any other `sched_ext` scheduler) refuses to start and
names the incumbent.

## Pinned paths

Everything lives under `/sys/fs/bpf/crfuzz/`:

| Pin | What |
|---|---|
| `gate` | the `tgid -> epoch` hash map that `ops.enqueue`/`ops.dispatch` check |
| `epoch` | the single monotonic counter `GateMap::open()` mints from, so concurrent runs get distinct epochs and each run's `Drop` clears only its own gates |
| `kick` | the `SEC("syscall")` program `GateMap::kick()` invokes via `BPF_PROG_TEST_RUN` to preempt every CPU after a gate or ungate |
| `epoch_next` | the `SEC("syscall")` program that atomically bumps `epoch`, avoiding a userspace lookup-then-update race between concurrent opens |

The `struct_ops` attachment link itself is deliberately **not** pinned, so it
releases automatically when the daemon process dies — `/sys/kernel/sched_ext/state`
flips back to `disabled` within a couple of seconds, which is what lets
`GateBackend`'s per-round `scheduler_enabled()` check catch a dead daemon the
same way it catches a watchdog ejection. Startup clears any pins left behind
by a crashed prior daemon before creating fresh ones.

## The 30 s ceiling

`ops.timeout_ms` is set to `30000`, the maximum the kernel accepts. A gated
task is runnable-but-undispatched, which is exactly what that watchdog
watches: holding one past 30 s fires it and the kernel force-disables the
*entire* scheduler, releasing every gate at once — not just the one that
overstayed, every concurrent run on the machine. `GateBackend` treats an
approaching timeout as a run failure of its own rather than waiting for the
kernel to eject the scheduler underneath it. The freezer had no equivalent
limit.

A gated task also cannot be killed: it is runnable but never dispatched, and
a task has to run to process `SIGKILL`. `ops.exit_task` therefore cannot reap
the map entry for a task killed while gated — it never reaches its own exit
path — which is why the other two cleanup layers above (`GateBackend::Drop`
and `--reset`) are the ones that actually matter for recovery.
