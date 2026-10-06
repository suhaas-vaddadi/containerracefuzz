# scx_crfuzz_gate — the ContainerRaceFuzz gate

A `sched_ext` scheduler that holds a thread or a whole thread group by never
dispatching it, plus the thread-state sensor `scx_crfuzz` decides on. The
engine gates one thread for its watchdog freeze and a whole thread group for
`auto_attack`'s attacker window.

- `ops.enqueue` sends a task whose tgid is in the `gate` map, or whose tid is
  in `gate_tid`, to `HOLD_DSQ`, a dispatch queue the kernel never drains;
  everything else goes to the global queue.
- `ops.dispatch` moves tasks whose gate has been deleted back to the global
  queue.
- `ops.select_cpu` exists only so wakeups can't bypass `ops.enqueue` via
  direct dispatch.
- A pinned `SEC("syscall")` program kicks every CPU after a gate or ungate, so
  already-running tasks are caught immediately.

`SCX_OPS_SWITCH_PARTIAL` is set: only tasks in `SCHED_EXT` (which
`scx_crfuzz` puts its spawns in) are affected.

**Sensor.** `tp_btf` programs on `sched_wakeup_new`, `sched_waking`,
`sched_wakeup`, `sched_switch`, `sched_process_exit` and `cgroup_attach_task`
emit `{tid, tgid, kind, arg}` records for tasks under a registered run's
cgroup. Each run claims one of 64 slots (`RunSensor::register`), each with its
own 16 MiB ringbuf and a `dropped` counter; `Drop` releases it.

It is a separate crate because BPF needs a `build.rs`, which would run on every
host and break `scx_crfuzz`'s macOS build. `scx_crfuzz` links only the
userspace client, `scx_crfuzz_gate::GateMap` (`src/client.rs`).

## Running

Start the daemon before any `scx_crfuzz` run:

```bash
sudo scx_crfuzz_gated            # attach, pin, run until Ctrl-C
```

| Flag | Purpose |
|---|---|
| *(none)* | attach, pin, verify the kick over every CPU, run until `SIGINT` or ejection |
| `--reset` | clear every gate and sensor slot in the pinned maps; needs only the pins, not a running daemon |
| `--status` | whether a `sched_ext` scheduler is attached, and how many gates and slots are live |

Only one `sched_ext` scheduler can be attached; a second daemon refuses and
names the incumbent. A `flock` on `/run/scx_crfuzz_gated.lock` stops two
daemons racing at startup.

## Pins (`/sys/fs/bpf/crfuzz/`)

| Pin | What |
|---|---|
| `gate` | `tgid → epoch` hash map checked by `enqueue`/`dispatch` |
| `gate_tid` | `tid → epoch`, the same for one thread |
| `epoch` | counter each `GateMap::open()` mints a distinct epoch from |
| `kick` | program `GateMap::kick()` runs to preempt every CPU |
| `epoch_next` | program that bumps `epoch` atomically |
| `sensor_slots`, `sensor_rings` | per-run `{cgroup id, epoch, dropped}` and its ringbuf |
| `slot_claim` | program that claims a free slot atomically |

Each run stamps its gates and its slot with its epoch, so its cleanup clears
only its own.
The `struct_ops` link is **not** pinned: if the daemon dies the scheduler
detaches and `/sys/kernel/sched_ext/state` leaves `enabled`, which
`GateBackend` checks on every call. Startup clears pins a dead daemon left.

## Limits

- **30 s per hold.** `ops.timeout_ms` is 30000, the kernel maximum. A gated
  task is runnable but unrun — exactly what the watchdog looks for — so a
  longer hold ejects the scheduler and releases every gate on the machine.
  `GateBackend` detects the ejection and fails the run.
- **A gated task can't be killed**: it must run to act on `SIGKILL`. So
  `ops.exit_task` can't clean up a task killed while gated; `GateBackend`'s
  `Drop` and `--reset` are the recovery paths.
