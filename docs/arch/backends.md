# Backends

How a task is actually stopped. `src/backend.rs` (272), `src/backend_seccomp.rs`
(712), `src/backend_freezer.rs` (438), `src/backend_gate.rs` (292) — plus the
`sched_ext` side of the gate, in a separate crate:
`scx_crfuzz_gate/src/bpf/main.bpf.c` (217), `scx_crfuzz_gate/src/client.rs`
(238).

## The interface

```rust
pub trait CheckpointBackend {
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()>;
    fn poll(&mut self) -> Result<Poll>;
    fn release(&mut self, handle: NotifyHandle) -> Result<()>;
}

pub enum Poll { Events(Vec<BackendEvent>), Idle, Closed }
```

`NotifyHandle` is opaque to the engine — on Linux it wraps a seccomp
notification id, and the engine never interprets it.

**`Idle` must cost real time.** The engine's stall detector counts polls and has
no other clock. A backend that returns `Idle` without blocking converts a
3.2-second timeout into a microsecond one. Enforced by
`tests/exit_observation.rs`.

§14-J is open on `attach`: `one` roles attach before `Enforcing`, so nothing
races it, but pool members can be recognised at any time and the doc does not
say whether there is a window between a late member's first path-touching
syscall and attachment to it.

## StubBackend

Scripted events, no real processes. Runs anywhere, including macOS, and carries
18 engine integration tests.

**It cannot say anything about §14-A.** The script fixes the order in which
tasks reach their checkpoints, so any determinism it shows is determinism of
`decide()` as a pure function of `(seed, ready-set-sequence)` and nothing more.
A green suite here is not evidence of end-to-end reproducibility.

## SeccompNotifyBackend

The real one. `SECCOMP_RET_USER_NOTIF`: the filter is installed between fork and
exec, the kernel suspends the calling thread at the syscall, and it stays
suspended until the engine answers. Covers every `syscall` checkpoint — the
whole of the §4.2 default set — and needs neither eBPF nor a `sched_ext` attach.

Filter shape: default `ALLOW`, `NOTIFY` for each watched syscall. Descendants
inherit it, which is how `runc` → `runc init` stays instrumented without
re-attaching.

`CONTINUE`, not a synthesised return value: this engine decides *when* a syscall
runs, never what it does.

### The thread-vs-thread-group gap

**It holds a thread, not a thread group.** For a single-threaded target those
coincide. For a Go binary they do not, and holding one thread is itself what
provokes the Go runtime's `sysmon` into handing work to another M.

### Two bugs found here, both fixed

**POLLHUP busy-spin.** When a held child exits, its notify fd reports `POLLHUP`,
not `POLLIN`. `POLLHUP` is level-triggered and never clears, so leaving the fd
in the poll set made `poll(2)` return instantly forever. No event was produced,
the engine counted an idle round, and the loop span — burning the 64-round
budget in **66 µs** instead of 3.2 s, before `waitpid` could reap the child. The
window scales with teardown cost, so it read as a Go problem: a 1-thread C child
is reaped in time, an 11-thread Go child is not. Fixed by retiring hung-up fds
from the poll set and sleeping the poll timeout when nothing pollable remains.

**Exit status discarded.** `reap` threw away the child's status. Now kept in
shell convention (`128 + signo` if signalled) and exposed as
`child_exit_code()`, which `--exit-with-child` needs.

### Known sharp edge

`reap` calls `waitpid(None)`, which is **process-wide**. Two backends in one
process reap each other's children. The engine only ever builds one, so this
constrains tests — hence one test per binary in `exit_observation.rs` and
`exit_status.rs`.

## FreezerBackend

A decorator over `SeccompNotifyBackend`. On a checkpoint hit it resolves the
task's cgroup via `/proc/<pid>/cgroup` and writes `1` to `cgroup.freeze`, so
seccomp supplies the precision (stop at exactly this syscall) and the freezer
supplies the coverage (nothing else in the thread group gets CPU).

State it must keep, all of it forced by the bug below:

```rust
owner:    HashMap<NotifyHandle, Pid>,   // handle as the engine knows it
live:     HashMap<Pid, NotifyHandle>,   // notification it is parked on NOW
reported: Vec<Pid>,                     // absorbs restart duplicates
deferred: Vec<BackendEvent>,            // events seen while resolving
```

`Drop` thaws everything. Without it a frozen process keeps its inherited stdout
open and the shell hangs forever.

### It is a proof of concept. Three reasons it must be replaced

1. **It perturbs the syscall it is holding.** Freezing wakes every task in the
   cgroup, including one parked in a seccomp notification. That wait is
   interruptible, so the kernel tears the notification down, restarts the
   syscall (`ERESTARTSYS`), and the restart raises a **fresh notification with a
   new id** — measured directly, id `…077` became unanswerable the moment the
   cgroup froze and `…078` appeared in its place. The maps above paper over it,
   but the held syscall is re-executed from the kernel's point of view. Fine for
   `fstatat`; a change to the behaviour under test for anything whose re-entry
   is observable.
2. **The boundary is fuzzy.** `cgroup.freeze` is asynchronous — ~350 µs to
   converge, 702 µs observed against runc — and siblings run for that whole
   window. A task in uninterruptible sleep cannot be frozen until it wakes, so
   convergence has no upper bound in principle.
3. **It costs milliseconds per step**, capping interleavings per second.

## GateBackend

A decorator over `SeccompNotifyBackend`, sitting exactly where `FreezerBackend`
sits and for the same reason: seccomp supplies the precision, the gate
supplies the coverage. It talks to a separate crate, `scx_crfuzz_gate`, which
owns the `sched_ext` `struct_ops` half of the mechanism — split out because
BPF needs a `build.rs`, and a `build.rs` runs on every host, which would break
this crate's "builds and tests anywhere, macOS included" property.

`scx_crfuzz_gate`'s BPF program (`src/bpf/main.bpf.c`) is small:

- **The map.** `gate`, a `BPF_MAP_TYPE_HASH` keyed by `tgid`, value an epoch
  stamp. `is_gated(tgid)` is a lookup against it. `GateMap` (the userspace
  client, `scx_crfuzz_gate::client`) opens it pinned at
  `/sys/fs/bpf/crfuzz/gate` and writes an entry per `gate(tgid)` call.
- **`HOLD_DSQ`.** A dispatch queue (id 1) created in `ops.init` that nothing
  ever consumes except the ungating path in `ops.dispatch` itself — it exists
  purely as a parking place.
- **`ops.enqueue`.** A gated task's tgid routes it into `HOLD_DSQ` with
  `SCX_SLICE_INF` (it isn't competing for time; the slice that matters comes
  from wherever it lands once ungated). An ungated task goes to
  `SCX_DSQ_GLOBAL` as normal.
- **`ops.dispatch`.** Walks `HOLD_DSQ`. Anything still gated is skipped in
  place; anything whose gate has since been deleted is moved back to
  `SCX_DSQ_GLOBAL` with a fresh default slice. This is what makes `release()`
  a map delete plus a kick rather than something that has to reach into the
  DSQ itself.
- **`ops.exit_task`.** The first of three cleanup layers: deletes a gated
  leader's map entry on its own exit, so an ordinary exit never leaves a
  stale gate. (The other two, both in userspace: `GateBackend::Drop` clears
  the current run's epoch, and `scx_crfuzz_gated --reset` clears the map
  wholesale.)

**`SWITCH_PARTIAL` enrollment.** The scheduler sets
`SCX_OPS_SWITCH_PARTIAL`, so only tasks explicitly moved into `SCHED_EXT` are
scheduled by it; everything else on the machine stays on CFS, untouched.
`SeccompNotifyBackend::with_sched_ext(true)` is what does the moving — between
fork and exec, the spawned target calls `sched_setscheduler(0, SCHED_EXT, …)`
on itself, and because scheduling policy is inherited across fork and
`CLONE_THREAD`, that one call enrolls the whole tree the target goes on to
build, including threads a Go runtime raises later.

**Failure modes**, from the spec's error-handling table:

| Failure | Handling |
|---|---|
| Daemon not running, or map not pinned | `GateBackend::attach` fails the run outright. Never degrades to seccomp-only — that would look identical to a successful multi-threaded hold. |
| Scheduler ejected mid-run (watchdog, `ops.error`) | Gates evaporate and every gated task runs free. `GateBackend` polls `/sys/kernel/sched_ext/state` every `poll()` and fails the run on any transition away from `enabled`. |
| Daemon dies mid-run | The same condition, reached a second way: the `struct_ops` link is deliberately not pinned, so it releases when the daemon process dies and `state` flips to `disabled` within a couple of seconds — caught by the same per-round check above. |
| Stale gates from a crashed run | Three layers: `ops.exit_task` on leader exit, `GateBackend::Drop` clearing this run's epoch, and `scx_crfuzz_gated --reset` clearing the map wholesale as an explicit operator action. |

## What `ops.dispatch` fixed

Gating is a map lookup on the enqueue path; a sleeping task is off-CPU already
and gets gated on its way back in; and nothing touches the syscall path, so
there is no restart to correct for.

**The perturbation is gone**: no `ERESTARTSYS`, no fresh notification id, a
`NotifyHandle` stable across the hold. `tests/handle_stability.rs` asserts
this, and asserts the freezer's opposite behaviour alongside it, so the
distinction cannot quietly stop being true.

**The boundary is sharper, not zero.** The kick is one scheduling round, but
the userspace round trip before it — notification arriving until `map.gate()`
is called — is not, and siblings run for the whole of it. Closing that to zero
needs the gate written in-kernel in the trapping task's own context, which is
phase 2 and not built. The two backends' latency counters measure disjoint
intervals and are not a ratio; see
[measurements.md](measurements.md#hold-latency).

System-wide risk is bounded: `SCX_OPS_SWITCH_PARTIAL` schedules only tasks
explicitly moved to `SCHED_EXT`, and `ops.timeout_ms` (30000, the kernel
maximum) ejects a stuck scheduler — something the freezer had no equivalent
of.

Section 14-A remains open: the gate stops the other threads in a group, it
does not order their arrival, so run-to-run reproducibility against a
multi-threaded target is still not guaranteed.
