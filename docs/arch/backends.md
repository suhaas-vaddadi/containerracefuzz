# Backends

How a task is actually stopped. `src/backend.rs` (272), `src/backend_seccomp.rs`
(683), `src/backend_freezer.rs` (440).

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

### What `ops.dispatch` would fix

Gating is a map lookup on the enqueue path, so the boundary is one scheduling
round rather than a convergence wait; a sleeping task is off-CPU already and
gets gated on its way back in; and nothing touches the syscall path, so there is
no restart to correct for. It is also the only route to `uprobe`/`kprobe`/`lsm`
checkpoints.

System-wide risk is smaller than it looks: `SCX_OPS_SWITCH_PARTIAL` schedules
only tasks explicitly moved to `SCHED_EXT`, leaving the rest of the machine on
CFS, and `ops.timeout_ms` ejects a stuck scheduler.

**Until it lands, results against multi-threaded targets are not sound**,
freezer or not.
