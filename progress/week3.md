# Week 3 — Building the attacker/oracle, and holding Go processes still

Week 2 ended with the attacker/oracle contract fixed on paper and "build the
oracle" as the first item of the next stretch. This week I built it, and then
reworked the engine around a complete picture of thread state, because the
single-thread holds the scaffold used were not enough to hold a Go process
still.

## Building the attacker and the oracle

I implemented the `auto_attack` discovery mode the Week 2 contract specified:
one victim and one attacker, run in depth-2 windows. At each use-shaped
checkpoint the victim reaches, the driver rules on the previous window,
fingerprints the path the held syscall resolves, runs the attacker against it,
fingerprints the path again, and then releases the victim. The oracle
(`src/oracle.rs`) flags a path whose object identity — type or inode — changed
across the attacker's turn, the signature of a substitution.

The split from Week 2 held up: the attacker is user-authored and declares
nothing, while the oracle is harness-owned and derives the intended truth from
the scenario, so a new attacker gets bug detection for free. The fiddly part
was path capture. The held syscall's path argument is read out of
`/proc/<pid>/mem` through `checkpoint::path_arg_index`, and the notification id
is revalidated before the bytes are trusted. Verdicts stay off the canonical
log, so a discovery finding still projects back into a replayable `steps[]`.
`scenarios/03-containerd-runc/runc_wrapper_attackers.sh` tries a symlink
exchange, an unlink-and-recreate, and a bind mount on each held path.

## Why I hold whole thread groups, not threads

The most useful thing I learned this week is that holding one OS thread is not
the same as holding a process, because the container tooling is Go. runc and
containerd multiplex goroutines onto a changing set of OS threads, so parking
one thread just prompts the runtime to run the same work on another. I measured
it: for a two-thread C victim, holding one thread let 255 sibling bytes be
written, while holding the whole thread group let 0; for an eleven-thread Go
victim, one held thread leaked 920 bytes and the group again leaked 0.

The fix is to make the **role**, not the task, the unit of control. A Go
process is one thread group, every goroutine has to run on one of that group's
kernel tasks, and the gate checks the tgid on the dispatch path, so threads the
runtime spawns while the group is held are born held too. The M:N mapping is
internal to the process and never lets a goroutine escape its thread group. So
`auto_attack` freezes the whole victim group around the attacker's turn rather
than the single thread that parked.

## A complete readout of thread state

The bigger change was to stop deciding on whatever happened to be parked when
the last release came back, and instead decide only when every thread in the
run's cgroup is **at rest**. A new `sched_ext` sensor (six `tp_btf` tracepoints
into a per-run ringbuf) feeds a thread table, and the engine waits for a full
readout before asking a policy, so the ready set is exactly the threads parked
at a checkpoint and nothing else.

- **Gate.** Per-run ringbuf slots claimed atomically and scoped with
  `bpf_task_under_cgroup`; a group gate plus per-thread freeze/thaw with a
  kick, so one thread can be held for the watchdog without holding its
  siblings; a bypass-counter check alongside the ejection check.
- **Engine.** A thread table with `Running`/`Blocked`/`Parked`/`Frozen`/
  `Exited` states and a `wake_in_progress` flag, clone-path thread identity
  (`t0`, `t0.1`, …), a fresh conflict-key recapture before each decision, a
  CPU watchdog that freezes a spinner once it has burned `watchdog_cpu_secs`,
  and a `Deadlocked` outcome that names each waiting thread's `wchan` and
  syscall instead of timing out.
- **Backend.** `epoll` over the notification fds and the sensor ringbuf;
  `GateBackend` stops decorating hits and exposes `freeze`/`thaw` and
  `gate_group`/`ungate_group`; the stub scripts thread states and CPU so all of
  this is testable off-target.

Exits became a state, not a decision point, and replay gained an optional
`thread` field so a schedule can name one thread of a role.

## POS replaces OrderedWalk

Week 2 called POS the natural second policy against the `DecisionPolicy` seam.
It is now the discovery policy: seeded per-event priorities, release the
highest, and redraw only the ready events that conflict with it, with the
canonical `RoleRef` order breaking ties. Each thread is a process in the
paper's sense, so siblings stay runnable and reach their own checkpoints while
the next decision waits for the full readout. OrderedWalk is gone.

## containerd, and holding only what the sensor can see

Migrating scenario 03 to containerd surfaced a real bug. `runc:[2:INIT]` moves
into the container's own cgroup, outside the run's. The seccomp filter is
namespace-scoped and still delivers its checkpoints, but the thread-state
sensor is cgroup-scoped and can never see it. The engine tracked that task as
`Running`, nothing could ever retire it, and the readout stalled forever — the
two-attacker containerd scenario deadlocked with no canonical log at all.

The fix is that an out-of-cgroup task never resolves to a role however it was
forked, so the engine never creates a thread entry for it and releases it
unmodified; the watchdog retires any tracked thread that later leaves scope,
and the backend grew an `in_scope` check. Scenario 03 now completes and writes
a canonical log, and scenario 01 is unchanged.

I also cleaned up the review findings on that branch: a poll that drained
sensor records in the same round the scenario closed dropped `Closed` and
could hang after the last process exited (4/30 runs before, 0/230 after), and
the cgroup scope check used a bare string prefix, so run cgroup `/crfuzz/1`
also matched its sibling `/crfuzz/12`. Both are fixed.

## Housekeeping

The scenarios are now grouped as `01-single-thread`, `02-multi-thread`, and
`03-containerd-runc`, with shared programs moved to `fixtures/`; the superseded
top-level scripts and configs are gone.

## Where it stands

The discovery side now runs end to end: `auto_attack` drives a real attacker
against the victim's paths, the oracle rules each window on object identity,
and the engine only commits to a decision from a complete readout of thread
state. `scx_crfuzz_gen` follows POS and the new config fields. The full
invariant battery behind the oracle — containment, anchor, and integrity, not
just identity — is the first item of the next stretch.
