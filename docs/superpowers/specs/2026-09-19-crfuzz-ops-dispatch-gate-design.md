# `GateBackend`: holding a thread group with `ops.dispatch`

Status: approved design, not yet implemented.

Closes `docs/arch/gaps.md` #7 — "`ops.dispatch` backend", the gap that makes
results against multi-threaded targets unsound.

## Motivation

The design doc's Background says a role denotes a thread group, and that
"holding a role back means holding every thread of that thread group".
`SeccompNotifyBackend` does not deliver that. `SECCOMP_RET_USER_NOTIF` suspends
the *thread* that made the syscall; its siblings keep running.
`tests/thread_group_holding.rs` measures the gap:

| Fixture | OS threads | Bytes written during a 300 ms hold |
|---|---|---|
| `threaded_victim.c` (pthreads) | 2 | 255 |
| `go_victim.go` (goroutines) | 11 | 920 |

The Go row is the one that matters, because runc and containerd are Go.

`FreezerBackend` closes the *measurable* part of that gap — both rows go to
zero — and is explicitly a proof of concept. Three reasons it cannot be the
answer, the first found by building it:

1. **It perturbs the syscall it holds.** Freezing a cgroup wakes every task in
   it, including one parked in a seccomp notification. That wait is
   interruptible, so the kernel tears the notification down, restarts the
   syscall (`ERESTARTSYS`), and the restart raises a fresh notification with a
   new id — measured, `…077` became unanswerable the instant the cgroup froze
   and `…078` appeared in its place. The held syscall is re-executed from the
   kernel's point of view. Survivable for `fstatat`; a change to the behaviour
   under test for anything whose re-entry is observable.
2. **The boundary is fuzzy.** `cgroup.freeze` is asynchronous — ~350 µs to
   converge, 702 µs observed against runc — and siblings run for that whole
   window. A task in uninterruptible sleep cannot be frozen until it wakes, so
   convergence has no upper bound in principle.
3. **It costs milliseconds per step**, capping interleavings per second.

This spec builds the replacement: a `sched_ext` `struct_ops` scheduler that
declines to place a gated thread group on a CPU, and a `CheckpointBackend`
decorator that drives it.

## Goals

- Hold every thread of a role, with the held thread's syscall **unperturbed** —
  no wake, no `ERESTARTSYS`, no notification-id churn.
- A boundary measured in one scheduling round rather than a convergence wait.
- Per-step cost low enough not to cap a campaign's iteration rate. Concretely:
  gaps.md targets 17,700 iterations/hour, ~200 ms per iteration, so the gate's
  per-hold cost must stay in the tens of µs rather than the freezer's
  milliseconds, and `struct_ops` attach must not be paid per iteration at all.
- Preserve the blast-radius guarantee: nothing outside a declared role's thread
  group is ever gated.
- Zero change to `Engine`, `DecisionPolicy`, `role.rs`, or the canonical log.
- Preserve `scx_crfuzz`'s macOS build: 90 tests, no `build.rs`, no BPF.

## Non-goals

- **Per-thread release.** The engine continues to decide at role granularity: a
  release resumes every thread of the thread group. Gating is per-tgid. See
  "Rejected approach" below.
- **Answering §14-A.** Same-seed reproducibility against real processes stays
  open. The gate makes the other threads stop; it does not make them stop in a
  chosen order.
- **`uprobe`/`kprobe`/`lsm` checkpoints.** The gate is the only route to them
  and this spec builds the infrastructure they need, but checkpoint *detection*
  stays seccomp-only here. Phase 2 (§"Residual window") lands the first
  in-kernel hook; a full non-syscall checkpoint kind is separate work.
- **Retiring `FreezerBackend`.** It stays as the baseline the gate is measured
  against, exactly as `RandomWalk` was kept as the baseline §14-A was measured
  against.

## Rejected approach: per-thread gating

The gate map is keyed per task whether or not the engine uses that, so letting
the engine choose *which thread inside a role* runs next is nearly free on the
BPF side. It was rejected on three grounds:

1. **It does not widen the race window.** The TOCTOU is: victim checks a path,
   racer swaps it, victim uses it. The engine already owns both ends of that
   window — it holds the victim at the check and releases the racer into the
   gap. Subdividing the victim into threads gives it no new control over
   either end.
2. **It can wedge the Go runtime.** Releasing one M while its siblings stay
   gated deadlocks the moment that M needs a channel handoff, a GC assist, or a
   futex held by a gated sibling. The engine would see no progress and time
   out, and the failure would be in the instrument.
3. **It degrades the PCT bound.** `policy/pct.rs` places `d-1` inversion points
   over `1..=k`; PCT's probability is roughly `1/(n · k^(d-1))`. Per-thread
   takes `n` from ~2 roles to ~22 threads and inflates `k` by every GC and
   `sysmon` scheduling point. Both denominators grow, one exponentially in bug
   depth. More interleavings, lower hit rate — the extra states are Go runtime
   bookkeeping, not security-relevant orderings.

What per-thread gating actually buys is reproducibility (§14-A), not discovery.
That is worth doing, is a different problem, and costs a refactor of `role.rs`,
`policy/` and the canonical log. The BPF side designed here supports it without
change if that day comes.

## Architecture

Two new pieces, one small edit.

| | |
|---|---|
| **`scx_crfuzz_gate`** | New workspace crate under `scheds/experimental/`. The BPF `struct_ops` scheduler plus a `scx_crfuzz_gated` daemon that attaches it once and pins the gate map. |
| **`GateBackend<B>`** | New module in `scx_crfuzz`, `#[cfg(target_os = "linux")]`. A decorator over any `CheckpointBackend`, sitting exactly where `FreezerBackend` sits. |
| **`backend_seccomp.rs`** | One added call in the fork/exec window: `sched_setscheduler(0, SCHED_EXT, …)`, next to the filter install. |

**Why a separate crate.** BPF requires `scx_cargo` in `[build-dependencies]`,
and a `build.rs` always runs regardless of target. Putting it in `scx_crfuzz`
would end that crate's "builds and tests anywhere, macOS included" property,
which its README leans on and which is what keeps the engine, policies, role
algebra and log testable off-target. A separate crate consumed through
`[target.'cfg(target_os = "linux")'.dependencies]` leaves the macOS build
byte-for-byte as it is — the same pattern `libseccomp` and `nix` already use in
that manifest.

**Dependency direction.** `scx_crfuzz` → `scx_crfuzz_gate` (Linux only), for
the pinned-map client only. The gate crate has no knowledge of roles,
checkpoints, policies or the engine; it exposes gate/ungate by tgid and nothing
else.

## The BPF scheduler

```
gate:     BPF_MAP_TYPE_HASH<u32 tgid, struct gate_entry>   // pinned
HOLD_DSQ: a DSQ the normal dispatch path never consumes
```

```c
struct gate_entry { u64 epoch; };   // which run owns this gate
```

**Epoch.** `GateBackend::attach` mints one epoch per run — a monotonic counter
in a second pinned single-entry map, incremented atomically at attach — and
stamps every entry it writes with it. The BPF side never reads the epoch; it is
purely userspace bookkeeping, so that `Drop` can clear exactly the entries this
run owns and leave a concurrently-running engine's gates alone.

Ops:

| Callback | Behaviour |
|---|---|
| `ops.enqueue` | `gated(p->tgid)` → `scx_bpf_dsq_insert(p, HOLD_DSQ, SCX_SLICE_INF, 0)`; else → `scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0)` |
| `ops.dispatch` | `scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL)`, then `bpf_for_each(scx_dsq, p, HOLD_DSQ, 0)` moving out anything no longer gated |
| `ops.exit_task` | delete the tgid entry when the thread-group leader exits |
| flags | `SCX_OPS_SWITCH_PARTIAL`, `timeout_ms = 30000` |

All three primitives are already in tree: `SCX_OPS_SWITCH_PARTIAL` via
`scx_utils::compat`, `SCX_SLICE_INF` in `scx_tickless`, `bpf_for_each(scx_dsq,
…)` in `scx_tickless`, `scx_layered` and `scx_p2dq`.

**Enrollment.** `SCX_OPS_SWITCH_PARTIAL` means the scheduler only handles tasks
explicitly placed in `SCHED_EXT` (policy 7 — `scx_rustland_core` sets the
precedent). Scheduling policy is inherited across `fork` and `CLONE_THREAD`, so
a single `sched_setscheduler` before `exec` enrolls a `--spawn`'s entire
process tree, including threads the Go runtime raises later, and touches
nothing else on the machine. This is the blast-radius guarantee obtained the
same way the seccomp filter obtains it: by acting in the window between fork
and exec, and letting inheritance do the rest.

**The engine process itself is never enrolled.** Only spawned children. An
enrolled engine could gate itself.

## Hold and release

**Hold**, on `CheckpointHit { pid, … }` for thread group `T`:

1. Write `gate[T] = { epoch }`.
2. `scx_bpf_kick_cpu(…, SCX_KICK_PREEMPT)` on every CPU, so any of `T`'s
   threads currently on-CPU re-enters `ops.enqueue`.
3. Those threads land in `HOLD_DSQ` and stay there.

**Release**, on `release(handle)`:

1. Delete `gate[T]`.
2. Kick; `ops.dispatch` drains `T`'s threads out of `HOLD_DSQ`.
3. *Then* answer the seccomp notification.

Step order in release is load-bearing: ungate first, or the notifying thread
returns from the kernel into a still-gated thread group and is immediately
parked again.

**Nothing touches the held thread.** It stays parked in its seccomp
notification for the whole hold. No wake, no `ERESTARTSYS`, no fresh
notification id — which is the entire point, and which deletes `owner`, `live`,
`reported` and `deferred` from the freezer's state. `GateBackend` keeps only
`handle → tgid`.

Kicking every CPU rather than tracking which CPUs run `T`'s threads is
deliberate: the dev VM has few CPUs, a `SCX_KICK_PREEMPT` on an idle CPU is
cheap, and a per-tgid CPU map is state that would have to be kept correct
across migration for no measured benefit. Revisit if `GateStats` says the kick
dominates.

## Residual window, and phase 2

The gate's boundary is **sharper, not zero**, and the spec says so rather than
letting a later measurement say it.

Between the seccomp notification arriving and userspace writing `gate[T]`,
siblings still run: one userspace round trip, tens of µs, against the freezer's
measured ~350 µs. Step 2 then costs one scheduling round. So the honest claim
is roughly an order of magnitude sharper *and* the perturbation eliminated —
not synchronous holding of the thread group.

Closing it to zero requires setting the gate **in-kernel, in the trapping
task's own context**, before it blocks — an `fentry` or `kprobe` program on the
seccomp notification path that writes `gate[T]` itself. That is the same
trap-based construction the design doc specifies for `uprobe`/`kprobe`
checkpoints ("the attached BPF program runs in the interrupted task's own
kernel context and can force a reschedule check before the task returns to
userspace"). It is phase 2 of this spec: the map, the scheduler and the backend
are unchanged; only who writes the entry moves.

Phase 1 is landed and measured first, because the freezer's own header argues
that the case against a mechanism should be evidence rather than theory, and
the same standard applies to the case *for* one.

## The 30 s ceiling

A gated task is runnable-but-undispatched, which is exactly what
`ops.timeout_ms` watches, and 30000 ms is the maximum the kernel accepts
(`scx_chaos` and `scx_mlfq` both sit there). Exceed it and the kernel ejects
the scheduler mid-run.

The engine's stall budget is `MAX_IDLE_ROUNDS × poll timeout` = 3.2 s, so
ordinary holds fit comfortably underneath. A `Barrier` waiting on a role that
never appears does not obviously fit, and the freezer had no equivalent limit.
`GateBackend` therefore treats an approaching timeout as a run failure of its
own rather than waiting for the kernel to eject the scheduler underneath it.

## CLI

`--gate` wraps the seccomp backend in `GateBackend`, mutually exclusive with
`--freezer`. The daemon is separate:

```bash
sudo scx_crfuzz_gated            # attach, pin, run until SIGINT
sudo scx_crfuzz_gated --reset    # clear every gate in the pinned map and exit;
                                 # operates on the map, so it does not require
                                 # (or replace) a running daemon
sudo scx_crfuzz_gated --status   # is it attached, how many gates live
```

**Ordering precondition.** The daemon must be attached before any `--spawn`
runs. Enrolling a task in `SCHED_EXT` with no scheduler loaded does not gate
it, so a spawn that wins that race is silently unheld — which is why
`GateBackend::attach` fails the run outright rather than warning.

```bash
sudo scx_crfuzz --config scenarios/go_race.json --cgroup-path /crfuzz/go0 \
    --gate --spawn ./go_victim --spawn ./racer …
```

## Error handling

The recurring lesson in this codebase is that the dangerous failures are silent
ones — a bundle's seccomp profile erasing a checkpoint, a mismatched `comm`
releasing the interesting half of runc. Each of these is loud.

| Failure | Handling |
|---|---|
| Daemon not running, or map not pinned | `GateBackend::attach` fails the run. **Never** degrade to seccomp-only: that looks identical to a successful multi-threaded hold and is unsound. |
| Scheduler ejected mid-run (watchdog, `ops.error`) | Gates evaporate, every gated task runs free, and the engine goes on believing it holds them — a clean-looking bogus verdict. The backend polls `/sys/kernel/sched_ext/state` each `poll()` and fails the run on any transition away from `enabled`. |
| Stale gates from a crashed run | Three layers: `ops.exit_task` deletes on leader exit; `GateBackend::Drop` clears the entries stamped with this run's epoch; and `scx_crfuzz_gated --reset` clears the map wholesale as an explicit operator action, since a recovery tool by definition has no epoch of its own to match. |
| Another `sched_ext` scheduler attached | Only one can be. The daemon detects this at start and names it. |
| A `--spawn` fails `sched_setscheduler` | Fail the spawn. An un-enrolled target is invisible to the gate and silently unheld. |

## Testing

**Parity** — a third column in `tests/thread_group_holding.rs`'s existing
table, reusing the harness already there:

| Fixture | seccomp alone | `--freezer` | `--gate` |
|---|---|---|---|
| `threaded_victim.c` (2 threads) | 255 B | 0 | expect 0 |
| `go_victim.go` (11 threads) | 920 B | 0 | expect 0 |

**Soundness** — the test that distinguishes the gate from the freezer rather
than measuring them equal. Assert that the `NotifyHandle` the engine was first
told about is the handle it releases, with no intervening id change. The
freezer demonstrably fails this; the gate must pass it. This is gaps.md #7's
claim turned into an assertion.

**`GateStats`**, mirroring `FreezeStats`: hold latency from notification to
kick-complete, total and max, so the residual window above is a measured number
in the README rather than an estimate in this spec.

**Non-regression** — `cargo test -p scx_crfuzz` on macOS still reports exactly
90 tests, proving the new crate stayed off the host build.

**BPF** — `veristat` baselines under `scx_crfuzz_gate/veristat/`, following
`scx_mlfq`.

**End to end** — `go_run.sh --gate` with `--project-schedule` and
`--canonical-log`, byte-comparing the replay against the discovery run, as the
freezer path already does. Expect no worse than the freezer; §14-A means not
100%.

All of the privileged tests skip unless root, as the existing ones do, and run
in the Lima `sched-ext` VM (`docs/environment/SCHED_EXT_VM.md`). Note the
existing constraint that `reap` calls `waitpid(None)` process-wide, so backend
tests stay one per binary.

## Open questions carried forward

- **§14-J** (`CheckpointBackend::attach`) is unchanged but newly relevant: a
  late pool member must be enrolled in `SCHED_EXT` before it can be gated.
  Inheritance covers descendants of a `--spawn`, so the window only exists for
  a member that arrives by some other route. Not closed here.
- **§14-A** is untouched. The gate stops the other threads; it does not order
  their arrival.
- Whether `SCX_KICK_PREEMPT` on every CPU stays acceptable on a machine with
  many more CPUs than the dev VM. `GateStats` will say.
