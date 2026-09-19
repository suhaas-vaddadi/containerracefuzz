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
| `FreezerBackend` — extends a hold to the thread group | **proof of concept**, Linux only — works, but see "TODO" below |
| `sched_ext` `struct_ops` backend (`ops.dispatch` gating) | **not implemented** — the intended mechanism; see "TODO" below |
| Mutator, racer, oracle, harness, Class B PID-reuse module | out of scope — see "Seams" in the crate docs |

`SeccompNotifyBackend` covers every `syscall` checkpoint, which is the whole of
§4.2's default set, and needs neither eBPF nor a `sched_ext` attach. It holds a
target at a real syscall boundary: the kernel suspends the calling thread and
will not resume it until the engine answers the notification.

**It holds a thread, not a thread group.** Background requires that holding a
role hold every OS thread in it. For a single-threaded target those coincide.
For a Go binary — runc, containerd, the actual targets — they do not: sibling
goroutine threads keep running while one thread sits in a notification.

That gap is now measured rather than asserted.
`tests/thread_group_holding.rs` holds a multi-threaded fixture at a checkpoint
and watches the threads that should have been held with it:

| Fixture | OS threads | Bytes written during a 300 ms hold | With `--freezer` |
|---|---|---|---|
| `threaded_victim.c` (pthreads) | 2 | 255 | **0** |
| `go_victim.go` (goroutines) | 11 | 920 | **0** |

The Go row is the one that matters: runc and containerd are Go, and Go's
`sysmon` responds to a thread blocked in a syscall by handing its work to
another M — so holding one thread in a notification is itself what provokes the
runtime into running more. Four of those eleven threads are pinned siblings the
fixture creates; the rest the runtime raised on its own.

## TODO: replace the freezer with `ops.dispatch`

`FreezerBackend` (`src/backend_freezer.rs`) is a **proof of concept**, kept
because it is a useful baseline to measure against — not because it is the
answer. It wraps `SeccompNotifyBackend` and writes `1` to the held task's
`cgroup.freeze`, so seccomp supplies the precision (stop exactly at this
syscall) and the freezer supplies the group coverage (nothing else in the
thread group gets CPU).

Three reasons it has to go, the first of which was found by building it:

1. **It perturbs the syscall it is holding.** Freezing a cgroup wakes every
   task in it, including one parked in a seccomp notification. That wait is
   interruptible, so the kernel tears the notification down, restarts the
   syscall (`ERESTARTSYS`), and the restart raises a *fresh* notification with
   a new id — measured directly, id `…077` became unanswerable the moment the
   cgroup froze and `…078` appeared in its place. `FreezerBackend` keeps a
   `pid → live handle` map to paper over that, but the deeper problem is
   semantic: the held syscall is re-executed from the kernel's point of view.
   For an idempotent call like `fstatat` that is survivable; for a call whose
   re-entry is observable it is a change to the behavior under test, introduced
   by the instrument.
2. **The boundary is fuzzy.** `cgroup.freeze` is asynchronous — measured at
   ~350 µs to converge — and siblings run for that whole window. A task in
   uninterruptible sleep cannot be frozen at all until it wakes, so
   convergence has no upper bound in principle.
3. **It costs milliseconds per step**, which caps how many interleavings a
   discovery run can explore per second.

`ops.dispatch` has none of these. Gating is a map lookup on the enqueue path,
so the boundary is one scheduling round rather than a convergence wait; a
sleeping task is off-CPU already and gets gated on its way back in; and nothing
touches the syscall path, so there is no restart to correct for. The system-wide
risk is smaller than it looks — `SCX_OPS_SWITCH_PARTIAL` schedules only tasks
explicitly moved to `SCHED_EXT`, leaving the rest of the machine on CFS, and
`ops.timeout_ms` ejects a stuck scheduler.

**Until `ops.dispatch` lands, results against multi-threaded targets remain
unsound**, freezer or not.

## Build and test

The engine is pure Rust — no `build.rs`, no BPF, no `libbpf`. It builds and
tests anywhere, macOS included:

```bash
cargo test -p scx_crfuzz          # 90 tests on macOS, no kernel needed
```

The seccomp and freezer backends are behind `#[cfg(target_os = "linux")]`, and
their dependencies behind a target cfg in `Cargo.toml`, so none of it reaches
the host build. On Linux the same command runs 112 — the extra 22 are the
freezer's and the OCI preflight's own unit tests plus
`tests/thread_group_holding.rs`, `tests/exit_observation.rs` and
`tests/exit_status.rs`, which **skip themselves unless run as root** (they
install a seccomp listener and write `cgroup.freeze`). To actually exercise
them, inside the VM (see
`docs/environment/SCHED_EXT_VM.md`):

```bash
CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz
cd scheds/experimental/scx_crfuzz/scenarios && make   # builds threaded_victim
sudo CARGO_TARGET_DIR=/workspace/scx/target-linux cargo test -p scx_crfuzz
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
./run.sh race_wins.json --freezer   # same, holding whole thread groups
./go_run.sh                  # the Go victim; --freezer is load-bearing here
```

`--freezer` wraps the seccomp backend in `FreezerBackend` and switches each
`--spawn` into its own `<cgroup-path>/spawn<i>`. It is optional for the
single-threaded C fixtures (both scenarios give the same verdict with and
without it, at ~350 µs of added freeze latency per hold) and mandatory for
anything multi-threaded.

### Fixed: the stall timeout was 48,000x shorter than it looked

Writing the Go fixture surfaced a real bug, worth recording because the symptom
pointed nowhere near the cause. `go_run.sh` would end in
`TimedOut { reason: "no progress ... with 0 role(s) held" }` 9 runs in 10, with
`victim@exit` missing from the trace — while the victim had in fact run to
completion and printed its verdict.

The cause was not the role model and not the freezer. When a held child exits,
its seccomp notify fd reports **POLLHUP**, not POLLIN. POLLHUP is
level-triggered and never clears, so leaving that fd in the poll set made
`poll(2)` return immediately, forever. The backend produced no event, the
engine counted an idle round, and the loop span. `MAX_IDLE_ROUNDS` is 64 and the
poll timeout is 50 ms, so the stall budget is nominally 3.2 s — measured, it was
**66 µs**. The engine declared the run dead in the window between the child
exiting and `waitpid` being able to reap it.

That window scales with teardown cost, which is why it read as a Go problem: a
single-threaded C child is reaped inside 66 µs, an 11-thread Go child is not.

| Victim | OS threads | Completed / 10, before | after |
|---|---|---|---|
| `victim` (C) | 1 | 10 | 10 |
| `go_victim` (Go) | 11 | **1** | **10** |

The fix retires a hung-up fd from the poll set and sleeps the poll timeout when
nothing pollable is left but children are still unreaped, so an idle poll costs
real time again. `tests/exit_observation.rs` asserts exactly that, since the
engine's stall detector counts polls and has nothing else with which to measure
a stall.

Note for anyone extending the tests: `reap` calls `waitpid(None)`, which is
process-wide, so two backends in one test binary reap each other's children.
The engine only ever builds one, so this constrains tests rather than code.

## Running against runc and containerd

`runc` needs no new machinery — point `--spawn` at it instead of a fixture:

```bash
sudo scx_crfuzz --config scenarios/runc.json --cgroup-path /crfuzz/runc0 \
    --freezer --spawn "/usr/bin/runc run -b /tmp/bundle ctr1"
```

A full `runc run` is **279 structural syscalls across 31 tasks** (86 `openat`,
80 `newfstatat`, 54 `readlinkat`, 30 `mount`) — a tractable decision space, and
the readlinkat/mount traffic is the path-resolution surface the runc CVEs live
in. Only two of those tasks ever notify: the runc parent and `runc init`. They
resolve to one role occupant, because `resolve_role` matches `runc init`
through its *parent's* thread group. Worth checking if you change the role
config, since an unrecognised task is released immediately and never recorded —
the blast-radius guarantee — so a mismatched `comm` silently lets the
interesting half of runc run free rather than failing loudly.

Use `comm_match: substring`: `runc init` sets its comm to `runc:[2:INIT]`.

**containerd** is a daemon, and the seccomp backend installs its filter between
fork and exec — so there is nothing to spawn. Instead, intercept the `runc` the
shim execs. Nothing about containerd or the shim changes:

```
containerd (daemon)                  <- untouched
  └─ containerd-shim-runc-v2         <- untouched
       └─ runc create/start/delete   <- exec'd by path; the wrapper replaces it
```

```bash
sudo ctr run --rm --runc-binary scenarios/runc_wrapper.sh \
    docker.io/library/busybox:latest ctr1 /bin/echo hello
```

The shim makes four invocations per container — `create`, `start`, `delete`,
`delete --force`. `runc_wrapper.sh` instruments only `create`, which is where
the mounts and symlinkats happen; `start` merely signals an init that `create`
already built. The rest are exec'd straight through.

`--exit-with-child` is what makes this safe to put in the shim's path. The shim
reads the exit status to decide whether the container was created, so it has to
be runc's answer and not the engine's verdict on the scheduling run — otherwise
a `TimedOut` run reports failure for a container that started fine, and a
completed run reports success for a `runc create` that failed. It requires
exactly one `--spawn`, since with several there is no single status to report.

### The container's own seccomp profile can erase checkpoints

Seccomp filters **stack**. Installing one never removes another: every filter
runs on every syscall and the kernel takes the most restrictive action returned.
The precedence is

```
KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW
```

`USER_NOTIF` — the entire holding mechanism — sits *low*. `ERRNO` beats it. So
when a bundle carries a `linux.seccomp` block denying a syscall a checkpoint
sits on, runc installs that filter in the container init before `exec`ing the
entrypoint and the checkpoint stops firing. Measured with a fixture that added
`openat → ERRNO` to itself: the engine went from **5 observed `openat`
checkpoints to 4**, with no error, no warning, no failed release.

The silence is the problem. In replay, a step naming the erased checkpoint can
never be satisfied and the run times out looking like an engine bug. In
discovery, the interleaving space is quietly smaller than it appears and the
run reports "no race found" — a false negative in a tool whose job is finding
races.

`--oci-bundle <dir>` reads the bundle's `config.json` and refuses to start if
any configured checkpoint is masked:

```
Error: the bundle's seccomp profile erases 1 of this scenario's checkpoint(s):
  `mount` (mount) -> SCMP_ACT_ERRNO
```

`runc_wrapper.sh` passes it automatically, taking the path from runc's own
`--bundle`.

**It compares syscall numbers, not names**, because names produce false alarms.
Checked against a real resolved profile from a running container, the only
structural syscall that *looked* denied was `fstatat` — which is not a syscall
on aarch64 at all. The profile lists `newfstatat`, the name the architecture
actually uses. libseccomp reports two distinct failures and both need catching:
a name it does not know (`fstatat`) returns an error, while a name it knows that
the architecture lacks returns *successfully* as a negative pseudo-number —
`stat`, `lstat`, `access`, `readlink`, `rename`, `symlink`, `unlink`, `mknod`
and `umount` all land there on aarch64. Those are reported as "can never fire on
this architecture" rather than blamed on the profile.

Scope, since it is narrower than it first sounds: **runc's own work is
unaffected** — all 279 structural syscalls, the whole CVE surface, run before
the container profile is installed. Allowed syscalls are unaffected too, since
`ALLOW` loses to `NOTIFY`. Only denied syscalls in the container *payload* lose
their checkpoint.

## Controlling the interleaving on a multi-threaded target

The discovery→replay loop reproduces an interleaving, and editing the schedule
changes it. Measured against the 11-thread `go_victim`:

```bash
# capture
./go_run.sh --project-schedule /tmp/go.steps --canonical-log /tmp/go.log
# replay it: canonical log is byte-identical to the discovery run, 3/3
```

Moving one step — `racer@renameat` from before the victim's check to between
its check and its use — flips the security verdict, 5/5 each way:

| Schedule | Verdict |
|---|---|
| `… racer@renameat … victim@newfstatat …` (`go_race.json`) | `refused-symlink` |
| `… victim@newfstatat \| racer@renameat \| victim@openat …` (`go_wins.json`) | `read=SECRET` |

Same binaries, same freezer, only the position of one release differs. Note the
five leading `victim@openat` steps: replay names *every* release, and the Go
runtime opens five files before `main` — which is what the generator's
contention filter exists to handle for a target the size of runc.

This is control of the ordering *between roles*, at checkpoints. It is not
control of which thread inside a thread group arrives first: that is §14-A, and
it is still not reproducible. The freezer makes the other threads stop; it does
not make them stop in a chosen order.

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
