# Engine

`src/engine.rs` (429 lines). Owns the run: drives the backend, maintains the
ready set, asks the policy, writes the log.

## Phases

```
Barrier  ──(every `one` role seen at least once)──>  Enforcing
                                                        │
                            (policy returns Drain, or   │
                             the scenario ends)         v
                                                    Draining
```

- **Barrier** — wait until every `one`-cardinality role has appeared. Pool roles
  are excluded: a pool's membership is not fixed at barrier time, so waiting on
  it would never complete. `policy.on_barrier(&one_roles)` fires on transition.
- **Enforcing** — hold everyone, release one at a time.
- **Draining** — nothing left to enforce; release everything as it arrives.

## The ready set

A `Vec<ReadyCheckpointHit>`, one entry per role currently held at a checkpoint:

```rust
struct ReadyCheckpointHit { role, role_name, checkpoint, handle }
```

The pid is deliberately **not** in this struct. It is kept in a parallel
`ready_pids` vector, so a policy structurally cannot see a pid and start
depending on one.

## The decision loop

```rust
while !self.ready.is_empty() {
    self.decisions.push(/* the ready set, for the trace */);
    match self.policy.decide(&self.ready) {
        Decision::Release(i) => { self.release_at(i, true)?; break; }
        Decision::Drain      => { self.phase = Phase::Draining; break; }
        Decision::Divergence(reason) => { /* per config.on_divergence */ }
    }
}
```

The `break` after a release is load-bearing. Exactly one role runs at a time, so
the loop stops rather than draining the ready set — the released role must reach
its next checkpoint (or exit) and rejoin before the next decision is made.

### Divergence

When no ready entry satisfies the policy, `config.on_divergence` decides:

| Value | Behaviour |
|---|---|
| `abort` | end the run as `Diverged { step_idx, reason }` |
| `block` | stop deciding this round; wait for more arrivals |
| `skip` | call `policy.skip()` and retry |

`skip` is guarded: an unchanged reason means skipping achieved nothing, so it
degrades to `block` rather than spinning.

## Events

The backend reports three things, and the engine's handling of each is where
the role model meets reality:

| Event | Handling |
|---|---|
| `TaskAppeared(TaskInfo)` | record `pid -> tgid`; try to resolve a role |
| `CheckpointHit { pid, checkpoint, handle }` | if the pid resolves to a role, push onto the ready set; **otherwise release immediately and never record it** |
| `TaskExited(pid)` | if it resolves *and* is the thread-group leader, push a synthetic `exit` checkpoint onto the ready set |

The unrecognised-task path is the **blast-radius guarantee**: a bug in this
engine must not be able to hang unrelated work on the machine. It is also a
silent failure mode — a mismatched `comm` means the interesting half of a
target runs free rather than the run failing loudly. This bit during runc
bring-up and is worth checking whenever a role config changes.

Only the **thread-group leader's** exit counts. A role is a thread group, so a
single Go runtime thread going away is not the role exiting. A pid never
announced defaults to being its own leader.

## Stall detection

`MAX_IDLE_ROUNDS = 64` consecutive idle polls ends the run as `TimedOut`. The
engine counts polls and has **no other clock**, so this is only meaningful if an
idle poll actually waits — a backend that can return `Idle` without blocking
silently converts a multi-second timeout into a microsecond one. That was a real
bug; see [backends.md](backends.md) and `tests/exit_observation.rs`.

## Outcomes

```rust
enum RunOutcome {
    Completed,
    Diverged { step_idx, reason },
    TimedOut { reason },
}
```

§14-H is open: a discovery run where the racer's action causes an uninteresting
early failure — the container simply fails to start — maps onto none of these
cleanly. Distinguishing that from a real finding is the oracle's problem, and it
is also open, so the engine does not invent a category.

## The canonical log

One line per release, tab-separated:

```
# scenario toctou-rename-swap-go
0	victim	openat
1	racer	renameat
2	victim	openat
...
8	victim	exit
```

`project_to_steps()` maps each entry to `{ role, until }`, turning a discovery
log directly into a replay schedule. That round trip is verified byte-for-byte
against an 11-thread Go target — see [measurements.md](measurements.md).

A separate **debug log** carries pids, resolution provenance and timings. It is
never byte-compared; the canonical log is the reproducible artifact.

§14-D is open: nothing in the log identifies the config that produced it, so
"replay against a fresh instance of the same scenario" is not mechanically
checkable for a generated config.
