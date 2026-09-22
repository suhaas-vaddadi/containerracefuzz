# scx_crfuzz architecture

Reference for the ContainerRaceFuzz engine as built. Written to be read before
changing it, and to record which claims are measured and which are not.

Source: `scheds/experimental/scx_crfuzz/`.
Design doc: `docs/sched_replay/design_doc.md` (one level above the `scx`
checkout; the crate README's relative link dangles for a repo-only reader).

| Document | Covers |
|---|---|
| [engine.md](engine.md) | Phases, the ready set, the decision loop, the canonical log |
| [roles-and-checkpoints.md](roles-and-checkpoints.md) | What a role is, how tasks resolve to one, where execution stops |
| [policies.md](policies.md) | The `DecisionPolicy` seam and the four implementations |
| [backends.md](backends.md) | How a task is actually held: stub, seccomp, freezer |
| [harness.md](harness.md) | CLI, the runc wrapper, the OCI preflight |
| [measurements.md](measurements.md) | Every measured number, and what is still unverified |
| [gaps.md](gaps.md) | What is missing, in dependency order |

## The one-paragraph version

A scenario names **roles** (thread groups, matched by cgroup and comm) and
**checkpoints** (syscalls where execution may be stopped). A **backend** holds
tasks at those checkpoints and reports who is waiting. The **engine** keeps a
**ready set** of held roles and asks a **policy** which one to release, one at a
time, so exactly one role runs at any moment. Every release is appended to a
**canonical log**, which can be projected back into a replayable schedule.

## Shape

```
        scenario config (JSON)
                 |
                 v
   +---------------------------+        roles: cgroup + comm -> RoleRef
   |          Engine           |        ready set: who is held, and where
   |  Barrier -> Enforcing     |
   |          -> Draining      |---> canonical log --> project_to_steps()
   +-------------+-------------+                            |
       poll()    |   release(handle)                        v
                 v                                  replayable steps[]
   +---------------------------+
   |    CheckpointBackend      |   Stub | SeccompNotify | Freezer(SeccompNotify)
   +---------------------------+
                 |
                 v
        real processes (runc, containerd's runc, fixtures)
```

## Two modes, one engine

Replay and discovery differ in exactly one place: the answer to "what runs
next". That answer is the `DecisionPolicy` interface, not a second binary.
Because both modes write the same canonical log, turning a discovery finding
into a replayable schedule is a field drop, not a translation that would itself
need validating.

The mode is a property of the config, not a flag: a config carries either
`steps[]` or a `policy` block, and the type makes carrying both unrepresentable.

## Current state

**Working and measured:** the engine, the role algebra, all four policies, the
canonical log and its projection; seccomp holding of real processes; both
thread-group backends — the cgroup freezer and the `sched_ext` gate;
instrumentation of `runc` directly and of the `runc` that containerd's shim
invokes; deterministic control of interleaving on an 11-thread Go target.

**Not built:** the mutator, the oracle, the campaign driver. See
[gaps.md](gaps.md).

**Soundness caveat, narrowed:** `--gate` holds a thread group without touching
the held thread, so it does not restart the syscall it holds — the perturbation
the freezer introduces is gone. What remains open is §14-A: run-to-run
reproducibility against a multi-threaded target is still not guaranteed. The
freezer stays as the baseline the gate is measured against. See
[backends.md](backends.md).
