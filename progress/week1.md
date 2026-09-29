# Week 1 — Scaffolding and crates

This week I stood up the skeleton of the `scx_crfuzz` project: the three crates
that hold a race open, decide what runs next, and derive a scenario to run.

## What I built

I split the work into three standalone crates under
`scheds/experimental/`, each with a single job.

- **`scx_crfuzz`** — the engine. One scheduler serves both *replay* of a
  hand-authored schedule and *discovery* of new interleavings. The load-bearing
  seam is `policy::DecisionPolicy`: RandomWalk, OrderedWalk, and PCT are all
  implementations of "which role goes next," and every one writes the same
  canonical log, so a discovery finding projects straight back into a replayable
  `steps[]`. Real holding runs on `SECCOMP_RET_USER_NOTIF`
  (`SeccompNotifyBackend`), validated in a VM against a victim/racer TOCTOU
  fixture. The kernel/privileged paths sit behind `cfg` gates, so the engine's
  own test suite runs on any host with no kernel in the loop.

- **`scx_crfuzz_gen`** — the config generator. It traces a pair of roles with
  `strace -f`, keeps only paths that two or more roles touch, and turns each
  surviving syscall into a checkpoint, categorized through the engine's *own*
  `STRUCTURAL_SYSCALLS` table rather than a second copy. It depends on
  `scx_crfuzz` only for its config/checkpoint types — never the engine,
  backends, or policies — and round-trips its output through the JSON schema so
  the result is valid by construction.

- **`scx_crfuzz_gate`** — the `sched_ext` gate. A BPF `struct_ops` scheduler
  plus the `scx_crfuzz_gated` daemon. Gating happens on the enqueue path: a task
  whose tgid has a pinned map entry goes to `HOLD_DSQ` instead of the global
  DSQ, and `ops.dispatch` drains it only once the entry is gone. Holding a whole
  thread group therefore costs a map lookup, and the held task is never
  touched — no signal, no wake, no syscall restart. `SCX_OPS_SWITCH_PARTIAL`
  keeps the rest of the machine on CFS; only enrolled targets are scheduled
  here.

## Architecture at a glance

```
config (JSON) --> Engine (ready set, policy.decide) --> canonical log --> steps[]
                     |  poll / release
                     v
              CheckpointBackend  (Stub | Seccomp | Freezer | Gate)
                     |  Gate: gate/ungate/kick via pinned BPF objects
                     v
              scx_crfuzz_gated (sched_ext) --> real processes
```

## Cleanup

I reduced the checkout from a full scheduler tree to a standalone
ContainerRaceFuzz project, dropping the `scx_rustland`/`scx_rlfifo` remnants and
unused deps, and rewrote the crate READMEs and architecture docs to match what
actually shipped.

## Where it stands

Built and measured: the engine, role resolution, the four policies, the
canonical log and its projection, seccomp holding of real processes,
thread-group holding by both cgroup freezer and the `sched_ext` gate, and
`runc`/containerd instrumentation. Not built yet — the mutator, the oracle, and
the campaign driver, which is where Week 2 starts.
