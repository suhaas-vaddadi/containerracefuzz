# Gaps

What is missing, in dependency order. Written before starting the fuzzer and
oracle work, so it records the state those decisions were made from.

## Where things stand

There is a **deterministic interleaving-control harness for runc**. There is not
a fuzzer. The scheduling half is real, measured and reproducible; the
generate → run → **judge** loop is mostly absent, and judge is the hard part.

## Blocking the fuzzer

### 1. Oracle — nothing decides whether a run found a bug

The single most important gap. With fixtures, a run is judged by reading a
`VERDICT:` string the fixture prints. runc prints no such thing. At 17,700
iterations/hour that produces 17,700 unjudged logs.

Design doc §7, with §14-B open on what separates a genuine violation from a
cleanly rejected racer action or an uninteresting failure to start. §14-H
(`RunOutcome` taxonomy) is the engine-side face of the same question.

Strictly downstream: consumes `RunOutcome` and the canonical log. Even a crude
first version — "did anything get mounted outside the rootfs" — unblocks
everything else.

### 2. The wrapper cannot carry a racer

`--exit-with-child` requires exactly one `--spawn`, so through
`ctr --runc-binary` you get runc alone and **zero branch points**. The
containerd path and the multi-role path are currently mutually exclusive.

Small fix: let the flag name which spawn to answer for.

### 3. Racer lifetime is hand-tuned

A racer that outlives the victim stalls the engine
(`no progress ... with 1 role(s) held`). But a racer that dies early leaves most
decisions forced — 5% branch points instead of 68%. The racer must currently be
tuned to the victim's checkpoint count, which is both fragile and backwards.

Wants either a racer whose lifetime is bounded by the victim's exit, or a policy
that handles a role outliving its counterpart.

### 4. Mutator — nothing generates what to attack

§6.1. Strictly upstream: emits an OCI spec plus the list of paths it references,
before runc is invoked. Today the attacked path is hand-picked. Without it,
"discovery" re-runs one hand-written scenario with varied timing.

### 5. Racer vocabulary is one verb

`scenarios/racer.c` renames. §6.2 wants symlink swap, rename, and
unlink-and-recreate, with *targets* supplied by the mutator. That separation is
what makes discovery capable of finding something novel.

### 6. No campaign driver

No seed sweep, no deduplication, no corpus, no triage. `scenarios/flake.sh` and
`experiment.sh` are measurement scripts, not a campaign.

## Closed

### 7. `ops.dispatch` backend — CLOSED

The intended holding mechanism. Implemented as `GateBackend`
(`src/backend_gate.rs`) over a `sched_ext` scheduler in a separate crate,
`scx_crfuzz_gate` — see the spec at
`docs/superpowers/specs/2026-09-19-crfuzz-ops-dispatch-gate-design.md` and
[backends.md](backends.md)'s `GateBackend` section. It eliminates the
freezer's syscall restart: `tests/handle_stability.rs` holds a fixture under
each mechanism and asserts opposite outcomes — the gate's `NotifyHandle`
survives the hold, a raw `cgroup.freeze` write does not — at the mechanism
level, below the `CheckpointBackend` trait that `FreezerBackend`'s contract
deliberately hides that churn behind.

What remains open: phase 2 (writing the gate entry in-kernel, in the trapping
task's own context, to close the residual userspace-round-trip window rather
than merely shrink it) is not built, and the 30 s `ops.timeout_ms` ceiling —
which the freezer had no equivalent of — caps how long any single hold can
last before the kernel ejects the scheduler for every concurrent run on the
machine, not just the one that overstayed.

## Still open

### 8. §14-A is answered but not eliminated

Same-seed runs are reproducible *given* `OrderedWalk`, because it draws its
target from the seed alone. The ready set's arrival order remains
non-reproducible, so a campaign must not assume run-to-run identity from any
policy that indexes by position.

## Out of scope by design

Class B PID/identity-reuse (§9) consumes this machinery and adds a cursor
tracker and filler-cycle planner. The dependency runs one way only — nothing
here references Class B — which is what makes it deletable without touching
Class A.

## Remaining open questions from §14

| | Question | Where it bites |
|---|---|---|
| 14-A | is the ready set's arrival order reproducible? | **answered: no** |
| 14-C | how is a pool hit identified in the log? | `RoleRef`, `Pct` |
| 14-D | nothing links a log to its originating config | `CanonicalLog` |
| 14-H | the run-outcome taxonomy | `RunOutcome`, and the oracle |
| 14-J | attachment race for late pool members | `CheckpointBackend::attach` |

## Suggested order

1. **Oracle**, crude but real — without it nothing else produces signal.
2. **Wrapper spawn count** — one small change, unblocks racers under containerd.
3. **Racer lifetime** bounded by the victim rather than a count.
4. **Mutator + racer vocabulary** — turns replay-with-jitter into discovery.
5. **Campaign driver.**
