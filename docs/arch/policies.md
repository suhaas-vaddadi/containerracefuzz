# Decision policies

`src/policy/` — `mod.rs` (125), `fixed.rs` (204), `ordered_walk.rs` (334),
`pct.rs` (301), `random_walk.rs` (102).

The seam that makes replay and discovery one engine.

## The interface

```rust
pub trait DecisionPolicy {
    fn name(&self) -> &'static str;
    fn on_barrier(&mut self, _roles: &[RoleId]) {}
    fn decide(&mut self, ready: &[ReadyCheckpointHit]) -> Decision;
    fn skip(&mut self) {}
    fn is_finished(&self) -> bool { true }
}

pub enum Decision {
    Release(usize),       // release ready[index]
    Divergence(String),   // nothing here satisfies me
    Drain,                // nothing further to enforce
}
```

`decide` is only ever called with a non-empty ready set.

`on_barrier` receives **only `one`-cardinality roles**. Pool membership is not
fixed at barrier time, which is exactly the tension §14-C notes against PCT's
"assign each role a random priority at barrier time". A policy that cares must
say what it does about late arrivals.

`is_finished` separates "every role finished and the run is simply over" from
"every role finished while the schedule still had steps left". An algorithmic
policy would happily keep deciding, hence the default `true`.

## The four

| Policy | Mode | Behaviour |
|---|---|---|
| `FixedSchedule` | replay | walk `steps[]` in order; `Divergence` if the named step is not in the ready set; `Drain` at the end |
| `RandomWalk` | discovery | uniform choice **by position in the ready set** |
| `OrderedWalk` | discovery | draw a target *role* from the seed, then search the ready set for it |
| `Pct` | discovery | priority-based, with the tie-break on canonical `RoleRef` ordering |

### A step is one release, not a "run until"

`{ "role": "victim", "until": "mount" }` means *let the victim past exactly this
`mount`*, not *let it run freely until it reaches a `mount`*. A hand-authored
schedule must therefore name **every** release, not only the interesting ones.

The cost is visible: replaying the Go fixture needs five leading
`victim@openat` steps, because the Go runtime opens five files before `main`.
For `runc create` the equivalent prefix is ~89 steps. Hand-authoring does not
scale; `--project-schedule` and the generator exist for this.

The other reading would break the discovery→replay guarantee, since a discovery
log records individual releases and could not be re-expressed as run-untils.

## §14-A: the ready set's arrival order is not reproducible

**Answered, in the negative, by measurement.** Holding the seed fixed and
varying nothing, roughly one run in a few hundred has two roles reach their
first checkpoint in the opposite order (`scenarios/flake.sh`). The ready set
then reaches `decide()` with the same members in the other position, a
position-indexing policy releases a different one, and the whole run diverges —
including the security verdict.

§10.1 says ordering determinism "holds trivially if `decide()` is a pure
function of `(seed, ready-set-sequence)`". That premise is true here and the
conclusion is still false: nothing makes the ready-set-sequence itself
reproducible. The condition is necessary, not sufficient.

Two fixes were available:

- **Narrow** — canonicalise the ready set's order before `decide()`. Insufficient:
  two runs seeing the same arrivals in the same order can still diverge, because
  what `decide()` is handed is whichever snapshot existed at that instant, and
  its *membership* is timing-dependent too, not just its order.
- **Taken** — `OrderedWalk` draws a target role from the seed alone, before
  anything has run and independent of the ready set. Timing can then change
  *when* the target appears, never *which* target was chosen. `Pct`'s tie-break
  moved to the same canonical ordering.

`RandomWalk` keeps its arrival-order-dependent behaviour on purpose: it is the
literal baseline the measurement was taken against, not a recommended policy.

This is a scaffold-level judgment call, not a doc amendment. §3.4 describes
`RandomWalk` as uniform choice "over the ready set"; `OrderedWalk`'s
role-first, ready-set-blind draw is a different reading of that.

## What a policy can actually explore

A decision is only a choice if the ready set has more than one member.
Otherwise it is a forced release. Measured against `runc create`:

| Racer | Decisions | Branch points |
|---|---|---|
| one-shot (swap once, exit) | 94 | **5 (5%)** |
| persistent (30 swap cycles) | 152 | **104 (68%)** |

The policy is not the limiting factor here — scenario design is. A racer that
finishes in three steps leaves the remaining ~89 decisions with exactly one
runnable role and nothing to decide.
