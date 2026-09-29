# Week 2 — Discovery algorithms, attacker/oracle, and rewiring the syscalls

With the scaffolding in place, this week was about *what* to run in the window
and *how to tell* when a run found something — plus fixing which syscalls the
engine holds on in the first place.

## Investigating the discovery algorithms

I read the two papers behind the discovery policies:

- **`pct.pdf`** — Burckhardt et al., *A Randomized Scheduler with Probabilistic
  Guarantees of Finding Bugs* (PCT). A depth-`d` bug is caught with probability
  at least `1/(k·n^(d-1))` for `n` threads and `k` decision points. This is
  already the `pct.rs` policy: parameters `d` (bug depth) and `k` (estimated
  decisions), ties broken by canonical `RoleRef` order.

- **`pos.pdf`** — *Partial Order Aware Concurrency Sampling* (POS). Instead of
  fixed priorities, it reweights only the events in a happens-before relation
  with the one just scheduled, which raises the hit probability on programs with
  many independent operations.

The takeaway for the engine: both fit the existing `DecisionPolicy` seam
unchanged — they only change *which* ready role is picked, and both must draw
from the seed independently of arrival order, since §14-A showed the ready
set's membership is itself timing-dependent. PCT exists; POS is the natural next
policy to add against the same interface.

## Rewiring the checkpoint syscalls

A checkpoint holds a task *at syscall entry* — a decision point just before the
call runs. A check-then-use race needs a hold after the check returns and before
the use re-resolves the path, and the use's own entry is exactly that spot. So I
narrowed the default checkpoint set to the syscalls that can *be* that second
resolution: opens, execs, directory-entry and metadata mutation, mount and root
changes, and chdir (44 names, 29 on aarch64). Check-shaped calls (`stat`,
`access`, `readlink`) are out of the default — a hold at their entry sits
*before* the check, outside the window — but stay declarable by hand.

This needed two backend changes for `execve`, whose checkpoint fires while the
task is still the old program: the spawned child's own launch exec now passes
unreported, and the pid is re-announced after any exec so a process that execs
into a role binary from a non-role can still match its role. `scx_crfuzz_gen`
now traces and emits only the same use-shaped set.

## Attacker / oracle design

I worked out the contract for the half that turns exposed windows into findings,
recorded in `docs/brainstorm/`. The core decision: **the attacker and the oracle
are separate and never reference each other.**

- **Attacker** — pluggable and user-authored. Given a window and the target
  paths, it performs filesystem/namespace actions and declares *nothing* about
  success. Because the victim is frozen at the start checkpoint, the attacker
  *cannot lose the race*; atomicity stops being about winning and becomes "does
  this verb leave the intended final state when the victim wakes?"

- **Oracle** — harness-owned and shared. It derives the *intended truth* from
  the OCI/scenario spec, then diffs the observed state. It never reads the
  attacker's action list, which is the payoff: a new attacker gets bug detection
  for free.

I catalogued the attack vocabulary in four families — leaf substitution,
ancestor redirection, anchor redirection, and content/attribute mutation — and
noted that the serious container escapes (CVE-2021-30465, CVE-2024-21626) live
in the redirection families, not the generic leaf/content ones. The oracle runs
one battery per window (identity, containment, anchor, integrity) and classifies
each outcome as VIOLATION, TOLERATED, ACTION-FAILED, or CRASH.

I also separated *attacker* from *interferer* in the threat model: for a TOCTOU
bug to be a security bug it must cross a trust boundary, and the unifying
abstraction is the **channel** the attacker uses to reach the window
(kernel-object, shared-memory, request-driven). The kernel-object channel is the
one that exists today and covers most runc/containerd history; the rest are
scoped as extensions.

## Where it stands

The discovery side has a validated algorithm (PCT) and a clear next one (POS).
The checkpoint set now matches the actual race window. The attacker/oracle
contract is fixed on paper; building the oracle is the first item of the next
stretch.
