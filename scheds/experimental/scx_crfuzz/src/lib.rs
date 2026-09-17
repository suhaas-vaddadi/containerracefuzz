// SPDX-License-Identifier: GPL-2.0
//
//! # ContainerRaceFuzz scheduling engine
//!
//! One engine, two modes, per `docs/sched_replay/design_doc.md`:
//!
//! - **Replay** enforces a schedule someone already wrote: the right tool for
//!   *reproducing* a known vulnerability.
//! - **Discovery** has no such schedule and must *decide* which of several
//!   roles sitting at their own checkpoints moves next, systematically enough
//!   that a TOCTOU violation gets found rather than hoped for.
//!
//! They differ in exactly one place -- the answer to "what happens next" --
//! which is why `policy::DecisionPolicy` is an interface inside one engine
//! rather than a second binary (section 3.1). Because both modes write the
//! same canonical log, turning a discovery finding into a replayable schedule
//! is a field drop (`log::CanonicalLog::project_to_steps`), not a translation
//! step that would itself need validating.
//!
//! ## Module map
//!
//! | Module | Design doc |
//! |---|---|
//! | [`config`] | section 8 (schema), Background |
//! | [`role`] | Background (role resolution), section 5 (pools) |
//! | [`checkpoint`] | section 4 (placement, the structural syscall set) |
//! | [`policy`] | section 3 (the decision-policy abstraction) |
//! | [`engine`] | Background (three-phase state machine) |
//! | [`log`] | Background (canonical log), section 3.5 (projection) |
//! | [`backend`] | Background (checkpoint mechanisms) |
//!
//! ## Status
//!
//! The engine, the policies, the role algebra and the log are real and tested
//! on any host against [`backend::StubBackend`], which scripts events instead
//! of holding anything.
//!
//! On Linux, [`backend_seccomp::SeccompNotifyBackend`] holds real processes at
//! real syscalls via `SECCOMP_RET_USER_NOTIF`. It covers every `syscall`
//! checkpoint, which is the whole of the section 4.2 default set, and needs
//! neither eBPF nor a `sched_ext` attach.
//!
//! It is not the whole story. seccomp user-notification holds the *thread*
//! that made the syscall; Background requires holding the whole thread group.
//! For a single-threaded target those coincide, and this backend is sound. For
//! a Go binary -- runc, containerd, the actual targets -- they do not, and the
//! `ops.dispatch` half of the base design is what closes the gap. Until that
//! exists, treat results against multi-threaded targets as unsound.
//!
//! ## Seams
//!
//! Components the design doc specifies but that are deliberately not in this
//! crate, with the interface each would attach to:
//!
//! - **`sched_ext` `struct_ops` backend** (Background). The remaining half of
//!   the holding mechanism: `ops.dispatch` declining to place a task on a CPU,
//!   which is what extends a hold from one thread to a whole thread group and
//!   what `uprobe`/`kprobe`/`lsm` checkpoints need. Implements the same
//!   [`backend::CheckpointBackend`]; nothing above it changes when it lands.
//! - **Mutator** (section 6.1). A pipeline stage strictly *upstream*: it emits
//!   an OCI spec plus the list of paths that spec references, before `runc` is
//!   invoked and therefore before any process tree exists for roles to be
//!   resolved against. It produces a [`config::ScenarioConfig`]; it never calls
//!   into the engine, and the engine never learns what OCI is.
//! - **Racer** (section 6.2). Not engine code at all -- an ordinary role, whose
//!   action vocabulary (symlink swap, rename, unlink-and-recreate) is fixed and
//!   small, and whose *targets* come from the mutator's path list. That
//!   separation is what makes discovery capable of finding something novel
//!   rather than re-running three known scripts with randomized timing.
//! - **Oracle** (section 7). Strictly *downstream*: consumes
//!   [`engine::RunOutcome`] and the canonical log, and derives what should have
//!   been true from the same OCI spec the mutator generated. Sections 14-B and
//!   14-H are open here -- what separates a genuine violation from a cleanly
//!   rejected racer action or an uninteresting failure to start, and when
//!   post-run state is sampled -- so the engine deliberately does not
//!   pre-empt either question.
//! - **Harness** (Background). Owns the disposable VM, the fresh scenario
//!   cgroup, and the supervisory wall-clock timeout measured from the canonical
//!   log's last advance. For PCT it also owns the throwaway counting run that
//!   estimates `k` (section 3.4); [`policy::Pct`] takes `k` as given.
//! - **PID/identity-reuse module, Class B** (section 9). Consumes the role,
//!   checkpoint and decision-policy machinery here and adds a cursor tracker
//!   and filler-cycle planner. That planner sits *outside*
//!   [`policy::DecisionPolicy`] by section 9.2's own argument: it is
//!   once-per-iteration resource planning over a namespace's whole allocation
//!   history, not a per-syscall reactive decision. The dependency runs one way
//!   only -- nothing in this crate references Class B -- which is what makes it
//!   deletable without touching Class A.
//!
//! ## Open questions that touch this code
//!
//! Design doc section 14 raises eleven; five bear directly on types here and
//! are marked at the relevant declaration: **14-A** (is the *ready set's*
//! arrival order itself deterministic? -- **answered, see below**), **14-C**
//! (how a pool hit is identified in the log -- [`role::RoleRef`],
//! [`policy::Pct`]), **14-D** (nothing links a log to its originating config --
//! [`log::CanonicalLog`]), **14-H** (the run-outcome taxonomy --
//! [`engine::RunOutcome`]), **14-J** (the attachment race for late pool members
//! -- [`backend::CheckpointBackend::attach`]). Only 14-A is resolved.
//!
//! ## Section 14-A is no longer open, and the answer is no
//!
//! The ready-set arrival order is **not** reproducible. Measured directly
//! against real processes (`scenarios/flake.sh`): holding the seed fixed and
//! varying nothing, roughly one run in a few hundred sees the two roles reach
//! their first checkpoint in the opposite order. The ready set then arrives at
//! `decide()` with the same two members in the other position, `RandomWalk`
//! indexes by position, a different member is released, and the entire run
//! diverges -- including the security verdict, which flips between "the victim
//! read the secret" and "the victim refused a symlink".
//!
//! Section 10.1 says ordering determinism "holds trivially if `decide()` is a
//! pure function of `(seed, ready-set-sequence)`". That premise is true here --
//! `decide()` is pure, and the unit tests prove it -- and the conclusion is
//! still false, because nothing makes the ready-set-sequence itself
//! reproducible. The condition is necessary, not sufficient.
//!
//! The exposure is concentrated where more than one role is runnable at once.
//! Once `Enforcing` is holding everyone but the single role it released, only
//! one process can be approaching a checkpoint, so arrival order is forced. The
//! window is the startup gap before the first hold, and any moment a released
//! role does not immediately reach its next checkpoint.
//!
//! Two fixes are available here. A narrow one -- canonicalise the ready set's
//! order before handing it to `decide()` (sort by role declaration index and
//! checkpoint id) -- would still leave a policy exposed to a subtler case:
//! two runs that see the same arrivals in the same order can still diverge,
//! because what `decide()` is handed is whichever ready-set snapshot existed
//! at that exact instant, and that snapshot's *membership* is itself
//! timing-dependent, not just its order.
//!
//! [`policy::OrderedWalk`] takes the stronger fix instead: it draws a target
//! *role* from the seed alone, before anything has run and independent of
//! the ready set entirely, and `decide()` only ever searches for that target
//! rather than indexing into arrival order. Real-world timing can then only
//! change *when* the target shows up, never *which* target was chosen.
//! [`policy::Pct`]'s tie-break was moved onto the same canonical `RoleRef`
//! ordering for the same reason. [`policy::RandomWalk`] keeps its original,
//! arrival-order-dependent behaviour -- it is retained as the literal
//! baseline the measurement above was taken against, not as a recommended
//! policy for a campaign that needs the reproducibility guarantee.
//!
//! This is still a scaffold-level judgment call, not something the design
//! doc itself has decided: §3.4 describes `RandomWalk` as uniform choice
//! "over the ready set," and `OrderedWalk`'s role-first, ready-set-blind
//! draw is a different reading of that. It is recorded here as the concrete
//! fix, with the reasoning that motivates it, not as a doc amendment.

pub mod backend;
/// The seccomp user-notification backend -- the one that holds real processes.
///
/// Linux-only, and deliberately so: keeping it behind a target cfg is what
/// lets the engine, policies, role algebra and log build and test on any host.
#[cfg(target_os = "linux")]
pub mod backend_seccomp;
pub mod checkpoint;
pub mod config;
pub mod engine;
pub mod log;
pub mod policy;
pub mod role;

pub use config::ScenarioConfig;
pub use engine::Engine;
pub use engine::RunOutcome;
pub use log::CanonicalLog;
