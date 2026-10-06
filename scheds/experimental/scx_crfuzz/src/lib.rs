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
//! | [`engine`] | Background; the full-readout thread table and decision loop |
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
//! checkpoint, which is the whole of the section 4.2 default set. A parked hit
//! holds only its own thread.
//!
//! The binary always wraps it in [`backend_gate::GateBackend`] (over
//! `scx_crfuzz_gate`, so `scx_crfuzz_gated` must be attached), which adds the
//! thread-state sensor the full readout is built on, and holds a thread or a
//! thread group off the CPU when the engine asks: the watchdog's freeze and
//! `auto_attack`'s attacker window.
//!
//! ## Seams
//!
//! Components the design doc specifies but that are deliberately not in this
//! crate, with the interface each would attach to:
//!
//! - **`sched_ext` `struct_ops` backend** (Background). Implemented, but in a
//!   separate crate: `scx_crfuzz_gate`, whose BPF program (`crfuzz_gate_ops`)
//!   and daemon (`scx_crfuzz_gated`) supply the gate maps, the dispatch queue
//!   that keeps a gated thread or thread group off the CPU, and the
//!   thread-state sensor. It is a separate crate because BPF needs a
//!   `build.rs`, and a `build.rs` runs on every host -- keeping it out of this
//!   crate is what preserves this crate's "builds and tests anywhere, macOS
//!   included" property. This crate's own [`backend_gate::GateBackend`] talks
//!   to it over the pinned maps.
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
//!   log's last advance.
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
//! (how a pool hit is identified in the log -- [`role::RoleRef`]), **14-D** (nothing links a log to its originating config --
//! [`log::CanonicalLog`]), **14-H** (the run-outcome taxonomy --
//! [`engine::RunOutcome`]), **14-J** (the attachment race for late pool members
//! -- [`backend::CheckpointBackend::attach`]). Only 14-A is resolved.
//!
//! ## Section 14-A: answered by the full readout
//!
//! Measured against real processes, the ready set's *arrival order* is not
//! reproducible, and neither is its *membership* at any instant chosen by
//! timing: decision 1 could see two of four threads parked while the other two
//! were still running toward their checkpoint. `decide()` being a pure
//! function of `(seed, ready-set-sequence)` (section 10.1) is necessary, not
//! sufficient.
//!
//! The engine therefore decides only at a full readout: every thread of the
//! run's cgroup at rest, the ready set exactly the threads parked at a
//! checkpoint, canonicalised, with each thread named by its clone path. POS
//! keys priorities from the seed and event identity alone. That makes
//! ready-set membership deterministic except for two counted cases --
//! decisions taken while a thread is frozen (`frozen_decisions`) or while a
//! Blocked thread is in a timed sleep (`timed_sleep_decisions`) -- and for
//! memory races between checkpoints that change which syscall a thread
//! reaches next, which are out of scope.

/// The attacker runner: how the engine invokes a user-authored attacker inside
/// each window (`PolicyType::AutoAttack`). Portable -- `std::process` -- so it
/// tests on any host.
pub mod attacker;
pub mod backend;
/// The `ops.dispatch` gate and the thread-state sensor.
///
/// Linux-only. It freezes a thread or a whole thread group when the engine
/// asks, by declining to dispatch it; a thread parked in its seccomp
/// notification stays parked, so the notification id the engine was given
/// stays valid. It also reports every thread's state in the run's cgroup.
#[cfg(target_os = "linux")]
pub mod backend_gate;
/// The seccomp user-notification backend -- the one that holds real processes.
///
/// Linux-only, and deliberately so: keeping it behind a target cfg is what
/// lets the engine, policies, role algebra and log build and test on any host.
#[cfg(target_os = "linux")]
pub mod backend_seccomp;
pub mod checkpoint;
pub mod config;
pub mod engine;
/// POS event identity and conflict keys (plan Phase 1). Pure Rust, tests on any
/// host; the kernel-side key capture lives in `backend_seccomp`.
pub mod event;
pub mod log;
/// The oracle: the harness-owned detector run after each use. Each window runs
/// the full battery -- host integrity, canary, mounts, handles, privileges --
/// against the intended truth in the config's `oracle` block.
pub mod oracle;
pub mod policy;
pub mod role;

pub use config::ScenarioConfig;
pub use engine::Engine;
pub use engine::RunOutcome;
pub use log::CanonicalLog;
