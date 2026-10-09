// SPDX-License-Identifier: GPL-2.0
//
//! # ContainerRaceFuzz engine
//!
//! Finds check-then-use races in a container runtime by sweeping attack
//! windows. The victim (runc) is held at every checkpoint hit: seccomp
//! user-notification parks the thread at syscall entry, and with `--gate` the
//! `sched_ext` gate keeps the rest of its thread group off the CPU. At one
//! selected window an attacker runs while the victim is frozen, so the race
//! is won by construction rather than by timing. An oracle then diffs the
//! underlying objects the window resolved.
//!
//! A dry run lists the windows; the sweep runs once per window
//! (`scenarios/sweep.sh`). One attack per run makes every finding
//! attributable, and `(scenario, window)` replays it. This covers races whose
//! trigger is one swap placed between a check and a use -- depth 2 with one
//! attacker. A race that needs two swaps at two windows would need a sweep over
//! window pairs.
//!
//! | Module | |
//! |---|---|
//! | [`config`] | scenario schema |
//! | [`role`] | which tasks are the victim |
//! | [`checkpoint`] | the structural syscall set, path-argument table |
//! | [`engine`] | one run: hold, observe, attack, release |
//! | [`attacker`] | runs the external attacker in the window |
//! | [`oracle`] | a lightweight object diff of the window paths |
//! | [`backend`] | the holding seam, plus `StubBackend` for tests |
//!
//! The engine, oracle and victim resolution build and test on any host; the
//! seccomp and gate backends are Linux-only.

pub mod attacker;
pub mod backend;
/// Holds the victim's whole thread group via the `sched_ext` gate, without
/// restarting the syscall the held thread sits in. Linux-only.
#[cfg(target_os = "linux")]
pub mod backend_gate;
/// Holds a real process at a real syscall via `SECCOMP_RET_USER_NOTIF`.
/// Linux-only.
#[cfg(target_os = "linux")]
pub mod backend_seccomp;
pub mod checkpoint;
pub mod config;
pub mod engine;
pub mod oracle;
pub mod role;

pub use config::ScenarioConfig;
pub use engine::Engine;
pub use engine::RunOutcome;
