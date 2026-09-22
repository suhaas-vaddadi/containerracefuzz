// SPDX-License-Identifier: GPL-2.0
//
//! The ContainerRaceFuzz gate: a `sched_ext` scheduler that declines to place
//! a gated thread group on a CPU.
//!
//! Split out of `scx_crfuzz` for one reason: BPF needs a `build.rs`, and a
//! `build.rs` runs on every host. Keeping it here is what preserves
//! `scx_crfuzz`'s "builds and tests anywhere, macOS included" property.

pub mod bpf_intf;
pub mod bpf_skel;
pub mod client;

pub use client::GateMap;
