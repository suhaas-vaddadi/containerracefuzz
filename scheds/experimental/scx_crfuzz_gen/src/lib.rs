// SPDX-License-Identifier: GPL-2.0
//
// scx_crfuzz_gen: a standalone tool that derives a discovery-mode
// scx_crfuzz scenario config from real traced behavior. Depends on
// scx_crfuzz only for its config types (see the crate's design doc,
// docs/superpowers/specs/2026-09-16-crfuzz-config-generator-design.md) --
// never for Engine, CheckpointBackend, or DecisionPolicy.

pub mod derive;
pub mod tracer;
