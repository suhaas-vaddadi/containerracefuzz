//! crfuzz gate: the sched_ext scheduler (BPF), and `GateMap`, the client the
//! engine uses to drive it over the daemon's pinned objects (spec §3.2).

#[cfg(target_os = "linux")]
pub mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

#[cfg(target_os = "linux")]
mod gate_map;
#[cfg(target_os = "linux")]
pub use gate_map::*;
