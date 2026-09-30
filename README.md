# ContainerRaceFuzz

Deterministic replay and race discovery for container-runtime TOCTOU bugs.

A scenario names **roles** (thread groups, matched by cgroup and comm) and
**checkpoints** (syscalls where execution may be stopped). A **backend** holds
tasks at those checkpoints and reports who is waiting. The **engine** keeps a
**ready set** of held roles and asks a **policy** which one to release, one at a
time, so exactly one role runs at any moment. Every release is appended to a
**canonical log**, which projects back into a replayable schedule.

## Crates

| Crate | What it is |
|---|---|
| [`scx_crfuzz`](scheds/experimental/scx_crfuzz) | The engine: roles, checkpoints, decision policies, the canonical log, and the checkpoint backends. Pure Rust; builds and tests on any host, macOS included. |
| [`scx_crfuzz_gate`](scheds/experimental/scx_crfuzz_gate) | The `sched_ext` scheduler that holds a whole thread group by declining to dispatch it, plus the `scx_crfuzz_gated` daemon. Linux only — it is a separate crate because BPF needs a `build.rs`, and a `build.rs` runs on every host. |
| [`scx_crfuzz_gen`](scheds/experimental/scx_crfuzz_gen) | `crfuzz_gen`: derives a discovery-mode scenario config by tracing each role with `strace` and keeping only the paths two or more roles touch. |

## Building

```bash
cargo test -p scx_crfuzz     # 90 tests on any host; 114 on Linux, which adds
                             # the seccomp and gate backend tests
cargo build --workspace      # scx_crfuzz_gate needs Linux, clang and libbpf
```

The gate needs a `sched_ext`-enabled kernel. The development VM
(`docs/environment/SCHED_EXT_VM.md`) and the design doc
(`docs/sched_replay/design_doc.md`) live one level above this checkout, outside
the repository.

## Provenance

This repository began as a checkout of
[sched-ext/scx](https://github.com/sched-ext/scx) and has been reduced to the
ContainerRaceFuzz crates plus the upstream support they depend on:

- `rust/scx_utils`, `rust/scx_cargo`, `rust/scx_stats` — the BPF build machinery
  and `struct_ops` helpers `scx_crfuzz_gate` links against.
- `scheds/include` — the shared BPF headers. `rust/scx_cargo/bpf_h` symlinks
  here, and its `build.rs` bakes the tree into the header tarball every BPF
  build unpacks.
- `OVERVIEW.md` — upstream's `sched_ext` reference, kept because the design
  documents cite it.

Everything else from upstream (the other schedulers, `scxtop`, the arena
library, CI and packaging) has been removed. It remains in this repository's
git history.

## License

GPL-2.0. See [LICENSE](LICENSE).
