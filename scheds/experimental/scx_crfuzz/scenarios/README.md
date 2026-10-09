# Scenarios

| File | What it is |
|---|---|
| `runc_attack.json` | The runc scenario: victim `runc` (substring, so `runc:[2:INIT]` too), held at `mount` and `symlinkat`, attacked by `attacker.sh`. |
| `attack_run.sh [window] [bundle] [id]` | One run against a scratch copy of an OCI bundle, under `--gate`. No window is a dry run. `CRFUZZ_CONFIG` picks the scenario. |
| `sweep.sh [bundle] [outdir]` | Dry run, then one `attack_run.sh` per listed window; prints every finding. |
| `fuzz.sh [bundle] [outdir]` | The seeded fuzzer: dry run, a reachability pass over the windows, then `CRFUZZ_FUZZ_SEEDS` seeds per reachable window. `(scenario, window, seed)` is the reproducer; the plan log records what each seed tried. |
| `attacker.sh` | The attacker: a **seeded, compositional mutator**, not a CVE-preset table. `CRFUZZ_ATTACK_SEED` fixes the plan; the sampler picks a target (leaf or an in-scope ancestor) and a recipe from a verb grammar (`symlink`, `exchange`, `recreate`, `hardlink`, `tree`, `overmount`, `meta`, `chain`, `compose`), with host-internal link payloads. It writes a plan record (seed, checkpoint, status, target, recipe, payload, result, `known=0/1`) so a finding is a replayable `(scenario, window, seed)` and is classifiable old vs new. The CVE corpus survives only as the `known=` tag. See the header for the full contract. |
| `runc_wrapper.sh` | Stands in for `runc` under `ctr run --runc-binary`; instruments only `runc create`. `CRFUZZ_AT` selects the window. |
| `threaded_victim.c`, `go_victim.go` | Fixtures for the backend tests (`make` builds them). |

Run in the VM as root, with `scx_crfuzz_gated` attached. The engine binary is
`$CRFUZZ_BIN`, defaulting to `/workspace/scx/target-linux/debug/scx_crfuzz`;
build the guest side with `CARGO_TARGET_DIR=/workspace/scx/target-linux`, since
host and guest share this checkout and macOS binaries in `./target` fail in the
VM with "cannot execute binary file".

A report is tab-separated: `window <key> <path>` per victim hit (a path under
the bundle is written `<bundle>/...`), then `finding <seen-at> <reason>`, then
`unreached <key>` if the selected window never came. A window key is
`<checkpoint>#<n>`, the victim's nth hit of that checkpoint. A finding in a dry
run is a false positive; an attacked run keeps only findings first seen after
the attack. The sweep flags a window whose path differs from the dry run's: two
thread groups hit that checkpoint concurrently and the key moved.
