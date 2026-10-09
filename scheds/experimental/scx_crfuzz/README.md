# scx_crfuzz — ContainerRaceFuzz engine

Sweeps attack windows in a real container lifecycle, so a TOCTOU race is won
by construction rather than by timing.

## How it works

A scenario names the **victim** (thread groups matched by cgroup and `comm`,
plus their threads and children) and **checkpoints** (syscalls). The backend
holds the victim at every checkpoint hit. Each hit is a **window**, keyed
`<checkpoint>#<n>` (the victim's nth hit of that checkpoint). At one selected
window the engine runs the **attacker** on the path the syscall resolved, while
the victim is frozen; it then releases the victim. Tasks that are not the
victim's are released immediately.

A dry run (no window) lists the windows. The sweep (`scenarios/sweep.sh`) then
runs once per window. One attack per run makes every finding that window's
doing, and `(scenario, window)` is the reproducer. This finds races whose
trigger is one swap between a check and a use; two swaps at two windows would
need a sweep over pairs.

| Backend | Holds | Notes |
|---|---|---|
| `StubBackend` | nothing (scripted) | any host; engine tests |
| `SeccompNotifyBackend` | the calling **thread** | seccomp user-notification; siblings keep running |
| `GateBackend` (`--gate`) | the thread group | `sched_ext` scheduler in [`scx_crfuzz_gate`](../scx_crfuzz_gate); no restart; needs `scx_crfuzz_gated` running |

Why the thread group matters: runc and containerd are Go, and parking one Go
thread prompts the runtime to run more on others. Sibling bytes written during
a 300 ms hold:

| Fixture | OS threads | seccomp alone | `--gate` |
|---|---|---|---|
| `threaded_victim.c` | 2 | 255 | 0 |
| `go_victim.go` | 11 | 920 | 0 |

## Oracle

The oracle (`src/oracle.rs`) is a lightweight object diff. The engine collects
the path every window resolved; around the attacked window it takes an object
token of each before the attacker runs and again after, and reports any object
that changed. The token is a cheap, per-run-keyed hash of the object's identity
and metadata (device, inode, mode, owner, link count, size, mtime and ctime
with nanoseconds) -- one stat per path, no reads. Set
`"oracle": { "content": true }` to also fold in a regular file's first 64 KiB
(or a symlink's target) and to content-token each immediate child of a watched
directory, so a canary file the attacker plants in a swapped directory is
reported by name.

A finding is therefore always a change to a watched object, attributed to the
attacked window; detection does not depend on the attacker, so a new attacker
gets it for free.

**Coverage.** This is deliberately a minimal, lightweight subset of the bug
space. It sees object substitution and mutation (the leaf, content and
ancestor-redirection families). It does **not** see, and does not claim to:
pure reads (a canary-style leak leaves no object change), mount-table changes
that touch no watched path, cwd or directory-fd escapes, or privilege changes.
Those are future work.

## Config

```json
{
  "cgroup": "/crfuzz",
  "victim": { "comm": "runc", "comm_match": "substring" },
  "checkpoints": [{ "id": "mount", "kind": "syscall", "target": "mount" }],
  "attack": { "argv": ["attacker.sh", "{path}"], "at": "mount#3" },
  "oracle": { "content": false }
}
```

`checkpoints` defaults to the whole structural set; `at` and `oracle` are
optional, and `--at` overrides `at`.

## Build and test

```bash
cargo test -p scx_crfuzz      # any host, macOS included
```

On Linux the same command adds the seccomp and gate backend tests, which skip
unless root, and the gate cases unless `scx_crfuzz_gated` is attached. In the
VM:

```bash
CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz -p scx_crfuzz_gate
make -C scheds/experimental/scx_crfuzz/scenarios
sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated &
sudo CARGO_TARGET_DIR=/workspace/scx/target-linux cargo test -p scx_crfuzz
```

## Run

See [`scenarios/README.md`](scenarios/README.md). In the VM, as root:

```bash
./attack_run.sh                 # dry run: list runc's windows
./attack_run.sh mount#3         # attack one window
./sweep.sh                      # every window
```

Under containerd, intercept the `runc` the shim execs:

```bash
sudo CRFUZZ_AT=mount#3 ctr run --rm --runc-binary scenarios/runc_wrapper.sh \
    docker.io/library/busybox:latest ctr1 /bin/sleep 30
```

## Things to know

- **`--oci-bundle`** refuses to start if the bundle's seccomp profile denies a
  checkpoint's syscall: filters stack, `ERRNO` beats `USER_NOTIF`, and the
  checkpoint would silently never fire.
- **The gate caps holds at 30 s.** Longer trips the `sched_ext` watchdog, which
  ejects the scheduler and releases every gate on the machine. `GateBackend`
  detects the ejection and fails the run.
- **Use `comm_match: substring` for runc** (`runc init`'s comm is
  `runc:[2:INIT]`).
- **On aarch64, 15 of the 44 structural syscalls don't exist** (the legacy
  x86_64 names); each has an `*at` form in the set that does.
