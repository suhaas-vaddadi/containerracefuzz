# Scenarios

Three self-contained scenarios, one folder each, in increasing order of
complexity. All three run the partial-order policy (POS); each escalates what it
is scheduling.

| Folder | What it holds | Run |
|---|---|---|
| `01-single-thread/` | one single-threaded victim + one single-threaded attacker | `make run-01` |
| `02-multi-thread/` | a multithreaded victim + a multithreaded attacker, one actor per thread | `make run-02` |
| `03-containerd-runc/` | `runc create` under containerd + two multithreaded attackers | `make run-03` |

`fixtures/` holds binaries the Rust integration tests exec (`go_victim`,
`mt_hold`, `spin_park`, `pinned_wake`). They belong to no scenario but are
built by `make` so `cargo test` has them.

## Build and run

```sh
make                 # build every scenario's binaries + the test fixtures
make run-01          # scenario 1
make run-02          # scenario 2
make run-03          # scenario 3  (needs containerd)
make clean
```

Each `run.sh` uses `sudo` (seccomp user-notify needs root), and every run
needs the `sched_ext` gate daemon (`scx_crfuzz_gated`) attached: its sensor
reports every thread's state, which each decision waits on. The engine binary is `$CRFUZZ_BIN`, defaulting to
`/workspace/scx/target-linux/debug/scx_crfuzz`.

**Build the guest side with a separate target dir.** Host and guest share this
checkout over the VM mount; without a separate dir a `cargo build` on macOS
drops Mach-O binaries into `./target` and every run in the VM dies with "cannot
execute binary file":

```sh
CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz
```

## 1 — single thread (the basic proof of concept)

Two single-threaded static C programs (`victim`, `racer`) and a three-file
fixture laid out by `setup.sh`:

- `target` — a regular file containing `BENIGN`, what the victim expects
- `secret` — a file containing `SECRET`, what it must never read
- `evil` — a symlink to `secret`, which the racer renames over `target`

The victim checks a path with `fstatat(AT_SYMLINK_NOFOLLOW)` — "is this a plain
file, not a symlink?" — then opens it **by name**. The racer renames the symlink
over it. Land the rename between the check and the use and the victim reads a
file it explicitly refused. POS samples the orderings of their path-touching
syscalls. The victim's stdout is the oracle: `VERDICT:read=SECRET` (race won),
`VERDICT:read=BENIGN` (swap too late), `VERDICT:refused-symlink` (swap too
early — the check did its job).

## 2 — multiple threads (sample processes, no runc)

`threaded_victim` (a checking main thread plus a sibling worker) against
`mt_attacker` (several worker threads each hammering `renameat`). Under POS
every thread that reaches a checkpoint is its own actor, and a hit parks only
that thread. The engine decides only when every thread is at rest, so each
ready set holds every parked thread. The decision trace in the debug log names
threads by clone path (`role/t0.1`). The victim's sibling sleeps on a 1 ms
timer, so most decisions count in `timed_sleep_decisions` and two runs with one
seed can differ. `threaded_victim ... still` and `mt_attacker ... <renames>`
remove every timer; `tests/full_readout.rs` runs them that way and gets
identical decision traces from one seed.

## 3 — containerd + runc (full startup, two attackers)

A real `ctr run` of busybox. `runc_wrapper_attackers.sh` replaces the leaf
`runc` binary containerd's shim execs, and spawns the instrumented `runc create`
alongside two `mt_attacker` thread groups. POS, with thread actors, schedules all
three one thread at a time. See `03-containerd-runc/run.sh`.

## Why `-static`

A dynamically-linked binary's loader makes dozens of
`openat`/`readlinkat`/`fstatat` calls before `main`, every one a checkpoint in
the structural set — a real finding about instrumenting real targets, but noise
in a scenario meant to isolate a few syscalls. Even static glibc makes one
`readlinkat` before `main`, so it shows up in every canonical log here.
