# Synthetic check-then-use scenario

The minimal target the engine was first validated against (design doc §10.1,
§10.2). Two single-threaded static C programs and a three-file fixture.

| | syscalls it makes |
|---|---|
| `victim` | `readlinkat` (glibc startup), `fstatat`, `openat` |
| `racer` | `readlinkat` (glibc startup), `renameat` |

The victim checks a path with `fstatat(AT_SYMLINK_NOFOLLOW)` — "is this a plain
file, not a symlink?" — and then opens that path **by name**. The racer renames
a pre-made symlink over it. Land the rename between the two and the victim
reads a file it explicitly refused to accept.

Built `-static` on purpose: a dynamically-linked binary's loader makes dozens of
`openat`/`readlinkat`/`fstatat` calls before `main`, every one of them a
checkpoint in the §4.2 structural set. That is a real finding about
instrumenting real targets — and noise in a scenario meant to isolate two
syscalls. Even static glibc makes one `readlinkat` before `main`, which is why
it shows up in every canonical log here.

## Build and run

```sh
make                                     # victim, racer
./run.sh race_wins.json                  # swap lands between check and use
./run.sh race_loses.json                 # swap lands after the use
./experiment.sh <seed> <runs> <policy>   # distinct logs / arrival orders
./flake.sh <seed> <runs>                 # §14-A: per-run reproducibility
```

The engine binary is taken from `$CRFUZZ_BIN`, defaulting to
`/workspace/scx/target-linux/debug/scx_crfuzz`. **Build the guest side with a
separate target dir:**

```sh
CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz
```

Host and guest share this checkout over the VM mount. Without separate target
dirs, a `cargo build` on the macOS host drops Mach-O binaries into `./target`
and every subsequent run in the VM dies with "cannot execute binary file" —
which, mid-experiment, looks exactly like a resource leak in the backend.

## What the fixture is

`setup.sh` builds it fresh, because the racer consumes the symlink by renaming
it — the state is single-use, so every run needs a rebuild:

- `target` — a regular file containing `BENIGN`, what the victim expects
- `secret` — a file containing `SECRET`, what it must never read
- `evil` — a symlink to `secret`, which the racer renames over `target`

The victim's stdout is the oracle: `VERDICT:read=SECRET` (race won),
`VERDICT:read=BENIGN` (swap too late), `VERDICT:refused-symlink` (swap too
early — the check did its job).
