# scx_crfuzz

A deterministic concurrency-sampling and replay engine for filesystem
check-then-use bugs. It runs a program (the **SUT**) under a `sched_ext`
scheduler, holds it at its path syscalls, lets an attacker-privileged
**mutator** change the filesystem at each hold, and judges the end state
against a **canary** the attacker must never reach. A violation is reported
only after it has been replayed from a recorded schedule and minimized to the
one hold that causes it.

## Usage

### Requirements

- Linux with `sched_ext` (6.12+, `CONFIG_SCHED_CLASS_EXT`), cgroup v2, and
  seccomp `WAIT_KILLABLE_RECV` (5.19+). Root.
- Rust, plus `clang` and libelf/zlib headers for the BPF build.
- On macOS, the workspace builds and the pure tests run, but nothing executes:
  use a Linux VM (development uses a Lima VM named `sched-ext`).

### Quickstart

Build, start the gate daemon (one per machine, leave it running), then fuzz
the bundled check-then-use fixture: root `stat`s a path in a directory the
attacker owns, then opens and writes it.

```sh
cargo build --release
sudo target/release/scx_crfuzz_gated &          # until SIGINT
sudo target/release/scx_crfuzz_gated --status   # expect: enabled

# The scenario: alice (65534) owns /tmp/q/alice; the SUT runs as root on alice/p.
mkdir -p /tmp/q/alice && sudo chown 65534:65534 /tmp/q/alice
cc -o /tmp/q/check_use scx_crfuzz/tests/fixtures/check_use.c

# layout: restores the starting filesystem before every run (as root).
printf '#!/bin/sh\nrm -f /tmp/q/alice/p\n: > /tmp/q/alice/p\n' > /tmp/q/layout.sh
# mutator: runs at every hold as alice; swaps p for a symlink into the canary.
cat > /tmp/q/swap.sh <<'EOF'
#!/bin/sh
[ "$1" = /tmp/q/alice/p ] || exit 0
c=$(ls -dt /var/lib/crfuzz/canary-* | head -1)
ln -sfn "$c/file" /tmp/q/alice/p.new && mv -f /tmp/q/alice/p.new /tmp/q/alice/p
EOF
chmod +x /tmp/q/layout.sh /tmp/q/swap.sh

# One run: discover, and on a Violation confirm by replay and minimize.
sudo target/release/scx_crfuzz --attacker 65534:65534 --seed 0 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh --log /tmp/q/sched \
  -- /tmp/q/check_use /tmp/q/alice/p
#   outcome: Violation([Changed { entry: "file" }, ...])
#   confirmed: Violation
#   guilty: step 3 EventId { thread: "0", nr: 79, path: Some("/tmp/q/alice/p"), n: 0 }

# Replay that schedule later (everything comes from the file).
sudo target/release/scx_crfuzz --replay /tmp/q/sched

# A campaign over 8 seeds, deduped. The fixed SUT (O_NOFOLLOW) gives 0 findings.
sudo target/release/scx_crfuzz --campaign /tmp/q/camp --seeds 8 --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p
sudo target/release/scx_crfuzz --campaign /tmp/q/camp-fixed --seeds 8 --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p nofollow
```

Stop the daemon with Ctrl-C (or `kill -INT`). If a crash leaves gated tasks
behind, `sudo scx_crfuzz_gated --reset` clears every gate.

### `scx_crfuzz`

```
scx_crfuzz --attacker UID:GID [--seed N] [--mutator PROG] [--layout PROG] [--log FILE] -- CMD [ARGS...]
scx_crfuzz --replay FILE
scx_crfuzz --campaign DIR --seeds N --attacker UID:GID [--mutator PROG] [--layout PROG] -- CMD [ARGS...]
```

| Flag | Meaning |
|---|---|
| `--attacker UID:GID` | The attacker identity ("alice"): no groups, no capabilities. Required; never inferred. |
| `--seed N` | POS seed (default 0). Same seed ⇒ same partial order of held events. |
| `--mutator PROG` | Run at every hold whose event has a path, as alice inside the held task's namespaces, root and cwd. Gets the path as `argv[1]` and `CRFUZZ_PATH`, plus `CRFUZZ_SYSCALL` and `CRFUZZ_SEED`. Must exist inside the task's root. 15 s watchdog; a failure is logged, never a finding. |
| `--layout PROG` | Run as root before **every** run (baseline, discovery, confirm, each minimization, each campaign seed) to restore the starting filesystem. A failure makes the run invalid. |
| `--log FILE` | Write discovery's schedule; on a Violation, confirm and minimize. |
| `--replay FILE` | Rerun a schedule: baseline, strict confirm, minimize. |
| `--campaign DIR --seeds N` | Sweep seeds `0..N` (see below). `DIR` must be absent or empty. |

Every invocation first runs a **baseline** (no mutator) that must leak nothing,
else the scenario is invalid. Exit status is 0 whatever the outcome; nonzero
only for an invalid run (after printing the decisions made so far). Needs root
and a running `scx_crfuzz_gated`.

**Outcome classes** (one per run): `Violation` (alice can reach, or has
changed, the canary) / `RuntimeRefused` (the SUT exited nonzero: it noticed) /
`RuntimeError` (signal, the 60 s deadline, or a failing baseline) / `Clean`.

### `scx_crfuzz_gated`

```
scx_crfuzz_gated            run the daemon (until SIGINT or ejection)
scx_crfuzz_gated --status   sched_ext state + pins
scx_crfuzz_gated --kick     open the gate map and kick every CPU
scx_crfuzz_gated --reset    delete every gate entry of every run
```

One scheduler per machine. It refuses to start if another `sched_ext`
scheduler is enabled or another daemon holds its lockfile. A gated task held
past 30 s trips the `sched_ext` watchdog, which ejects the scheduler and
releases every run; `scx_crfuzz` detects that and fails the run.

## How it works

```
 CMD (SUT) ──seccomp-notify──▶ GateBackend ──▶ engine loop ──▶ oracle
   │  held at path syscalls      │ gate tree      │ POS or        │ canary +
   │  in a run cgroup,           │ (sched_ext)    │ fixed         │ probe as
   └─ SCHED_EXT                  │ while mutator  │ schedule      │ alice
                                 ▼ runs           ▼               ▼
                           mutator (as alice)   decision log ─▶ schedule file
```

1. **Hold** (`backend.rs`, `scx_crfuzz_gate`). The SUT starts in its own
   cgroup, enrolled in `SCHED_EXT`, with a seccomp filter that turns each
   watched path syscall into a user notification: the thread sleeps until it
   is answered. While the mutator runs, every thread of the SUT tree is gated
   in the scheduler, so nothing moves.
2. **Readout** (`sensor.rs`). A decision is taken only when no SUT thread is
   running (a complete frontier), or at a 200 ms limit (logged as *partial*).
3. **POS** (`pos.rs`). Each held event is named
   `(thread, syscall, path, occurrence)`, threads by their place in the
   creation tree (`0/2/0`), never by tid. Each gets a seeded priority; the
   highest is released, and only events whose read/write key sets conflict
   with it are redrawn.
4. **Mutator** (`engine.rs`). At each released hold with a path, the tree is
   gated and the mutator runs as alice in the held task's view.
5. **Oracle** (`oracle.rs`). Each run gets a fresh canary under
   `/var/lib/crfuzz/canary-<pid>-<n>` that alice cannot reach. At the root's
   `exit_group` alice probes everything the SUT touched plus every mount
   point; afterwards the canary is compared with its starting state.
6. **Replay and minimization** (`schedule.rs`). Discovery's decisions become a
   schedule. Replay releases the recorded event at each step instead of POS's
   pick; a missing or extra event is a **divergence**. *Confirmed* = same
   outcome class and the same normalized findings (canary directory, pids and
   fd numbers stripped). Minimization replays once per mutated step with only
   that mutation on and reports the **first** step whose run still flags one
   of the findings: the guilty hold.
7. **Campaign** (`main.rs`). Seeds `0..N` after one baseline. A Violation
   whose findings and guilty `(thread, syscall, path)` match a known finding
   is counted against it without re-confirming; a new one is confirmed and
   minimized.

**Determinism.** Same seed ⇒ same partial order for 1:1-threaded SUTs whose
code between watched syscalls is deterministic. Under M:N runtimes (Go) a
thread name identifies the OS thread, not the goroutine, so there it is
checked by replay (divergence) rather than guaranteed.

## Files

### Schedule file (`--log`, `runs/<seed>.sched`, `findings/<n>/schedule`)

Space-separated lines; in paths and arguments, bytes outside printable ASCII,
space and `%` are `%XX`, and an empty string is a lone `%`.

```
crfuzz-schedule 1
seed 0
attacker 65534:65534
mutator /tmp/q/swap.sh            optional
layout /tmp/q/layout.sh           optional
deadline                          only if discovery ended at the deadline
cmd /tmp/q/check_use /tmp/q/alice/p
outcome Violation
finding Changed file              normalized; also Reached <entry> <at>, Copy <at>
step 1 0 79 0 /tmp/q/alice/p      mutate thread syscall-nr occurrence [path]
```

### Campaign directory

```
DIR/runs.tsv                one row per seed, written as it ends:
                            seed class status finding decisions partial secs note
DIR/runs/<seed>.sched       every seed's discovery schedule (replayable)
DIR/findings/<n>/schedule   the first confirmed schedule of finding n
DIR/findings/<n>/seeds      every seed that hit finding n, one per line
```

`status` is `new`, `repeat`, `unconfirmed` or `invalid` for a Violation, `-`
otherwise. Findings are deduped by `(guilty thread, syscall, path, normalized
findings)`. The terminal shows one line per seed, then a summary: runs,
invalid runs, discovery time, distinct partial orders (runs whose canonical
order of dependent events differs), the share of partial decisions, and each
finding.

## Repository layout

```
scx_crfuzz/                engine, backend, POS, oracle, schedule, CLI
  src/backend.rs           seccomp-notify hold, tree gate, mutator and probe
  src/sensor.rs            /proc double-snapshot readout (complete frontier)
  src/pos.rs               event identity, conflict keys, POS
  src/engine.rs            the discovery / replay loop
  src/oracle.rs            canary, attacker identity, outcome class
  src/schedule.rs          schedule file, fixed-schedule policy, finding
                           normalization, dedup, canonical partial order
  src/main.rs              CLI: single run, replay, campaign
  tests/                   on-target tests and C/Go fixtures
scx_crfuzz_gate/           sched_ext gate scheduler, daemon and GateMap client
  src/bpf/main.bpf.c
```

## Testing

```sh
cargo test -p scx_crfuzz      # pure tests (POS, schedule); also runs on macOS
```

The on-target tests are `#[ignore]`d and need root and a running
`scx_crfuzz_gated`; some also need `cc`, `go`, `unshare`, `mount` or
`setpriv` (see each file's header). Build them, then run each binary:

```sh
cargo test -p scx_crfuzz --no-run
sudo env PATH=$PATH target/debug/deps/<suite>-<hash> --include-ignored --test-threads=1
sudo -E cargo test -p scx_crfuzz_gate -- --ignored --test-threads=1
```

## Limitations

- Filesystem oracle only. Shared memory, request-driven daemons and PID/fd/IPC
  reuse are out of scope.
- One userspace round trip between a trap and the tree gate lets siblings run
  briefly (an in-kernel gate would close it).
- The mutator is user-supplied; no default primitives ship. It is exec'd
  inside the held task's root.
- Minimization tries single holds only; a bug that needs two mutations is
  reported as "needs more than one hold".
- Campaigns run seeds sequentially, with no time budget and no resume.
