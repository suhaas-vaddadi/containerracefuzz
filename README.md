# scx_crfuzz

A deterministic concurrency-sampling and replay engine for filesystem
check-then-use bugs. It runs a program (the **SUT**) under a `sched_ext`
scheduler, holds it at its path syscalls, lets an attacker-privileged
**mutator** change the filesystem at each hold, and judges the end state
against a **canary** the attacker must never reach. A violation is reported
only after it has been replayed from a recorded schedule and minimized to the
one hold that causes it.

It is one executable, `scx_crfuzz`, that carries its own `sched_ext`
scheduler (the **gate**) and a built-in target that fuzzes a containerd →
shim → runc container start.

## Requirements

To run:

- Linux 6.12 or later with `sched_ext` (`CONFIG_SCHED_CLASS_EXT`), and no
  other `sched_ext` scheduler enabled.
- cgroup v2 at `/sys/fs/cgroup` and bpffs at `/sys/fs/bpf`.
- Root.
- `cp` and `chown` (coreutils).

The kernel also has to provide seccomp `WAIT_KILLABLE_RECV` (5.19),
`close_range` with `CLOEXEC` (5.11) and `openat2` (5.6). Any 6.12 kernel has
all three.

To build:

- Rust.
- `clang` for the BPF program, and libelf and zlib headers.
- `gcc` and a static libc. The build links the containerd target's mutator
  statically and embeds it in the binary.

| Distribution | Packages |
|---|---|
| Fedora | `sudo dnf install clang elfutils-libelf-devel zlib-devel gcc glibc-static` |
| Debian/Ubuntu | `sudo apt install clang libelf-dev zlib1g-dev gcc libc6-dev` |

The Fedora line is the one the build is tested on. The Debian line lists the
same packages under their Debian names but is untested.

On macOS the workspace builds and the pure tests run, but nothing executes.
Use a Linux VM. Development uses a Lima VM named `sched-ext`.

## Install

From a checkout:

```sh
cargo install --locked --path scx_crfuzz            # into ~/.cargo/bin
sudo install -m 755 ~/.cargo/bin/scx_crfuzz /usr/local/bin/
```

`sudo` resets `PATH`, so the second line puts the binary in `/usr/local/bin`,
which is on `sudo`'s `secure_path` on Fedora and Debian.
You can skip both lines and use `cargo build --release`, which leaves the
binary at `target/release/scx_crfuzz`.

A release binary, where one is published, is this same build for one
architecture. Install it the same way:
`sudo install -m 755 scx_crfuzz /usr/local/bin/`.

## Check the machine

```sh
sudo scx_crfuzz check
```

`check` prints one `ok` or `FAIL: <why>` line per check and exits 1 if any
check fails. It checks:

- root
- kernel 6.12 or later
- `sched_ext` is disabled, or the running scheduler is crfuzz's gate
- cgroup v2 at `/sys/fs/cgroup`
- bpffs at `/sys/fs/bpf`
- `/var/lib/crfuzz` and its parents are root-owned and writable only by
  root (where each run's canary lives)

`run`, `replay` and `containerd` run the same checks first and stop if any
fail, listing the failures.

## Quickstart

This fuzzes the bundled check-then-use fixture. Root `stat`s a path in a
directory the attacker owns, then opens and writes it. Run it from a
checkout. `scx_crfuzz` loads the gate scheduler itself.

```sh
cargo build --release

# The scenario: alice (65534) owns /tmp/q/alice; the SUT runs as root on alice/p.
mkdir -p /tmp/q/alice && sudo chown 65534:65534 /tmp/q/alice
cc -o /tmp/q/check_use scx_crfuzz/tests/fixtures/check_use.c

# layout: restores the starting filesystem before every run (as root).
printf '#!/bin/sh\nrm -f /tmp/q/alice/p\n: > /tmp/q/alice/p\n' > /tmp/q/layout.sh
# mutator: runs at a hold as alice; swaps p for a symlink into this run's canary.
cat > /tmp/q/swap.sh <<'EOF'
#!/bin/sh
[ "$1" = /tmp/q/alice/p ] || exit 0
ln -sfn "$CRFUZZ_CANARY/file" /tmp/q/alice/p.new && mv -f /tmp/q/alice/p.new /tmp/q/alice/p
EOF
chmod +x /tmp/q/layout.sh /tmp/q/swap.sh

sudo target/release/scx_crfuzz check

# One seed: a run per window, each new Violation confirmed by replay and minimized.
sudo target/release/scx_crfuzz run /tmp/q/one --seeds 1 --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p
echo $?   # 3: a confirmed finding

# Replay the finding (everything comes from the file); -v prints every decision.
sudo target/release/scx_crfuzz replay /tmp/q/one/findings/1/schedule

# 8 seeds, deduped. The fixed SUT (O_NOFOLLOW) gives 0 findings and exit 0.
sudo target/release/scx_crfuzz run /tmp/q/camp --seeds 8 --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p
sudo target/release/scx_crfuzz run /tmp/q/camp-fixed --seeds 8 --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p nofollow

# The same 8 seeds, 4 at a time, each worker with its own copy of alice's directory.
sudo target/release/scx_crfuzz run /tmp/q/camp4 --seeds 8 --jobs 4 --private /tmp/q/alice --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p

# A campaign with a time budget instead of a seed count, then resumed with more time.
sudo target/release/scx_crfuzz run /tmp/q/long --time 20s --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p
sudo target/release/scx_crfuzz run /tmp/q/long --time 20s --resume --attacker 65534:65534 \
  --mutator /tmp/q/swap.sh --layout /tmp/q/layout.sh -- /tmp/q/check_use /tmp/q/alice/p
```

The one-seed run prints this (abridged):

```
alice: uid=65534 gid=65534 groups=[] capeff=0000000000000000
plan: 1 seeds, 5 windows in seed 0, ~6 runs, est. 0s (+ confirms)
[1/1] seed 0: telemetry: 6 decisions (0 partial), 1 threads, 5 mutation targets, 0.0s
[1/1] seed 0 window 1/5: Clean  0.0s
...
[1/1] seed 0 window 4: Violation, confirming
  confirmed: Violation
  minimize step 3: Violation([Changed { entry: "file" }, Changed { entry: "hard" }])
  guilty: step 3 EventId { thread: "0", nr: 79, path: Some("/tmp/q/alice/p"), n: 0 }
left /var/lib/crfuzz/canary-272182-6: changed
[1/1] seed 0 window 4/5: Violation → confirmed, guilty step 3 (0 79 /tmp/q/alice/p) → finding #1 (new)  0.0s
...
[1/1] seed 0: unsafe
campaign: 1 seeds, 5 runs, 0 invalid, discovery 0.1s
seeds: 0 safe, 1 unsafe, 0 incomplete, 0 no windows
distinct partial orders: 1
partial decisions: 0/30 (0%)
findings: 2
finding #1: 1 runs, guilty (0 79 /tmp/q/alice/p), {Changed { entry: "file" }, Changed { entry: "hard" }}, /tmp/q/one/findings/1
finding #2: 1 runs, guilty (0 56 /tmp/q/alice/p), {Changed { entry: "file" }, Changed { entry: "hard" }}, /tmp/q/one/findings/2
```

Both holds on `p` let alice's swap through: the `stat` (`newfstatat`, 79 on
aarch64) and the `open` (`openat`, 56). Syscall numbers are the
architecture's.

Every Violation's canary, repeats included, is kept under `/var/lib/crfuzz`
as evidence (`left ...: changed`). Each run reports how many are there
(`N canaries from earlier runs`). One is kept per Violation, repeats
included, so they accumulate over long campaigns; remove them yourself when
you no longer need them. A SUT can leave a mount inside a canary, so first
check that `findmnt | grep /var/lib/crfuzz` shows nothing.

If a crash leaves gated tasks behind, `sudo scx_crfuzz reset` clears every
gate.

## The containerd target

`scx_crfuzz containerd` fuzzes a container start. A private containerd runs
as the SUT's child, so the shim and runc inherit the hold. It starts a
busybox container from a rootfs that alice owns. The mutator is
`tests/fixtures/mutator_all.c`, embedded in the binary. At each hold under the
rootfs it applies one of three primitives, picked by the hold's seed:

- a symlink exchange, modelled on runc's mount bug CVE-2021-30465
- a dangling link created ahead of the SUT
- a rebind of a path's subpath or ancestor, modelled on Kubernetes
  CVE-2021-25741

The target needs a few things beyond the general requirements:

- `containerd`, `ctr` and `runc` on root's `PATH`. Under `sudo`, that means
  on `sudo`'s `secure_path`, or kept with `sudo env PATH=$PATH`.
- A static busybox for the container's rootfs. The container holds no libc.
  Fedora's `busybox` package is static; on Debian, install `busybox-static`.

`check` does not test these. `containerd` adds four checks to its preflight:
`containerd`, `ctr` and `runc` on `PATH`, and `busybox image` (readable, an
ELF64 executable, no interpreter).

```sh
sudo target/release/scx_crfuzz containerd --seeds 2
```

A run takes about 8 s and a seed has about 50 windows, so two seeds take
about 15 minutes (measured on a 6-CPU VM).

```
scx_crfuzz containerd [--dir D] [--image BUSYBOX] [--attacker UID:GID]
                      [--seeds N] [--time DURATION] [--jobs N] [--resume] [-v]
```

| Flag | Meaning |
|---|---|
| `--dir D` | The scenario directory (default `/tmp/crfuzz-containerd`); its parent must exist. See the rules below. |
| `--image BUSYBOX` | The static busybox copied into the rootfs (default `/usr/bin/busybox`). |
| `--attacker UID:GID` | Alice, who owns the rootfs (default `65534:65534`). |
| `--seeds`, `--time`, `--jobs`, `--resume`, `-v` | As for `run`, passed through. With no `--seeds` or `--time` it runs until Ctrl-C. |

The target first recreates D:

- `rootfs/`, owned by alice, and a pristine copy, `rootfs.orig/`
- `mut/mutator_all`, also mirrored at the same path inside the rootfs, so the
  held task's view has it after `pivot_root`
- `sut.sh` and `layout.sh` (in `scx_crfuzz/targets/containerd/`)
- `run/` (the daemon's state)
- `logs/`: `mutator.log`, which alice can write, and `containerd.log`, with
  a `==` header line per SUT run
- `/run/containerd/s` and `/run/nri`, if they are missing

Then it runs the campaign `D/campaign` from D, the same as this command:

```
run D/campaign --attacker A [your flags] \
  --private D/rootfs --private D/run --private /run/containerd/s --private /run/nri \
  --mutator D/mut/mutator_all --layout D/layout.sh --scope D/rootfs -- D/sut.sh
```

The results are in `D/campaign`, laid out like any `run` directory.

The mutator reads these variables from the environment, all optional:
`CRFUZZ_PRIMITIVE` (`swap`, `dangling` or `pivot` for that primitive only,
`all` for all three in turn), `CRFUZZ_TARGET` and `CRFUZZ_ENTRY`. Set them through `sudo`, for example
`sudo env CRFUZZ_PRIMITIVE=swap scx_crfuzz containerd --seeds 2`.
`CRFUZZ_SCOPE` and `CRFUZZ_LOG` are always set to the rootfs and
`logs/mutator.log`.

Rules for D. Root runs `sut.sh` and `layout.sh` from D, so D must be safe from
other users:

- D, and every directory above it, must be owned by root and not writable by
  anyone else. A sticky directory such as `/tmp` is allowed. A D under your
  home directory is refused, because your home directory is owned by you.
- D must be empty, or a D from an earlier run, which is marked by
  `D/.crfuzz-containerd`. Anything else is refused, and nothing is deleted.

`--resume` keeps `D/campaign/` and `D/logs/`, recreates the rest, and resumes
the campaign. Without `--resume`, a D whose `campaign/` is not empty is
refused, so an earlier campaign and its findings are never deleted: resume
it, pass another `--dir`, or remove `D/campaign` yourself. Pass the same `--attacker` as before. A different `--image` is
not detected: the image is not part of the campaign's arguments, so the
resumed seeds run on the new image.

`scx_crfuzz containerd` replaces `scripts/fuzz_containerd.sh`. What changed:

- Flags replace the environment variables: `--dir` for `CRFUZZ_DIR`,
  `--image` for `CRFUZZ_IMAGE` and `--attacker` for `CRFUZZ_ATTACKER`.
  `CRFUZZ_BIN`, `CRFUZZ_GATED` and `CRFUZZ_CC` are gone, because the mutator
  is compiled at build time and `scx_crfuzz` loads the gate itself.
  `CRFUZZ_SCOPE` and `CRFUZZ_LOG` can no longer be overridden.
- `--seeds` is optional (no `--seeds` and no `--time`: run until stopped).
  `--time`, `--jobs`, `--resume` and `-v` are new.
- D is checked before anything is deleted: it must be root-only all the way
  up, and empty or a former D. The script ran `rm -rf` on any `CRFUZZ_DIR`.
- The preflight also checks `containerd`, `ctr`, `runc` and a static busybox.
- There is no `logs/scx_crfuzz.log`. The campaign's output goes to the
  terminal only, so redirect it yourself if you want to keep it.
- The rootfs, `run/`, `/run/containerd/s` and `/run/nri` are `--private`, so
  `--jobs` > 1 works. The layout and `sut.sh` therefore empty and refill
  these directories in place, where the script removed and recreated them.

From a Mac, `scx_crfuzz/scripts/vm_containerd.sh <seeds> [args...]` builds a
release binary in the Lima VM and runs the target there, passing the args
(`--resume`, `--dir D`, ...) to `containerd`.

## Commands

```
scx_crfuzz run DIR --attacker UID:GID [--seeds N] [--time DURATION] [--first-seed S] [--resume]
               [--jobs N] [--private DIR]... [--mutator PROG] [--layout PROG] [--scope DIR]... [--timeout SECS] [-v] -- CMD [ARGS...]
scx_crfuzz replay FILE [-v]
scx_crfuzz containerd [--dir D] [--image BUSYBOX] [--attacker UID:GID] [--seeds N] [--time DURATION] [--jobs N] [--resume] [-v]
scx_crfuzz gated | status | reset | check
scx_crfuzz --help | -h
scx_crfuzz --version | -V
```

Every command needs root except `--help`, `--version` and `check`, which
runs without root and reports `root: FAIL`.

### `run`

`run` sweeps seeds `S..S+N` into `DIR`, each seed over all its windows. With
no `--seeds`, it runs `S, S+1, ...` until `--time` runs out or it is stopped.
`DIR` must be absent or empty, unless you pass `--resume`. To study one seed,
use `run DIR --seeds 1 --first-seed S -v`.

| Flag | Meaning |
|---|---|
| `--attacker UID:GID` | The attacker identity ("alice"): no groups, no capabilities. Required, and never inferred. `4294967295` is refused. |
| `--seeds N` | How many seeds to sweep (default: until `--time` or a stop). A seed is a POS seed: the same seed gives the same partial order of held events. A seed runs its baseline, then one run per **window**. There is one window per distinct `(syscall, path, occurrence)` hold of the baseline that has a path. |
| `--time DURATION` | `90s`, `30m` or `2h` (a bare number is seconds). Once that much time has passed, no new run starts. The current run finishes, its seed is left incomplete, and the summary follows a `time limit: <S> seeds complete` line. Exit 0 or 3. |
| `--first-seed S` | The first seed (default 0). |
| `--resume` | Continue the campaign in `DIR`: one that was stopped, ran out of time, or needs more seeds. See [Resuming](#resuming). |
| `--jobs N` | Run N seeds at once (default 1), one worker each, all sharing the gate scheduler. N > 1 needs `--private`. Warns if N exceeds the CPUs, because contention makes more decisions partial. |
| `--private DIR` | Repeatable. Give each worker its own copy of DIR. Name every directory the runs write: the layout's target, the SUT's state, the mutator's playground. Recorded in the schedule, so `replay` sets it up again. See [Parallel seeds](#parallel-seeds). |
| `--mutator PROG` | Runs at one window's hold per run, as alice, inside the held task's namespaces, root and cwd. It gets the path as `argv[1]` and `CRFUZZ_PATH`, plus `CRFUZZ_SYSCALL`, `CRFUZZ_SEED` and `CRFUZZ_CANARY`. `CRFUZZ_CANARY` is this run's canary directory. Find the canary there, never by listing `/var/lib/crfuzz`, which at `--jobs` > 1 holds other workers' canaries. PROG must exist inside the task's root, and a script needs a `#!` line. It is killed after 15 s. A failure is logged, never a finding. |
| `--layout PROG` | Runs as root before **every** run (baseline, discovery, confirm, each minimization) to restore the starting filesystem. If it fails, the run is invalid. |
| `--scope DIR` | Repeatable. Only holds whose absolute path is under one of the DIRs (where the attacker can act) become windows. Default: every hold with a path. |
| `--timeout SECS` | End a run still going after SECS (1 to 30, default 30) as a `RuntimeError`. Recorded in the schedule, and `replay` uses it. |
| `-v` | Print every run's decision log (baseline, discovery, confirm, minimize). Without it, no decision log is printed, and a `replay` that fails says to rerun with `-v`. |

`--mutator`, `--layout`, `--scope` and `--private` take paths that must
exist. They are made absolute.

How a seed runs:

1. A **baseline** runs under the seed with no mutator. It must leak nothing,
   or the scenario is invalid. Its holds are the seed's windows.
2. One discovery run per window. The mutator fires at that window's hold.
3. A new Violation is confirmed by replay and minimized, as `replay` does. A
   Violation that repeats a known finding is only counted.

An invalid run or baseline is recorded, and the sweep goes on. Each seed
ends with a verdict:

- `safe`: every window was valid, mutated, and not a Violation.
- `unsafe`: some window was a Violation.
- `incomplete`: anything else (a window was invalid, or never reached its
  target).
- `no windows`: no mutator or no target, so the seed is one unmutated run.

**Outcome classes.** Each run gets one:

- `Violation`: alice can reach the canary, or has changed it.
- `RuntimeRefused`: the SUT exited nonzero (it noticed).
- `RuntimeError`: a signal, the `--timeout` deadline, or a failing baseline.
- `Clean`.

#### Resuming

`--resume` continues the campaign in `DIR`. Its arguments must match
`DIR/args`, except `--seeds`, `--time`, `--jobs` and `-v`, which may change,
and `--resume` itself.

- A seed with a line in `seeds.tsv` is complete and is skipped.
- Every other seed's `runs.tsv` rows, `runs/<seed>/` and `findings/*/seeds`
  lines are dropped, and the seed runs again from its start.
- Findings and the summary's totals carry on. A repeat of an earlier finding
  is counted against it. The count of distinct partial orders covers this
  session only.
- `--time` counts this session only.

The match is textual. `--mutator ./swap.sh` and `--mutator /tmp/q/swap.sh`
differ, even when they name the same file. A file whose contents changed since the first
session still matches, so keep the mutator, the layout and the SUT unchanged
across a resume.

#### Parallel seeds

With `--private DIR`, each worker runs in its own mount namespace. This
applies at any `--jobs`, `replay` included, so a scenario behaves the same at
any N.

- `/` is made `rslave`: host mounts still show, and nothing the worker mounts
  leaks out.
- A `cp -a` of DIR (DIR's own owner and mode too) is made under
  `/var/lib/crfuzz/work/<pid>/` and bind-mounted over DIR, once per worker.
- The layout, the SUT and the mutator inherit this view. The copies are
  removed at exit.

Only the filesystem is isolated. A scenario that collides on network ports,
abstract sockets or SysV IPC must run at `--jobs 1`.

A private DIR is a mount point in its worker, which has two consequences:

- A layout must restore DIR's *contents* (`rm -rf DIR/* && cp -a orig/. DIR/`).
  Removing and recreating DIR fails with `EBUSY`.
- A `rename` or `link` across DIR's boundary fails with `EXDEV`. Choose DIR so
  that whatever the SUT and the mutator rename between lives inside one DIR.

These are refused before any run:

- `--jobs` > 1 without `--private`
- a DIR that overlaps `/var/lib/crfuzz` (the canaries stay shared)
- a DIR that holds the campaign `DIR`

At `--jobs` > 1:

- Each seed's lines print as one block when the seed ends.
- `runs.tsv` rows are written in order of completion. The seed and window
  columns say which run each row is.
- Finding numbers are also given in order of completion.
  `findings/<n>/seeds` says where each finding came from.
- The files and the summary are otherwise the same as at 1.

### `replay`

`replay FILE` reruns a schedule. Everything comes from the file: the
command, attacker, mutator, layout, timeout, private directories and the
`CRFUZZ_*` environment of the `run` that wrote it, which `replay` sets
again (so a `containerd` finding replays as is; its D must still be there). It does
three things:

1. Runs a baseline.
2. Runs a replay with every recorded mutation. It must give the same outcome
   class and the same normalized findings.
3. Replays each recorded mutation alone, in order, until one flags one of the
   schedule's findings. That mutation's hold is the guilty hold.

SUT and layout output is discarded. With `-v`, the output goes to stderr and
every run's decisions are printed.

### The gate scheduler: `gated`, `status`, `reset`

```
scx_crfuzz gated    hold the gate scheduler in the foreground (until SIGINT/SIGTERM or ejection)
scx_crfuzz status   sched_ext state, scheduler and pins
scx_crfuzz reset    delete every gate entry of every run
```

There is one gate scheduler per machine, shared by every crfuzz process.
`run`, `replay` and `containerd` use the one that is running. If `sched_ext`
is disabled, each loads its own and holds it until it exits. A kill leaves
stale pins, which are harmless and are removed by the next load.

Start `scx_crfuzz gated` to keep one scheduler up across processes. The
on-target tests need it.

If another `sched_ext` scheduler is enabled, crfuzz refuses to start and
names that scheduler (from `/sys/kernel/sched_ext/root/ops`).

A gated task held past 30 s trips the `sched_ext` watchdog. The watchdog
ejects the scheduler and releases every run. The scheduler is also gone when
the crfuzz process that loaded it exits while others borrow it (start
`gated` to avoid that). A `replay` then fails the run. A campaign stops: the
runs then ending are discarded, it prints `scheduler lost: <S> seeds
complete` before the summary and exits 1, and `--resume` reruns the
unfinished seeds.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Finished with no findings. |
| 3 | Finished with a confirmed finding. For `replay`, a confirmed Violation. |
| 2 | A usage error. The usage is printed on stderr. |
| 1 | Any other error, including a failed preflight, a lost gate scheduler, or a `replay` that does not reproduce its schedule. |
| 130 | Stopped by Ctrl-C or SIGTERM. |

On a stop, the runs then ending are discarded. crfuzz cleans up the gates,
the run cgroup and the canary, then prints the summary after an
`interrupted: <S> seeds complete` line. A second signal kills at once.

## Output files

### Campaign directory

```
DIR/args                    run's arguments after DIR, one per line, escaped as in schedules
DIR/seeds.tsv               one row per seed (seed, verdict), written as the seed ends
DIR/runs.tsv                one row per window, written as it ends:
                            seed window class status finding decisions partial secs note
DIR/runs/<seed>/<k>.sched   window k's discovery schedule (replayable); k = 0:
                            the unmutated run of a seed with no windows
DIR/runs/<seed>/<k>.log     window k's SUT and layout output (stdout and
                            stderr): its discovery, then any confirm and
                            minimize runs, each after a header line
                            (== discovery, == confirm 2/3, == minimize step 12)
DIR/runs/<seed>/baseline.log  the same for the seed's baseline (== baseline)
DIR/findings/<n>/schedule   the first confirmed schedule of finding n
DIR/findings/<n>/seeds      every seed:k that hit finding n, one per line
DIR/findings/<n>/guilty     the schedule's guilty step, or - (needs more than one hold)
```

The SUT's stdin is `/dev/null`.

The `status` column is `new`, `repeat`, `unconfirmed` or `invalid` for a
Violation, and `-` otherwise. Findings are deduped by the guilty hold's
`(thread, syscall, path)` plus the normalized findings.

The terminal shows:

- a plan line, sized from the first baseline
- one line per window
- a verdict per seed. An invalid baseline gives a `-` window row, and the
  seed is `incomplete`.
- a summary: seeds, runs, invalid runs, the seeds' verdicts, discovery time,
  distinct partial orders (runs whose canonical order of dependent events
  differs), the share of partial decisions, and each finding

### Schedule file

Schedules are written to `runs/<seed>/<k>.sched` and
`findings/<n>/schedule`. A schedule has space-separated lines. In paths and
arguments, bytes outside printable ASCII, space and `%` are written as `%XX`.
An empty string is a lone `%`.

```
crfuzz-schedule 1
seed 0
attacker 65534:65534
mutator /tmp/q/swap.sh            optional
layout /tmp/q/layout.sh           optional
timeout 30                        optional: --timeout, only if not 60
private /tmp/q/alice              optional, one per --private
env CRFUZZ_PRIMITIVE swap         optional, one per CRFUZZ_* variable at run time
deadline                          only if discovery ended at the deadline
cmd /tmp/q/check_use /tmp/q/alice/p
outcome Violation
finding Changed file              normalized; also Reached <entry> <at>, Copy <at>
step 1 0 79 0 /tmp/q/alice/p      mutate thread syscall-nr occurrence [path]
```

## How it works

```
 CMD (SUT) ──seccomp-notify──▶ GateBackend ──▶ engine loop ──▶ oracle
   │  held at path syscalls      │ gate tree      │ POS or        │ canary +
   │  in a run cgroup,           │ (sched_ext)    │ fixed         │ probe as
   └─ SCHED_EXT                  │ while mutator  │ schedule      │ alice
                                 ▼ runs           ▼               ▼
                           mutator (as alice)   decision log ─▶ schedule file
```

1. **Hold** (`backend.rs`, `gate.rs`). The SUT starts in its own cgroup,
   enrolled in `SCHED_EXT`. A seccomp filter turns each watched path syscall
   into a user notification, and the thread sleeps until it is answered.
   While the mutator runs, every thread of the SUT tree is gated in the
   scheduler, so nothing moves.
2. **Readout** (`sensor.rs`). A decision is taken only when no SUT thread is
   running (a complete frontier), or after a 200 ms limit (logged as
   *partial*).
3. **POS** (`pos.rs`). Each held event is named
   `(thread, syscall, path, occurrence)`. Threads are named by their place in
   the creation tree (`0/2/0`), never by tid. Each event gets a seeded
   priority, and the highest is released. Only the events whose read/write
   key sets conflict with the released one are redrawn.
4. **Mutator** (`engine.rs`). At the first released hold that matches the
   run's window (by syscall, path and occurrence, in any thread), the tree is
   gated and the mutator runs once, as alice, in the held task's view.
5. **Oracle** (`oracle.rs`). Each run gets a fresh canary under
   `/var/lib/crfuzz/canary-<pid>-<n>` that alice cannot reach. At the root
   process's `exit_group`, alice probes everything the SUT touched plus every
   mount point. Afterwards the canary is compared with its starting state.
6. **Replay and minimization** (`schedule.rs`). Discovery's decisions become
   a schedule. Replay releases the recorded event at each step instead of
   POS's pick. A missing or extra event is a **divergence**. A Violation is
   *confirmed* when the replay gives the same outcome class and the same
   normalized findings (with the canary directory, pids and fd numbers
   stripped). Minimization replays once per mutated step, with only that
   mutation on, and reports the **first** step whose run still flags one of
   the findings: the guilty hold.
7. **Campaign** (`main.rs`). Seeds `S..S+N` run, each with its baseline and
   windows, `--jobs` of them at once. A Violation whose findings and guilty
   `(thread, syscall, path)` match a known finding is counted against it
   without being confirmed again. A new one is confirmed and minimized.

**Determinism.** The same seed gives the same partial order for 1:1-threaded
SUTs whose code between watched syscalls is deterministic. Under M:N
runtimes (Go), a thread name identifies the OS thread, not the goroutine.
There, determinism is checked by replay (a divergence) rather than
guaranteed.

## Repository layout

```
LICENSE                    GPL-2.0
scx_crfuzz/                the scx_crfuzz crate: engine, backend, POS, oracle, schedule, CLI
  build.rs                 builds the BPF skeleton and the static containerd mutator
  src/backend.rs           seccomp-notify hold, tree gate, mutator and probe
  src/sensor.rs            /proc double-snapshot readout (complete frontier)
  src/pos.rs               event identity, conflict keys, POS
  src/engine.rs            the discovery / replay loop
  src/oracle.rs            canary, attacker identity, outcome class
  src/schedule.rs          schedule file, fixed-schedule policy, finding
                           normalization, dedup, canonical partial order
  src/gate.rs              loads the gate scheduler; GateMap, its client
  src/bpf/main.bpf.c       the sched_ext gate scheduler
  src/main.rs              CLI: run, replay, containerd, campaign, gated/status/reset/check
  targets/containerd/      the containerd target's sut.sh and layout.sh
  scripts/vm_containerd.sh build in the Lima VM and run the containerd target
  tests/                   on-target tests and C/Go fixtures (mutator_all.c included)
```

## Testing

```sh
cargo test -p scx_crfuzz      # pure tests (POS, schedule, CLI parsing); also runs on macOS
```

The on-target tests are `#[ignore]`d. They need root and a running
`scx_crfuzz gated`. Some also need `cc`, `go`, `unshare`, `mount` or
`setpriv`; each file's header lists what it needs. Build the tests, then run
each test binary:

```sh
cargo test -p scx_crfuzz --no-run
sudo target/debug/scx_crfuzz gated &     # stop with sudo kill -TERM
sudo env PATH=$PATH target/debug/deps/<suite>-<hash> --include-ignored --test-threads=1
```

The suites are hold, sensor, clone, pos, mutator, probe, oracle, replay,
cli, campaign and gate.

## Limitations

- The oracle is filesystem-only. Shared memory, request-driven daemons, and
  PID, fd or IPC reuse are out of scope.
- Between a trap and the tree gate there is one userspace round trip, which
  lets siblings run briefly. A gate set in the kernel would close it.
- The watch set and the timing (the 200 ms frontier limit, the 15 s mutator
  watchdog) are fixed. `execve` is not watched.
- For `run`, the mutator is yours: no default primitives ship with `run`.
  The mutator is exec'd inside the held task's root.
- Minimization tries single holds only. A bug that needs two mutations is
  reported as "needs more than one hold" (`guilty` is `-`).
- Only canaries are watched. A leak of any other file is not seen. An
  exposure undone before the final hold is missed, and a SUT killed by a
  signal is judged on the canary's changes alone.
- `--resume` reruns a seed that was stopped partway from its start. Its
  argument match is textual (see [Resuming](#resuming)). For `containerd`,
  a different `--image` is not detected.
- `--jobs` isolates only the filesystem. The windows within one seed still
  run one after another.

## License

GPL-2.0-only. See [LICENSE](LICENSE).
