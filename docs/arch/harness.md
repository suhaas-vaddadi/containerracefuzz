# Harness

Everything outside the engine: the CLI, the runc wrapper, the OCI preflight.
`src/main.rs` (442), `src/oci_preflight.rs` (419), `scenarios/`.

These are placeholders for the harness the design doc specifies, which is why
`--spawn` and `--cgroup-path` are not in §8's schema.

## CLI

```
scx_crfuzz --config <json> [options]
```

| Flag | Purpose |
|---|---|
| `--spawn <cmdline>` | launch and instrument a process (repeatable) |
| `--cgroup-path <p>` | where to place spawned processes; must sit under the config's `cgroup` |
| `--freezer` | wrap in `FreezerBackend`; forces per-spawn cgroups |
| `--gate` | wrap in `GateBackend` (the `sched_ext` gate, `scx_crfuzz_gate`); requires `scx_crfuzz_gated` already attached; mutually exclusive with `--freezer` |
| `--oci-bundle <dir>` | refuse to run if the bundle's seccomp profile erases a checkpoint |
| `--exit-with-child` | exit with the spawned process's status, not the engine's verdict |
| `--project-schedule <p>` | write the canonical log back out as a replay schedule |
| `--canonical-log <p>` / `--debug-log <p>` | where logs go |
| `--poll-timeout-ms` | default 50 |
| `--verbose` | debug logging |

There is no `--replay` / `--discover` flag: the mode is a property of the config.

With no `--spawn`, the engine runs against `StubBackend` and holds nothing.

Exit status is the **engine's verdict** by default — `0` for `Completed`, `2`
otherwise — because measurement shell loops need to tell those apart without
parsing the log. `--exit-with-child` inverts that, and does so unconditionally,
including on a timeout: a wrapper that substitutes its own verdict is exactly
the failure the flag exists to prevent. It requires exactly one `--spawn`, since
with several there is no single status to report.

## runc, directly

`--spawn` is the whole change:

```bash
sudo scx_crfuzz --config scenarios/runc.json --cgroup-path /crfuzz/runc0 \
    --freezer --spawn "/usr/bin/runc run -b /tmp/bundle ctr1"
```

Role config needs `comm_match: substring` — `runc init` sets its comm to
`runc:[2:INIT]`.

## containerd, via the wrapper

containerd is a daemon and the seccomp backend installs its filter between fork
and exec, so there is nothing to spawn. Instead intercept the `runc` the shim
execs. Nothing about containerd or the shim changes:

```
containerd (daemon)                  <- untouched
  └─ containerd-shim-runc-v2         <- untouched
       └─ runc create/start/delete   <- exec'd by path; the wrapper replaces it
```

```bash
sudo ctr run --rm --runc-binary scenarios/runc_wrapper.sh \
    docker.io/library/busybox:latest ctr1 /bin/echo hello
```

The shim makes four invocations per container, measured:

```
runc --root R --log L --log-format json create --bundle B --pid-file P ID
runc ... start ID
runc ... delete ID
runc ... delete --force ID
```

`runc_wrapper.sh` instruments only **`create`** — the invocation that does the
mounts and symlinkats — and execs the other three straight through. It finds the
subcommand by skipping global flags and their values rather than grepping for
the string `create`, which would misfire on `--bundle /var/lib/.../create`.

### Wrapper limitation

`--exit-with-child` requires exactly one `--spawn`, so the wrapper **cannot
currently carry a racer alongside runc**. Through containerd you get runc alone,
which means zero branch points. Every multi-role measurement was taken against a
direct runc invocation. Unblocking this means letting the flag name *which*
spawn to answer for.

## OCI preflight

`src/oci_preflight.rs`. Binary-only, not part of the library: the crate docs put
OCI strictly upstream and say the engine never learns what OCI is, so this sits
with `--spawn` as harness work.

**The problem.** Seccomp filters stack. Installing one never removes another:
every filter runs on every syscall and the kernel takes the most restrictive
action returned.

```
KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW
```

`USER_NOTIF` — the whole holding mechanism — sits *low*. `ERRNO` beats it. A
bundle whose `linux.seccomp` denies a checkpoint's syscall therefore erases that
checkpoint **silently**: no error, no failed release, the notification simply
never arrives. Measured with a fixture that added `openat → ERRNO` to itself:
the engine went from 5 observed `openat` checkpoints to 4.

That silence is the danger. In replay the erased step can never be satisfied and
the run times out looking like an engine bug. In discovery the interleaving
space is quietly smaller than it appears and the run reports "no race found".

**The check.** Compares syscall **numbers**, not names, and refuses to start:

```
Error: the bundle's seccomp profile erases 1 of this scenario's checkpoint(s):
  `mount` (mount) -> SCMP_ACT_ERRNO
```

Names produce false alarms: checked against a real resolved profile, the only
structural syscall that *looked* denied was `fstatat`, which is not a syscall on
aarch64 at all. See the resolution table in
[roles-and-checkpoints.md](roles-and-checkpoints.md).

Three outcomes: **masked** (refuse), **conditional** (warn — arg-conditional
rules, or a profile with its own `NOTIFY` listener), **absent on this arch**
(warn — nothing to do with the profile).

**Scope, narrower than it sounds.** runc's own work is unaffected: all 279
structural syscalls run before the container profile is installed. Allowed
syscalls are unaffected, since `ALLOW` loses to `NOTIFY`. Only denied syscalls
in the container *payload* lose their checkpoint.

## Fixtures

| File | Purpose |
|---|---|
| `victim.c` / `racer.c` | single-threaded check-then-use TOCTOU pair |
| `threaded_victim.c` | pthreads; 2 threads |
| `go_victim.go` | goroutines, `LockOSThread`; 11 OS threads. Built `CGO_ENABLED=0` so the dynamic loader's own path syscalls do not become checkpoints |
| `race_wins.json` / `race_loses.json` | replay; swap before vs after the use |
| `go_race.json` / `go_wins.json` | discovery and forced-win replay on the Go victim |
| `runc.json` / `runc_wrapper.sh` | runc scenario and the containerd stand-in |
