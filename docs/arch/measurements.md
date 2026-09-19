# Measurements

Every number in these docs, with how it was obtained. Anything not here is not
measured.

Environment: Lima VM `sched-ext`, Fedora, kernel 6.19.10 **aarch64**, 6 cores,
runc 1.5.1, containerd v2.3.3, crun 1.27, podman 5.8.1, cgroup v2 unified.
Architecture matters — see the syscall-availability note below.

## Tests

| Target | Count |
|---|---|
| macOS host | **90** |
| Linux VM as root | **112** |

Split on Linux: 78 lib unit, 11 binary unit (OCI preflight), 18 `engine_run`,
3 `thread_group_holding`, 1 `exit_observation`, 1 `exit_status`. The last three
files skip themselves unless run as root.

## Thread-group holding

Sibling threads writing 1 byte/ms during a 300 ms hold:

| Fixture | OS threads | seccomp alone | with `--freezer` |
|---|---|---|---|
| `threaded_victim.c` (pthreads) | 2 | 255 bytes | **0** |
| `go_victim.go` (goroutines) | 11 | 920 bytes | **0** |

The fixture pins 5 threads; the Go runtime raised the other 6 on its own.

Freeze convergence latency: ~350 µs against fixtures, **702 µs** max against
runc. Siblings run for that whole window.

## The POLLHUP stall bug

| | Measured |
|---|---|
| Nominal stall budget (64 polls × 50 ms) | 3.2 s |
| Actual, with the spin | **66 µs** |
| Error | ~48,000× |

Completion rate, same config, only victim thread count differing:

| Victim | Threads | Before | After |
|---|---|---|---|
| `victim` (C) | 1 | 10/10 | 10/10 |
| `go_victim` (Go) | 11 | **1/10** | **10/10** |

Confirming detail: the first instrumented run *passed*, because an `eprintln`
per spin slowed the loop enough for the reap to win.

## Interleaving control

Discovery → `--project-schedule` → replay ×3 on the 11-thread Go victim:
**all four canonical logs byte-identical** (md5 `d37a82d1…`).

Moving one step flips the security verdict, 5/5 each way:

| Schedule | Verdict |
|---|---|
| `… racer@renameat … victim@newfstatat …` | `refused-symlink` |
| `… victim@newfstatat │ racer@renameat │ victim@openat …` | `read=SECRET` |

## runc

A full `runc run`, traced with `strace -ff`:

| | |
|---|---|
| Tasks in the process tree | 31 |
| Structural syscalls total | **279** |
| Tasks that notify | **2** (runc parent: 6, `runc init`: 82) |

By syscall: 86 `openat`, 80 `newfstatat`, 54 `readlinkat`, 30 `mount`,
8 `unlinkat`, 7 `mknodat`, 6 `symlinkat`, 4 `faccessat2`, 2 `faccessat`,
1 `umount2`, 1 `renameat`.

Instrumented: `Completed after 89 decision(s)`, stable 4/4. Both notifying
tasks resolve to `runc#0` (see the parent-tgid rule).

### Cost per iteration

| | ms |
|---|---|
| baseline `runc run` | 38 |
| instrumented, no freezer | 85 |
| instrumented + freezer | 138 |
| + persistent racer (152 decisions) | **203** |

≈ **17,700 iterations/hour/core** at the last row.

### Branch points

Decisions where more than one role is ready, i.e. where the policy actually
chooses:

| Racer | Decisions | Branch points |
|---|---|---|
| one-shot | 94 | **5 (5%)** |
| persistent, 10 cycles | 112 | 36 |
| persistent, 30 cycles | 152 | **104 (68%)** |
| persistent, 200 cycles | 251 | 184 — but **TimedOut** |

The 200-cycle run stalls with `no progress ... with 1 role(s) held`: the racer
outlived runc and the engine would not release it. Racer lifetime currently has
to be hand-tuned against the victim's checkpoint count.

## Seccomp filter stacking

Fixture adding `openat → ERRNO` to itself, under an engine already holding
`openat` with `NOTIFY`:

| Mode | Checkpoints the engine saw | The openat |
|---|---|---|
| no second filter | **5** | `fd=3` |
| second filter denies | **4** | `EPERM` |

Against a real resolved OCI profile (`defaultAction: SCMP_ACT_ERRNO`, 23
groups, pulled from a running container): **21 of 22** structural syscalls are
`ALLOW` and survive. The one apparent denial, `fstatat`, is a naming artifact.

## Syscall availability on aarch64

**9 of the 22 structural syscalls do not exist**: `stat`, `lstat`, `access`,
`readlink`, `rename`, `symlink`, `unlink`, `mknod`, `umount`. libseccomp
resolves them to negative pseudo-numbers; `fstatat` fails to resolve entirely;
`newfstatat` is 79.

## Not measured

- Whether holding `runc create` trips a containerd shim timeout. The
  uninstrumented create→start gap is 26 ms; instrumented create is hundreds of
  ms. Shim timeouts are seconds, so probably fine — untested.
- Any multi-role scenario **through the wrapper** (blocked by the
  `--exit-with-child` single-spawn rule).
- Anything on x86-64. All figures above are aarch64.
- Whether a freezer-induced syscall restart has ever changed an outcome, as
  opposed to being papered over.
