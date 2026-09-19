# Roles and checkpoints

`src/role.rs` (431), `src/checkpoint.rs` (191), `src/config.rs` (635).

## What a role is

A **role is a thread group**, not a process and not a thread. Holding a role
means holding every OS thread in it. This is the definition the design doc's
Background gives, and it is the one the seccomp backend alone does not satisfy.

```json
{ "id": "runc", "comm": "runc", "comm_match": "substring", "cardinality": "pool" }
```

| Field | Meaning |
|---|---|
| `id` | name used in `steps[]` and the canonical log |
| `comm` | matched against `/proc/<pid>/status` `Name:` |
| `comm_match` | `exact` (default) or `substring` |
| `cardinality` | `one` (default) or `pool` |
| `cgroup` | optional override; defaults to the scenario cgroup |

`one` admits exactly one thread group. A second, unrelated thread group matching
an already-claimed `one` role is **not** an occupant — it falls through to
unmodified dispatch rather than silently displacing the incumbent. `pool` admits
many, rendered `racer#0`, `racer#1`, …

## Resolution: four steps, in order

`RoleTable::resolve_role(&TaskInfo)`:

1. **Sticky per-pid cache** — already resolved, return it (`Provenance::Cached`).
2. **The task's own thread group** (`tgid`) — a `CLONE_THREAD` sibling
   (`ThreadGroup`).
3. **The parent's thread group** (`parent_tgid`) — a new process via fork/exec
   (`Parent`).
4. **First-time match** against the declared matchers: cgroup prefix **and**
   comm (`Matcher`).

Order matters. A Go runtime thread created via `CLONE_THREAD` has a parent
pointer referring to the wrong process, so consulting the task's own thread
group before its parent's is what stops it being misattributed.

Step 3 is why `runc init` — a separate process the runc parent forks — inherits
the parent's role rather than claiming a new pool slot. Measured on a real
`runc run`: two tasks notify (the parent and `runc init`), both resolve to
`runc#0`. It is also why a container's payload inherits the runtime's role, so
role alone cannot separate "runc setting up" from "the workload".

Returning `None` sends the task down the unmodified-dispatch path. See the
blast-radius note in [engine.md](engine.md).

## Checkpoints

```json
{ "id": "openat", "kind": "syscall", "target": "openat", "category": "mutating" }
```

`kind` is `syscall`, `uprobe`, `kprobe` or `lsm`. Only `syscall` has a backend;
the rest need `ops.dispatch`.

### The structural set

The default `checkpoints[]` for a discovery config — 22 syscalls, split by what
they do to a path:

**Resolving** — `stat` `lstat` `fstatat` `access` `faccessat` `faccessat2`
`readlink` `readlinkat`

**Mutating / committing** — `mount` `umount` `umount2` `openat` `rename`
`renameat` `renameat2` `symlink` `symlinkat` `unlink` `unlinkat` `mknod`
`mknodat`

Deliberately excluded: syscalls whose resolution depends on a directory fd
rather than the path string. Adding them is a design decision the doc has not
made, so the scaffold does not make it either.

### The effective set is smaller than 22

Measured on aarch64: **9 of the 22 do not exist** — `stat`, `lstat`, `access`,
`readlink`, `rename`, `symlink`, `unlink`, `mknod`, `umount`. The architecture
has only the `*at` variants. libseccomp reports this in two different ways and
both matter:

| Name | libseccomp | Meaning |
|---|---|---|
| `fstatat` | **error** | no such name on this architecture |
| `stat` | **Ok(-10174)** | known, but this architecture lacks it |
| `newfstatat` | `Ok(79)` | a real syscall here |

A checkpoint on any of the first two can never fire. The OCI preflight reports
them as such rather than blaming the container's seccomp profile — see
[harness.md](harness.md).

### The reserved `exit` checkpoint

A role's exit becomes an ordinary ready-set entry carrying `exit`, so a policy
sees one uniform kind of thing to decide over. It uses the reserved
`EXIT_HANDLE`, whose release is a no-op — there is no task left to release.

## Scenario scope

`cgroup` is the scenario's execution scope. Roles are recognised only inside it;
everything else on the machine is dispatched unmodified. `--cgroup-path` places
spawned processes within it and must be a prefix match, which the CLI checks.

Under `--freezer` each `--spawn` additionally gets its own
`<cgroup-path>/spawn<i>`, because roles sharing one cgroup share a freezer and
would deadlock each other.
