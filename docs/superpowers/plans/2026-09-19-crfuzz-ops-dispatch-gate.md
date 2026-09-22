# `GateBackend` (ops.dispatch gate) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hold every thread of a role by declining to dispatch it in a `sched_ext` scheduler, so multi-threaded targets are held without the freezer's syscall restart.

**Architecture:** A new Linux-only crate `scx_crfuzz_gate` carries a BPF `struct_ops` scheduler plus a daemon that attaches it once per campaign and pins a `tgid -> gate_entry` map to bpffs. A `GateBackend<B>` decorator in `scx_crfuzz` sits exactly where `FreezerBackend` sits: on a `CheckpointHit` it writes the held task's tgid into the pinned map and kicks CPUs; on `release` it deletes the entry, kicks, and only then answers the seccomp notification. The held thread is never touched.

**Tech Stack:** Rust, `libbpf-rs` 0.27, `scx_cargo` (build), `scx_utils` (compat enums), BPF C against `scheds/include/scx/common.bpf.h`, `libseccomp`/`nix` (existing).

**Spec:** `docs/superpowers/specs/2026-09-19-crfuzz-ops-dispatch-gate-design.md`

## Global Constraints

- **`scx_crfuzz` must still build and test on macOS: exactly 90 tests, no `build.rs`, no BPF.** The new crate is reached only through `[target.'cfg(target_os = "linux")'.dependencies]`.
- **Zero changes to `Engine`, `DecisionPolicy`, `role.rs`, or the canonical log.** The only edit outside the new crate is `backend_seccomp.rs`'s fork/exec window, plus new modules and CLI wiring.
- **Role granularity.** Gating is keyed by **tgid**, never by pid. A release resumes every thread of the thread group.
- `ops.timeout_ms = 30000` (the kernel maximum; `scx_chaos` and `scx_mlfq` both use it).
- Scheduler flags include `SCX_OPS_SWITCH_PARTIAL`, read through `scx_utils::compat::SCX_OPS_SWITCH_PARTIAL`, never hardcoded as `0x8`.
- `SCHED_EXT` policy number is `7` (`rust/scx_rustland_core/assets/bpf.rs:49` sets the precedent).
- Pinned paths: gate map `/sys/fs/bpf/crfuzz/gate`, epoch counter `/sys/fs/bpf/crfuzz/epoch`.
- **Never degrade silently.** Any failure that would leave a target un-held fails the run. This codebase's recurring bug class is silent under-holding (a mismatched `comm`, a seccomp profile erasing a checkpoint); do not add another.
- All privileged tests `skip_unless_root` and print why, matching `tests/thread_group_holding.rs`.
- Everything below runs in the Lima `sched-ext` VM (`docs/environment/SCHED_EXT_VM.md`), built with `CARGO_TARGET_DIR=/workspace/scx/target-linux`.
- Commit messages end with `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

---

### Task 1: Crate skeleton and a pass-through scheduler

The riskiest scaffolding (build system, BPF verifier, `struct_ops` attach) with no gating logic, so a failure here is unambiguous.

**Files:**
- Create: `scheds/experimental/scx_crfuzz_gate/Cargo.toml`
- Create: `scheds/experimental/scx_crfuzz_gate/build.rs`
- Create: `scheds/experimental/scx_crfuzz_gate/src/bpf/intf.h`
- Create: `scheds/experimental/scx_crfuzz_gate/src/bpf/main.bpf.c`
- Create: `scheds/experimental/scx_crfuzz_gate/src/bpf_skel.rs`
- Create: `scheds/experimental/scx_crfuzz_gate/src/bpf_intf.rs`
- Create: `scheds/experimental/scx_crfuzz_gate/src/lib.rs`
- Create: `scheds/experimental/scx_crfuzz_gate/src/main.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Consumes: nothing.
- Produces: a `scx_crfuzz_gated` binary that attaches and runs until SIGINT. No library API yet.

- [ ] **Step 1: Add the crate to the workspace**

In the top-level `Cargo.toml`, add to `[workspace] members`, immediately after the `scx_crfuzz_gen` line:

```toml
    "scheds/experimental/scx_crfuzz_gate",
```

- [ ] **Step 2: Write `Cargo.toml`**

Copy the dependency shape from `scheds/experimental/scx_mlfq/Cargo.toml`, dropping the stats crates (this daemon has no stats server):

```toml
[package]
name = "scx_crfuzz_gate"
version = "0.1.0"
edition = "2021"
description = "ContainerRaceFuzz gate: a sched_ext scheduler that declines to dispatch a gated thread group."
license = "GPL-2.0-only"

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive", "env", "unicode", "wrap_help"] }
ctrlc = { version = "3", features = ["termination"] }
libbpf-rs = "=0.27.0"
libc = "0.2"
log = "0.4"
scx_utils = { path = "../../../rust/scx_utils", version = "1.1.3" }
simplelog = "0.12"

[build-dependencies]
scx_cargo = { path = "../../../rust/scx_cargo", version = "1.1.3" }

[[bin]]
name = "scx_crfuzz_gated"
path = "src/main.rs"
```

- [ ] **Step 3: Write `build.rs`**

Copy `scheds/experimental/scx_mlfq/build.rs` verbatim — it is boilerplate that invokes `scx_cargo`'s BPF builder. Read that file and reproduce it; do not invent a different build path.

- [ ] **Step 4: Write `src/bpf/intf.h`**

```c
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CRFUZZ_GATE_INTF_H
#define __CRFUZZ_GATE_INTF_H

/*
 * One entry per gated thread group. `epoch` is written by userspace and never
 * read by BPF: it exists so a run's Drop can clear exactly the gates it owns
 * and leave a concurrent engine's gates alone.
 */
struct gate_entry {
	unsigned long long epoch;
};

#endif /* __CRFUZZ_GATE_INTF_H */
```

- [ ] **Step 5: Write the pass-through scheduler**

`src/bpf/main.bpf.c`. No gate map yet — every task goes to the global DSQ.

```c
/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(crfuzz_gate_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(crfuzz_gate_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Deliberately empty. The core drains SCX_DSQ_GLOBAL itself once
	 * ops.dispatch() returns, and SCX_DSQ_GLOBAL is NOT a valid source for
	 * scx_bpf_dsq_move_to_local -- verified on target: the kernel rejects
	 * it ("invalid DSQ ID") and disables the scheduler immediately. The op
	 * stays defined because Task 3 drops the HOLD_DSQ drain in this body.
	 */
}

s32 BPF_STRUCT_OPS_SLEEPABLE(crfuzz_gate_init)
{
	return 0;
}

void BPF_STRUCT_OPS(crfuzz_gate_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(crfuzz_gate_ops,
	       .enqueue		= (void *)crfuzz_gate_enqueue,
	       .dispatch	= (void *)crfuzz_gate_dispatch,
	       .init		= (void *)crfuzz_gate_init,
	       .exit		= (void *)crfuzz_gate_exit,
	       .timeout_ms	= 30000,
	       .name		= "crfuzz_gate");
```

- [ ] **Step 6: Write `src/bpf_skel.rs` and `src/bpf_intf.rs`**

Copy both from `scheds/experimental/scx_mlfq/src/`, changing only the skeleton name to match this crate. These are `include!` shims for the generated skeleton; read the mlfq versions and mirror them exactly.

- [ ] **Step 7: Write `src/lib.rs`**

```rust
// SPDX-License-Identifier: GPL-2.0
//
//! The ContainerRaceFuzz gate: a `sched_ext` scheduler that declines to place
//! a gated thread group on a CPU.
//!
//! Split out of `scx_crfuzz` for one reason: BPF needs a `build.rs`, and a
//! `build.rs` runs on every host. Keeping it here is what preserves
//! `scx_crfuzz`'s "builds and tests anywhere, macOS included" property.

pub mod bpf_intf;
pub mod bpf_skel;
```

- [ ] **Step 8: Write a minimal `src/main.rs`**

```rust
// SPDX-License-Identifier: GPL-2.0
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use scx_crfuzz_gate::bpf_skel::*;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn main() -> Result<()> {
    let mut open_object = std::mem::MaybeUninit::uninit();
    let builder = BpfSkelBuilder::default();
    let mut open_skel = builder.open(&mut open_object).context("open skel")?;
    open_skel.struct_ops.crfuzz_gate_ops_mut().flags |= *scx_utils::compat::SCX_OPS_SWITCH_PARTIAL;
    let mut skel = open_skel.load().context("load skel")?;
    let _link = skel.maps.crfuzz_gate_ops.attach_struct_ops().context("attach struct_ops")?;

    println!("crfuzz gate attached; Ctrl-C to detach");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::Relaxed))?;
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}
```

- [ ] **Step 9: Build it**

Run in the VM:

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz_gate'
```

Expected: builds clean. If the BPF verifier rejects the program, the error names the offending instruction — fix it before proceeding; do not attach a program that only half-loads.

- [ ] **Step 10: Verify it attaches and the machine survives**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated &
   sleep 3
   cat /sys/kernel/sched_ext/state
   cat /sys/kernel/sched_ext/root/ops
   sudo pkill -INT scx_crfuzz_gated'
```

Expected: `enabled`, then `crfuzz_gate`. The VM stays responsive throughout — with `SWITCH_PARTIAL` and no task enrolled, the scheduler should be handling zero tasks.

- [ ] **Step 11: Verify the macOS build is untouched**

```bash
cd /Users/suhaasvaddadi/VSCode/senior-thesis/scx && cargo test -p scx_crfuzz 2>&1 | tail -5
```

Expected: `90 passed`. If `cargo` tries to build `scx_crfuzz_gate` on macOS, the workspace membership is fine but something has added a non-target-gated dependency — nothing should depend on it yet.

- [ ] **Step 12: Commit**

```bash
git add Cargo.toml scheds/experimental/scx_crfuzz_gate
git commit -m "$(cat <<'EOF'
scx_crfuzz_gate: pass-through sched_ext scheduler skeleton

The scaffolding for the ops.dispatch gate, with no gating logic: every task
goes to the global DSQ. Attaches with SCX_OPS_SWITCH_PARTIAL, so with nothing
enrolled in SCHED_EXT it schedules nothing at all.

Separate crate because BPF needs a build.rs and a build.rs runs everywhere;
scx_crfuzz's macOS build is load-bearing for testing the engine off-target.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: The kick mechanism

Gating only affects a task at its next `ops.enqueue`. A sibling already running on a CPU keeps running until something preempts it. `scx_bpf_kick_cpu` is a BPF-side kfunc, so userspace needs a `SEC("syscall")` program to call it (`rs_select_cpu` in `rust/scx_rustland_core/assets/bpf/main.bpf.c:637` is the in-tree precedent for calling scx kfuncs from a syscall program, invoked via `prog.test_run`).

**Pre-verified on this kernel (2026-09-19), so Step 5's fallback should not be needed.** A standalone `SEC("syscall")` program calling `scx_bpf_kick_cpu(0, SCX_KICK_PREEMPT)` loads clean on the Lima `sched-ext` VM (kernel 6.19, aarch64):

```
660: syscall  name kick_from_syscall  tag 16e223eec1d13ee9  gpl
```

That is a real result rather than an absent error: the identical kfunc call from a `SEC("xdp")` program is rejected with `calling kernel function scx_bpf_kick_cpu is not allowed` / `-EACCES`, so the verifier does enforce the prog-type allowlist for this kfunc.

What remains unverified is *runtime* behaviour with a scheduler attached, which is what Step 3 checks. Keep Step 5 as the contingency.

**Files:**
- Modify: `scheds/experimental/scx_crfuzz_gate/src/bpf/main.bpf.c`
- Modify: `scheds/experimental/scx_crfuzz_gate/src/bpf/intf.h`
- Modify: `scheds/experimental/scx_crfuzz_gate/src/main.rs`

**Interfaces:**
- Produces: a `SEC("syscall")` program `crfuzz_kick_all` taking `struct kick_arg { unsigned int nr_cpus; }`, invoked from userspace via `prog.test_run`.

- [ ] **Step 1: Add the argument struct to `intf.h`**

Append, before `#endif`:

```c
struct kick_arg {
	unsigned int nr_cpus;
};
```

- [ ] **Step 2: Add the syscall program**

Append to `main.bpf.c`, before `SCX_OPS_DEFINE`:

```c
/*
 * Kick every CPU so any thread of a newly-gated thread group that is currently
 * on-CPU goes back through ops.enqueue and lands in the hold queue.
 *
 * Kicking all CPUs rather than tracking which ones run the group's threads:
 * the dev VM has few CPUs, a kick on an idle CPU is cheap, and a per-tgid CPU
 * map would have to be kept correct across migration for no measured benefit.
 */
SEC("syscall")
int crfuzz_kick_all(struct kick_arg *input)
{
	/*
	 * The bound comes from the kernel, not from userspace: a bad
	 * nr_cpus must never be able to produce an out-of-range CPU id.
	 * input->nr_cpus only caps it further. scx_bpf_nr_cpu_ids() is
	 * declared in scx/common.bpf.h and used in-tree by scx_mlfq.
	 */
	u32 nr = scx_bpf_nr_cpu_ids();
	u32 kicked = 0;
	u32 i;

	if (input->nr_cpus < nr)
		nr = input->nr_cpus;

	bpf_for(i, 0, nr) {
		scx_bpf_kick_cpu(i, SCX_KICK_PREEMPT);
		kicked++;
	}

	/*
	 * Return the count, not a constant. scx_bpf_kick_cpu is void, so a
	 * constant return would make the caller's check unfalsifiable -- it
	 * would pass identically with a broken or short-circuited loop.
	 */
	return kicked;
}
```

- [ ] **Step 3: Invoke it from `main.rs` once at startup, as a load test**

Insert after the `attach_struct_ops` line:

```rust
    // Verified at startup rather than at first use: if kicking is not
    // available, every hold would silently have a one-tick boundary instead of
    // a one-round one, which is exactly the kind of quiet under-holding this
    // engine must never do.
    {
        use libbpf_rs::ProgramInput;
        let nr_cpus = libbpf_rs::num_possible_cpus().context("num_possible_cpus")? as u32;
        let mut arg = nr_cpus.to_ne_bytes().to_vec();
        let input = ProgramInput {
            context_in: Some(&mut arg),
            ..Default::default()
        };
        // The `?` here is the check that catches the kfunc being unavailable
        // for this program type -- that failure surfaces as an Err, not as a
        // return value.
        let out = skel.progs.crfuzz_kick_all.test_run(input).context("kick prog test_run")?;
        anyhow::ensure!(
            out.return_value == nr_cpus,
            "kick prog kicked {} of {nr_cpus} cpus: it did not run its full loop, so holds \
             would be bounded by the scheduling slice instead of one round",
            out.return_value
        );
        println!("kick mechanism verified over {nr_cpus} cpus");
    }
```

What this self-test does and does not prove, stated so the comment does not overclaim: it proves the program loads, is callable from userspace while the scheduler is attached, and runs its loop to completion. It does **not** prove a sibling thread is actually preempted — that is unobservable at daemon startup with nothing enrolled in `SCHED_EXT`, and is what Task 3 Step 7 verifies by watching a ticking process stop.

- [ ] **Step 4: Build and run**

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz_gate \
   && sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated'
```

Expected: `kick mechanism verified over N cpus`, then `crfuzz gate attached`.

- [ ] **Step 5: If and only if the load fails**

A verifier error naming `scx_bpf_kick_cpu` as not allowed for this program type means the kfunc is not in a set registered for `BPF_PROG_TYPE_SYSCALL`. Fallback, which needs no userspace kick at all:

```c
/* Force a gated task off-CPU at the next tick rather than at slice end. */
void BPF_STRUCT_OPS(crfuzz_gate_tick, struct task_struct *p)
{
	if (is_gated(p->tgid))
		scx_bpf_task_set_slice(p, 0);
}
```

wired as `.tick = (void *)crfuzz_gate_tick`, plus a short `SCX_SLICE_DFL` replacement (start at 100 µs) in `enqueue` so an untick'd task is preempted promptly. `is_gated` arrives in Task 3, so with this branch, merge Task 2 and Task 3.

**Then stop and amend the spec.** The fallback's boundary is up to one tick (1–4 ms), which is *worse* than the freezer's measured ~350 µs. (The spec's "roughly an order of magnitude sharper" claim is not live to weigh this against — it was withdrawn outright, for an unrelated reason, in the spec's residual-window section.) The perturbation argument (no `ERESTARTSYS`) survives either way and is the load-bearing one, but the window claim must be rewritten to match what was built.

- [ ] **Step 6: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gate
git commit -m "$(cat <<'EOF'
scx_crfuzz_gate: verify the userspace kick mechanism

Gating only takes effect at a task's next ops.enqueue, so a sibling already
on-CPU needs a preempting kick. scx_bpf_kick_cpu is BPF-side, reached from
userspace through a SEC("syscall") program invoked with test_run -- the same
shape scx_rustland_core uses for rs_select_cpu.

Checked at daemon startup rather than at first hold: a missing kick would make
every hold quietly coarser instead of failing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Gate map, hold queue, and the gating decision

**Files:**
- Modify: `scheds/experimental/scx_crfuzz_gate/src/bpf/main.bpf.c`

**Interfaces:**
- Produces: BPF map `gate` (`BPF_MAP_TYPE_HASH`, key `u32` tgid, value `struct gate_entry`), and a `HOLD_DSQ` that the normal dispatch path never consumes.

- [ ] **Step 1: Add the map, the DSQ and the predicate**

Insert into `main.bpf.c` after `UEI_DEFINE(uei);`:

```c
/* A DSQ nothing consumes except the ungating path in ops.dispatch. */
#define HOLD_DSQ 1

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct gate_entry);
} gate SEC(".maps");

static __always_inline bool is_gated(u32 tgid)
{
	return bpf_map_lookup_elem(&gate, &tgid) != NULL;
}
```

- [ ] **Step 2: Create the DSQ in `init`**

Replace the body of `crfuzz_gate_init`:

```c
s32 BPF_STRUCT_OPS_SLEEPABLE(crfuzz_gate_init)
{
	return scx_bpf_create_dsq(HOLD_DSQ, -1);
}
```

- [ ] **Step 3: Gate on enqueue**

Replace `crfuzz_gate_enqueue`:

```c
void BPF_STRUCT_OPS(crfuzz_gate_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_gated(p->tgid)) {
		/*
		 * SCX_SLICE_INF because a held task is not competing for time:
		 * if it is ever moved out of HOLD_DSQ it was ungated, and the
		 * slice it gets then comes from the ungating path, not here.
		 */
		scx_bpf_dsq_insert(p, HOLD_DSQ, SCX_SLICE_INF, enq_flags);
		return;
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}
```

- [ ] **Step 4: Drain ungated tasks in dispatch**

Replace `crfuzz_gate_dispatch`:

```c
void BPF_STRUCT_OPS(crfuzz_gate_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;

	/*
	 * Anything in HOLD_DSQ whose gate has since been deleted goes back to
	 * the global queue. This is what makes `release` a map delete plus a
	 * kick rather than needing userspace to move tasks itself.
	 *
	 * scx_bpf_dsq_move() and NOT scx_bpf_dsq_move_to_local(): the latter
	 * pops the DSQ *head*, which is not necessarily the task the iterator
	 * just found. With a still-gated task at the head and an ungated one
	 * behind it, popping the head would dispatch a task that is supposed
	 * to be held -- silent under-holding, the exact failure this whole
	 * backend exists to avoid. scx_bpf_dsq_move() moves the iterated task.
	 *
	 * The set_slice is load-bearing too: enqueue inserted these with
	 * SCX_SLICE_INF, so without it an ungated task would run with an
	 * infinite time slice. See scx_tickless dispatch_cpu() and scx_chaos
	 * for both patterns.
	 */
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, HOLD_DSQ, 0) {
		/*
		 * Verifier pointer-validation workaround, copied from
		 * scx_tickless: re-acquire a trusted reference by pid.
		 */
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (is_gated(p->tgid)) {
			bpf_task_release(p);
			continue;
		}
		scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, SCX_SLICE_DFL);
		scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_GLOBAL, 0);
		bpf_task_release(p);
	}
	bpf_rcu_read_unlock();

	/*
	 * NO trailing scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL, 0). Verified
	 * on target in Task 1: SCX_DSQ_GLOBAL is not a valid *source* for that
	 * helper -- the kernel rejects it ("invalid DSQ ID") and immediately
	 * disables the scheduler. The core drains SCX_DSQ_GLOBAL itself right
	 * after ops.dispatch() returns, which is why moving an ungated task
	 * there above is all this op has to do. SCX_DSQ_GLOBAL remains a valid
	 * *destination*, which is what enqueue and the move above rely on.
	 */
}
```

If the verifier rejects the `bpf_rcu_read_lock()` around the iteration, read `dispatch_cpu()` in `scheds/rust/scx_tickless/src/bpf/main.bpf.c:272` and mirror its structure exactly — it is the in-tree pattern this is derived from and it verifies on this kernel.

- [ ] **Step 5: Reap the gate entry when the leader exits**

Add before `SCX_OPS_DEFINE`, and wire `.exit_task = (void *)crfuzz_gate_exit_task`:

```c
/*
 * First of three layers that stop a crashed run's gates wedging the next one.
 * The other two are userspace: GateBackend::Drop clears this run's epoch, and
 * `scx_crfuzz_gated --reset` clears the map wholesale.
 */
void BPF_STRUCT_OPS(crfuzz_gate_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	u32 tgid = p->tgid;

	if (p->pid == p->tgid)
		bpf_map_delete_elem(&gate, &tgid);
}
```

- [ ] **Step 6: Build and confirm the verifier accepts the DSQ iteration**

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz_gate'
```

Expected: clean build. `bpf_for_each(scx_dsq, …)` is used in `scx_tickless`, `scx_layered` and `scx_p2dq`, so the pattern is known-good on this kernel; a rejection means the loop body differs from theirs in a way the verifier cares about.

- [ ] **Step 7: Test the gate by hand, end to end**

This is the first real proof the mechanism works. In the VM, with the daemon running:

```bash
# A victim that prints a tick every 100ms, enrolled in SCHED_EXT.
cat > /tmp/tick.c <<'EOF'
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
int main(void) {
    struct sched_param pa = {0};
    if (sched_setscheduler(0, 7, &pa)) { perror("setsched"); return 1; }
    for (int i = 0; ; i++) { printf("%d\n", i); fflush(stdout); usleep(100000); }
}
EOF
gcc -o /tmp/tick /tmp/tick.c && /tmp/tick &
TICK=$!
sleep 1

# Pinning arrives in Task 4, so find the map by id for now.
ID=$(sudo bpftool map show | awk '/name gate/ {print substr($1, 1, length($1)-1); exit}')

# Keys are little-endian u32; value is an 8-byte epoch, zero is fine here.
KEY=$(printf '%02x %02x %02x %02x' \
        $((TICK & 0xff)) $(((TICK >> 8) & 0xff)) \
        $(((TICK >> 16) & 0xff)) $(((TICK >> 24) & 0xff)))

sudo bpftool map update id $ID key hex $KEY value hex 00 00 00 00 00 00 00 00
sleep 1
echo "--- gated above this line ---"
sudo bpftool map delete id $ID key hex $KEY
```

Expected: ticks stop within a few milliseconds of the `update` and resume within a few milliseconds of the `delete`. If they never stop, the task is not enrolled in `SCHED_EXT` — check that `chrt -p $TICK` reports policy 7. If they stop but never resume, `ops.dispatch`'s `HOLD_DSQ` drain is not firing; confirm a kick is reaching the CPU (Task 2's prog) or wait out a full slice to distinguish the two.

- [ ] **Step 8: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gate
git commit -m "$(cat <<'EOF'
scx_crfuzz_gate: gate a thread group off the dispatch path

A tgid-keyed hash map and a DSQ nothing consumes. ops.enqueue routes a gated
task into HOLD_DSQ; ops.dispatch moves it back out once the entry is gone, so
releasing is a map delete plus a kick. ops.exit_task reaps the entry when the
thread-group leader exits.

Keyed by tgid, never pid: a release resumes every thread of the role, which is
what the design doc's Background requires.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Pinning, the epoch counter, and the daemon CLI

**Files:**
- Modify: `scheds/experimental/scx_crfuzz_gate/src/bpf/main.bpf.c`
- Modify: `scheds/experimental/scx_crfuzz_gate/src/main.rs`

**Interfaces:**
- Produces: pinned maps at `/sys/fs/bpf/crfuzz/gate` and `/sys/fs/bpf/crfuzz/epoch`; CLI flags `--reset`, `--status`.

- [ ] **Step 1: Add the epoch map to BPF**

After the `gate` map:

```c
/*
 * A single monotonic counter. Written only by userspace, never read by BPF:
 * each run stamps its gate entries so its Drop can clear exactly its own.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} epoch SEC(".maps");
```

- [ ] **Step 2: Pin both maps at startup**

In `main.rs`, after `load()` and before `attach_struct_ops`:

```rust
const PIN_DIR: &str = "/sys/fs/bpf/crfuzz";

std::fs::create_dir_all(PIN_DIR).with_context(|| format!("creating {PIN_DIR}"))?;
skel.maps.gate.pin(format!("{PIN_DIR}/gate")).context("pinning the gate map")?;
skel.maps.epoch.pin(format!("{PIN_DIR}/epoch")).context("pinning the epoch map")?;
// The kick program too: a pinned map gives no access to a program, and
// GateMap::kick needs to invoke this one via test_run.
skel.progs
    .crfuzz_kick_all
    .pin(format!("{PIN_DIR}/kick"))
    .context("pinning the kick program")?;
```

- [ ] **Step 3: Add the CLI**

Replace the top of `main.rs` with a clap parser:

```rust
#[derive(clap::Parser)]
#[command(name = "scx_crfuzz_gated")]
struct Args {
    /// Clear every gate in the pinned map and exit.
    ///
    /// Wholesale rather than by epoch: a recovery tool has no epoch of its own
    /// to match. It operates on the pinned map, so it neither requires nor
    /// replaces a running daemon.
    #[arg(long)]
    reset: bool,

    /// Report whether the gate is attached and how many gates are live.
    #[arg(long)]
    status: bool,
}
```

- [ ] **Step 4: Implement `--reset` and `--status` against the pinned maps**

These run without attaching anything:

```rust
fn open_pinned_gate() -> Result<libbpf_rs::MapHandle> {
    libbpf_rs::MapHandle::from_pinned_path(format!("{PIN_DIR}/gate"))
        .with_context(|| format!("opening {PIN_DIR}/gate -- is scx_crfuzz_gated running?"))
}

fn reset() -> Result<()> {
    let map = open_pinned_gate()?;
    let keys: Vec<Vec<u8>> = map.keys().collect();
    let n = keys.len();
    for k in keys {
        map.delete(&k).context("deleting a gate entry")?;
    }
    println!("cleared {n} gate(s)");
    Ok(())
}

fn status() -> Result<()> {
    let state = std::fs::read_to_string("/sys/kernel/sched_ext/state")
        .unwrap_or_else(|_| "unavailable".into());
    let ops = std::fs::read_to_string("/sys/kernel/sched_ext/root/ops")
        .unwrap_or_else(|_| "none".into());
    println!("sched_ext state: {}", state.trim());
    println!("attached ops:    {}", ops.trim());
    match open_pinned_gate() {
        Ok(map) => println!("live gates:      {}", map.keys().count()),
        Err(e) => println!("live gates:      {e:#}"),
    }
    Ok(())
}
```

and dispatch them in `main` before any skeleton work:

```rust
    let args = <Args as clap::Parser>::parse();
    if args.reset {
        return reset();
    }
    if args.status {
        return status();
    }
```

- [ ] **Step 5: Hold a startup lock, then detect an already-attached scheduler**

Order matters and the reason is subtle. `/sys/kernel/sched_ext/state` does not flip to `enabled`
until `scx_ops_attach!` succeeds, so the already-attached check alone does **not** serialise two
daemons: a second one starting inside the first's `load -> pin -> attach` window passes it, clears
the first's fresh pins as "stale", and pins its own maps. Its attach then fails, its `?`
early-return skips the unpin, and pinned maps survive process death -- leaving the pins pointing at
orphaned maps while the first daemon is still the attached scheduler reading its own. An engine run
would write tgids into a gate map nothing reads: silent under-holding.

So take an exclusive, non-blocking `flock` first, on `/run/scx_crfuzz_gated.lock` (falling back to
`/tmp` if `/run` is not writable, announcing which), and hold the `File` alive through the SIGINT
loop and the unpin -- dropping it closes the fd and reopens the window. `--reset` and `--status`
return *before* the lock is taken, so recovery tools still work against a wedged daemon. The
lockfile surviving a `kill -9` is harmless: flock is advisory and the kernel releases it on process
death, so a restart re-acquires immediately.

The stale-pin argument is therefore two-part: the attach check **and** the lock. Neither alone is
sufficient.

`attach_struct_ops` will fail, but the message is opaque. Before opening the skeleton:

```rust
    if let Ok(s) = std::fs::read_to_string("/sys/kernel/sched_ext/state") {
        if s.trim() == "enabled" {
            let ops = std::fs::read_to_string("/sys/kernel/sched_ext/root/ops")
                .unwrap_or_else(|_| "unknown".into());
            anyhow::bail!(
                "a sched_ext scheduler is already attached ({}); only one can be",
                ops.trim()
            );
        }
    }
```

- [ ] **Step 6: Verify**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated --status
   ls -l /sys/fs/bpf/crfuzz/
   sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated --reset'
```

Expected: `state: enabled`; `ops:` reporting a name **beginning** `crfuzz_gate` — `scx_ops_open!` appends version and target, so the real string is like `crfuzz_gate_0.1.0_aarch64_unknown_linux_gnu_debug`, exactly as every macro-based scheduler in this tree does. Do not assert equality against the bare name, here or in `--status`. Then `live gates: 0`, both pins present, `cleared 0 gate(s)`. Finally start a second daemon and confirm it refuses with the "already attached" message.

- [ ] **Step 7: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gate
git commit -m "$(cat <<'EOF'
scx_crfuzz_gate: pin the maps and add the daemon CLI

Pinning is what makes the scheduler campaign-scoped rather than run-scoped: a
struct_ops attach costs a BPF load and verifier pass, and gaps.md targets
17,700 iterations/hour, so paying it per run would roughly double iteration
cost. Each engine run opens the pinned map instead.

--reset clears the map wholesale for recovery, --status reports attachment and
live gate count, and starting a second daemon now names the scheduler already
holding the slot instead of failing opaquely.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: The `GateMap` client

The library face of the crate — what `scx_crfuzz` links against. No `struct_ops`, no skeleton: just the pinned maps.

**Files:**
- Create: `scheds/experimental/scx_crfuzz_gate/src/client.rs`
- Modify: `scheds/experimental/scx_crfuzz_gate/src/lib.rs`
- Modify: `scheds/experimental/scx_crfuzz_gate/src/bpf/main.bpf.c` (the `crfuzz_epoch_next` program, below)
- Modify: `scheds/experimental/scx_crfuzz_gate/src/main.rs` (pin it, and add it to the stale-pin/unpin lists)

**Interfaces:**
- Produces:
  ```rust
  pub struct GateMap { /* … */ }
  impl GateMap {
      pub fn open() -> anyhow::Result<GateMap>;
      pub fn epoch(&self) -> u64;
      pub fn gate(&self, tgid: i32) -> anyhow::Result<()>;
      pub fn ungate(&self, tgid: i32) -> anyhow::Result<()>;
      pub fn is_gated(&self, tgid: i32) -> bool;
      pub fn clear_epoch(&self) -> anyhow::Result<usize>;
      pub fn kick(&self) -> anyhow::Result<()>;
      pub fn scheduler_enabled() -> bool;
  }
  ```

- [ ] **Step 1: Write the failing test**

`src/client.rs`, at the bottom. These need root and a running daemon, so they skip loudly like the engine's do:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn skip() -> bool {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("skipping: needs root");
            return true;
        }
        if GateMap::open().is_err() {
            eprintln!("skipping: scx_crfuzz_gated is not running");
            return true;
        }
        false
    }

    #[test]
    fn gate_then_ungate_round_trips() {
        if skip() {
            return;
        }
        let m = GateMap::open().unwrap();
        let tgid = std::process::id() as i32;
        assert!(!m.is_gated(tgid), "nothing gated to start with");
        m.gate(tgid).unwrap();
        assert!(m.is_gated(tgid));
        m.ungate(tgid).unwrap();
        assert!(!m.is_gated(tgid));
    }

    #[test]
    fn clear_epoch_removes_only_this_epochs_entries() {
        if skip() {
            return;
        }
        let a = GateMap::open().unwrap();
        let b = GateMap::open().unwrap();
        assert_ne!(a.epoch(), b.epoch(), "each open mints a fresh epoch");

        a.gate(424242).unwrap();
        b.gate(424243).unwrap();
        assert_eq!(a.clear_epoch().unwrap(), 1, "only a's entry");
        assert!(!a.is_gated(424242));
        assert!(b.is_gated(424243), "b's gate survives a's cleanup");
        b.clear_epoch().unwrap();
    }
}
```

Note: gating this test process is safe because the test process is not in `SCHED_EXT`, so the map entry has no scheduling effect. It is exercising the map, not the hold.

- [ ] **Step 2: Run it to verify it fails**

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz_gate client 2>&1 | tail -20'
```

Expected: compile error, `GateMap` not found.

- [ ] **Step 3: Implement `GateMap`**

First the BPF side, because `open()` below depends on it. Append to `main.bpf.c`, beside `crfuzz_kick_all`:

```c
/*
 * Atomically bump the epoch counter and return the new value, so
 * GateMap::open() can mint an epoch without a userspace lookup-then-update
 * race: __sync_fetch_and_add is a single atomic RMW on the map's one
 * element, so two callers opening concurrently are guaranteed distinct
 * values. Returns 0 only if the map lookup fails; a real epoch is never 0
 * because the counter starts at 0 and this only ever returns old+1, so
 * userspace can treat a returned 0 as unambiguous failure.
 */
SEC("syscall")
int crfuzz_epoch_next(void)
{
	u32 key = 0;
	u64 *val;

	val = bpf_map_lookup_elem(&epoch, &key);
	if (!val)
		return 0;

	return __sync_fetch_and_add(val, 1) + 1;
}
```

and pin it in `main.rs` beside the other three, adding `"epoch_next"` to `remove_pins`'s list so the
daemon's stale-pin clearing and graceful unpin stay complete — a fourth pin the restart logic does
not know about would survive a `kill -9` and be reused by the next daemon.

Then the client:

```rust
// SPDX-License-Identifier: GPL-2.0
//
//! The client face of the gate: open the pinned maps, gate and ungate by tgid.
//!
//! Deliberately knows nothing about roles, checkpoints or the engine. The only
//! vocabulary here is "thread group" and "epoch".

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::ProgramInput;

const PIN_DIR: &str = "/sys/fs/bpf/crfuzz";

pub struct GateMap {
    gate: MapHandle,
    kicker: Option<libbpf_rs::Program>,
    epoch: u64,
}

impl GateMap {
    /// Open the pinned maps and mint this run's epoch.
    ///
    /// Fails if the daemon is not running. It must never fall back to "no
    /// gating": that is indistinguishable from a successful multi-threaded
    /// hold and is exactly the silent under-holding this engine must not do.
    pub fn open() -> Result<GateMap> {
        let gate = MapHandle::from_pinned_path(format!("{PIN_DIR}/gate")).with_context(|| {
            format!("opening {PIN_DIR}/gate -- is scx_crfuzz_gated running?")
        })?;

        // The epoch is minted by invoking the pinned crfuzz_epoch_next
        // program, NOT by a userspace lookup-then-update on the epoch map.
        // A plain read-modify-write here would race: two GateMap::open()
        // calls started close together could both read the same old value
        // and both write old+1, so two concurrent engine runs would
        // silently share one epoch. Then the first run's Drop-time
        // clear_epoch() would delete the SECOND run's gates too, leaving it
        // silently under-holding with nothing reporting an error -- which
        // defeats the entire reason the epoch exists.
        // NOTE on the API: libbpf-rs 0.27.0 cannot do this the obvious way.
        // `from_pinned_path` exists only on `ProgramHandle` (program.rs:1780)
        // and `test_run` only on `ProgramMut` (program.rs:1639), so a pinned
        // program cannot be test_run through the safe wrapper at all. Open it
        // as an `OwnedFd` via `Program::fd_from_pinned_path` and call
        // `libbpf_sys::bpf_prog_test_run_opts` on the raw fd. In-tree
        // precedent: `rust/scx_arena/scx_arena/src/lib.rs:113`.
        let epoch_fd = libbpf_rs::Program::fd_from_pinned_path(format!("{PIN_DIR}/epoch_next"))
            .with_context(|| format!("opening {PIN_DIR}/epoch_next"))?;
        let epoch = prog_test_run(epoch_fd.as_fd(), None)
            .context("minting an epoch via crfuzz_epoch_next")? as u64;
        anyhow::ensure!(
            epoch != 0,
            "crfuzz_epoch_next returned 0: the epoch map lookup failed in BPF"
        );

        Ok(GateMap {
            gate,
            kicker: None,
            epoch,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn gate(&self, tgid: i32) -> Result<()> {
        self.gate
            .update(
                &(tgid as u32).to_ne_bytes(),
                &self.epoch.to_ne_bytes(),
                MapFlags::ANY,
            )
            .with_context(|| format!("gating tgid {tgid}"))
    }

    pub fn ungate(&self, tgid: i32) -> Result<()> {
        match self.gate.delete(&(tgid as u32).to_ne_bytes()) {
            Ok(()) => Ok(()),
            // Already gone: ops.exit_task reaps on leader exit, so a release
            // that races an exit is normal, not an error.
            Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("ungating tgid {tgid}")),
        }
    }

    pub fn is_gated(&self, tgid: i32) -> bool {
        matches!(
            self.gate.lookup(&(tgid as u32).to_ne_bytes(), MapFlags::ANY),
            Ok(Some(_))
        )
    }

    /// Delete every entry stamped with this run's epoch. Returns how many.
    pub fn clear_epoch(&self) -> Result<usize> {
        let mut n = 0;
        for key in self.gate.keys() {
            let Ok(Some(v)) = self.gate.lookup(&key, MapFlags::ANY) else {
                continue;
            };
            if u64::from_ne_bytes(v[..8].try_into().unwrap()) == self.epoch {
                self.gate.delete(&key).context("clearing a gate entry")?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Is a sched_ext scheduler still attached?
    ///
    /// Polled every round by `GateBackend`: if the kernel ejects the scheduler
    /// mid-run, every gate evaporates and the engine would otherwise go on
    /// believing it holds tasks it does not -- a clean-looking bogus verdict.
    pub fn scheduler_enabled() -> bool {
        std::fs::read_to_string("/sys/kernel/sched_ext/state")
            .map(|s| s.trim() == "enabled")
            .unwrap_or(false)
    }

    pub fn kick(&self) -> Result<()> {
        let Some(prog) = self.kicker.as_ref() else {
            return Ok(());
        };
        let nr_cpus = libbpf_rs::num_possible_cpus().context("num_possible_cpus")? as u32;
        let mut arg = nr_cpus.to_ne_bytes().to_vec();
        let input = ProgramInput {
            context_in: Some(&mut arg),
            ..Default::default()
        };
        prog.test_run(input).context("kicking cpus")?;
        Ok(())
    }
}
```

- [ ] **Step 4: Wire the kicker program**

Task 4 pins the kick program at `/sys/fs/bpf/crfuzz/kick`. In `GateMap::open`, replace `kicker: None` with (same raw-fd construction as the epoch minter above, and for the same API reason):

```rust
        let kicker = libbpf_rs::Program::fd_from_pinned_path(format!("{PIN_DIR}/kick"))
            .with_context(|| format!(
                "{PIN_DIR}/kick is missing or unopenable: holds would be bounded by the \
                 scheduling slice instead of one round; refusing rather than under-holding."
            ))?;
```

The field is `kicker: OwnedFd`, **not** `Option<OwnedFd>`, and the failure propagates the real error
rather than `.ok()`-ing it into a guessed one. An earlier draft of this plan wrote `.ok()` followed
by an `ensure!(kicker.is_some(), …)`; that was wrong twice over. It discards *why* the open failed —
so an `EACCES`, a revoked pin or `ENOMEM` is all reported as "the daemon is too old" — and the
`Option` it leaves behind permits a `GateMap` with no kicker, which forces `kick()` to carry a
`return Ok(())` no-op branch. A silent no-op fallback in the one crate whose thesis is that failures
must be legible is a defect even while `open()` happens to guard it, because the next constructor
resurrects it as exactly the slice-boundary degradation this check exists to prevent.

Open the kicker **before** minting the epoch. Minting first burns a counter value on every run that
then fails this check.

- [ ] **Step 5: Export it**

In `lib.rs`:

```rust
pub mod client;
pub use client::GateMap;
```

- [ ] **Step 6: Run the tests**

The daemon must be **rebuilt and restarted** before the tests: `crfuzz_epoch_next` is new BPF, so a
daemon from before Step 3 has no such pin and every `open()` fails.

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && CARGO_TARGET_DIR=/workspace/scx/target-linux cargo build -p scx_crfuzz_gate
   sudo pkill -INT scx_crfuzz_gated; sleep 1
   sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   ls -l /sys/fs/bpf/crfuzz/
   cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz_gate client 2>&1 | tail -20'
```

Expected: four pins (`gate`, `epoch`, `kick`, `epoch_next`), then both tests pass.
`clear_epoch_removes_only_this_epochs_entries` is the one that proves the atomic mint: it asserts
two `open()`s get distinct epochs, which is exactly what the racy userspace version could violate.

- [ ] **Step 7: Commit**

```bash
git add scheds/experimental/scx_crfuzz_gate
git commit -m "$(cat <<'EOF'
scx_crfuzz_gate: GateMap, the pinned-map client

The library face the engine links against: open the pinned maps, mint an
epoch, gate and ungate by tgid, kick, and report whether the scheduler is
still attached.

Knows nothing about roles, checkpoints or the engine -- its whole vocabulary
is "thread group" and "epoch". Both the missing-daemon and missing-kicker
paths refuse rather than degrade, since a silently un-held target looks
exactly like a successfully held one.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Enroll spawned targets in `SCHED_EXT`

**Files:**
- Modify: `scheds/experimental/scx_crfuzz/src/backend_seccomp.rs` (`child_setup`, around line 394–436)

**Interfaces:**
- Consumes: nothing from earlier tasks (no gate map access in the child).
- Produces: `SeccompNotifyBackend::with_sched_ext(bool) -> Self`, defaulting to `false`.

- [ ] **Step 1: Write the failing test**

Create `scheds/experimental/scx_crfuzz/tests/sched_ext_enrollment.rs`. One test per binary, because `reap` calls `waitpid(None)` process-wide:

```rust
// SPDX-License-Identifier: GPL-2.0
//
// A spawned target must land in SCHED_EXT, and so must every thread and child
// it goes on to create -- scheduling policy is inherited across fork and
// CLONE_THREAD, which is what lets one call before exec enroll a whole tree
// without the engine chasing descendants.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::default_discovery_checkpoints;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

/// Scheduling policy of a task, from field 41 of /proc/<pid>/stat.
///
/// Read from `stat` rather than `sched_getscheduler` so the assertion covers
/// threads this process never spawned.
fn policy(pid: i32) -> Option<i64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &raw[raw.rfind(')')? + 2..];
    tail.split_whitespace().nth(38)?.parse().ok()
}

#[test]
fn a_spawned_target_and_its_threads_are_in_sched_ext() {
    if unsafe { libc::getuid() } != 0 {
        eprintln!("skipping: needs root (seccomp listener)");
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("threaded_victim");
    // Both fixture arguments are load-bearing: threaded_victim.c:49 exits via
    // VERDICT:usage when argc < 3, without ever creating the sibling thread --
    // which would make the multi-threaded assertion below vacuous.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");
    let mut backend = SeccompNotifyBackend::new(vec![spec], "/crfuzz/enroll")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    // A single narrowed checkpoint, NOT default_discovery_checkpoints(): the
    // full structural set holds the fixture at its progress-file openat, which
    // happens before the sibling thread exists, so the thread assertions would
    // run against a single-threaded process.
    //
    // "fstatat" and "newfstatat" both work and resolve to the same syscall
    // number: backend_seccomp.rs's ARCH_ALIASES maps the former to the latter
    // and tries both. "fstatat" is the canonical spelling in checkpoint.rs's
    // STRUCTURAL_SYSCALLS table; thread_group_holding.rs happens to spell it
    // "newfstatat". Follow whichever file you are writing into.
    backend
        .attach(&[CheckpointDecl {
            id: CheckpointId::new("fstatat"),
            kind: CheckpointKind::Syscall,
            target: "fstatat".into(),
            category: None,
        }])
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut held = None;
    while Instant::now() < deadline && held.is_none() {
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit { pid, .. } = e {
                    held = Some(pid);
                }
            }
        }
    }
    let pid = held.expect("the fixture never reached a checkpoint");

    const SCHED_EXT: i64 = 7;
    assert_eq!(policy(pid), Some(SCHED_EXT), "the held task is in SCHED_EXT");

    let tgid_dir = format!("/proc/{pid}/task");
    let threads: Vec<i32> = std::fs::read_dir(&tgid_dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    assert!(threads.len() >= 2, "the fixture is multi-threaded: {threads:?}");
    for t in threads {
        assert_eq!(policy(t), Some(SCHED_EXT), "thread {t} inherited SCHED_EXT");
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz --test sched_ext_enrollment 2>&1 | tail -20'
```

Expected: compile error, `with_sched_ext` not found.

- [ ] **Step 3: Add the builder flag**

In `backend_seccomp.rs`, add a field to `SeccompNotifyBackend` beside `per_spawn_cgroups`:

```rust
    /// Place each spawned target in `SCHED_EXT` before `exec`, so the gate's
    /// scheduler sees it. Off by default: with `SCX_OPS_SWITCH_PARTIAL` an
    /// un-enrolled task stays on CFS, which is exactly what the non-`--gate`
    /// paths want.
    sched_ext: bool,
```

initialise it `false` in `new`, and add next to `with_per_spawn_cgroups`:

```rust
    pub fn with_sched_ext(mut self, yes: bool) -> Self {
        self.sched_ext = yes;
        self
    }
```

Pass it through to `child_setup` as a new parameter at the `spawn` call site (around line 290).

- [ ] **Step 4: Enroll in the fork/exec window**

In `child_setup`, between the seccomp load and the `execv`. Placement is deliberate and belongs in the comment — before `exec` so the target never runs a single instruction outside the gate's view, and after the filter so a failure here is reported by the same path:

```rust
    if sched_ext {
        // Policy is inherited across fork and CLONE_THREAD, so this one call
        // enrolls the whole tree the target goes on to build -- including
        // threads a Go runtime raises later -- and nothing else on the
        // machine. Same construction the seccomp filter uses: act between
        // fork and exec, then let inheritance do the rest.
        const SCHED_EXT: libc::c_int = 7;
        let param: libc::sched_param = unsafe { std::mem::zeroed() };
        // SAFETY: `param` is a zeroed sched_param, valid for SCHED_EXT, and
        // pid 0 means the calling thread.
        if unsafe { libc::sched_setscheduler(0, SCHED_EXT, &param) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("enrolling the target in SCHED_EXT -- is scx_crfuzz_gated running?");
        }
    }
```

An un-enrolled target is invisible to the gate and silently unheld, so this returns an error rather than warning.

- [ ] **Step 5: Add the dev-dependency the test needs**

In `scheds/experimental/scx_crfuzz/Cargo.toml`, under the existing Linux-only target section:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2"
libseccomp = "0.4"
nix = { version = "0.29", features = ["fs", "poll", "process", "signal", "socket", "uio"] }
scx_crfuzz_gate = { path = "../scx_crfuzz_gate", version = "0.1.0" }
```

This is the only place `scx_crfuzz` gains the dependency, and it is target-gated, so the macOS build is unaffected.

- [ ] **Step 6: Run the test**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   cd /workspace/scx/scheds/experimental/scx_crfuzz/scenarios && make
   cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz --test sched_ext_enrollment 2>&1 | tail -20'
```

Expected: PASS, with both the held task and its sibling reporting policy 7.

- [ ] **Step 7: Confirm macOS is still clean**

```bash
cd /Users/suhaasvaddadi/VSCode/senior-thesis/scx && cargo test -p scx_crfuzz 2>&1 | tail -5
```

Expected: `90 passed`. This is the step that catches an accidentally ungated dependency.

- [ ] **Step 8: Commit**

```bash
git add scheds/experimental/scx_crfuzz
git commit -m "$(cat <<'EOF'
scx_crfuzz: enroll spawned targets in SCHED_EXT

One sched_setscheduler in the fork/exec window, behind with_sched_ext(). With
SCX_OPS_SWITCH_PARTIAL the gate's scheduler only handles tasks explicitly put
in SCHED_EXT, so this both enrolls the target and is the blast-radius
guarantee: policy is inherited across fork and CLONE_THREAD, so the target's
whole tree is covered and nothing else on the machine is.

Fails the spawn rather than warning -- an un-enrolled target is invisible to
the gate and would be silently unheld.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: `GateBackend`

**Files:**
- Create: `scheds/experimental/scx_crfuzz/src/backend_gate.rs`
- Modify: `scheds/experimental/scx_crfuzz/src/lib.rs`

**Interfaces:**
- Consumes: `scx_crfuzz_gate::GateMap` (Task 5); `CheckpointBackend`, `BackendEvent`, `Poll`, `NotifyHandle`, `EXIT_HANDLE`, `Pid` from this crate.
- Produces:
  ```rust
  pub struct GateStats { pub gates: usize, pub ungates: usize,
                         pub total_gate_latency: Duration, pub max_gate_latency: Duration }
  pub struct GateBackend<B: CheckpointBackend> { /* … */ }
  impl<B: CheckpointBackend> GateBackend<B> {
      pub fn new(inner: B) -> anyhow::Result<Self>;
      pub fn stats(&self) -> &GateStats;
      pub fn inner(&self) -> &B;
  }
  ```

- [ ] **Step 1: Write the failing test**

At the bottom of `src/backend_gate.rs`, using `StubBackend` so the state machine is testable without a kernel:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::StubBackend;
    use crate::role::TaskInfo;

    fn task(pid: Pid) -> TaskInfo {
        TaskInfo { pid, tgid: pid, parent_tgid: 1, comm: "v".into(), cgroup: "/c".into() }
    }

    fn skip() -> bool {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("skipping: needs root");
            return true;
        }
        if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
            eprintln!("skipping: scx_crfuzz_gated is not running");
            return true;
        }
        false
    }

    #[test]
    fn the_handle_the_engine_is_given_is_the_handle_it_releases() {
        // GateBackend::release passes the engine's handle straight through to
        // the inner backend, with no substitution. The gate-vs-freeze
        // distinction at the mechanism level is measured in
        // tests/handle_stability.rs, not here: this test drives a StubBackend,
        // so FreezerBackend is not involved in it at all.
        if skip() {
            return;
        }
        let inner = StubBackend::new().task(task(10)).hit(10, "openat");
        let mut b = GateBackend::new(inner).unwrap();

        b.poll().unwrap();
        let Poll::Events(e) = b.poll().unwrap() else { panic!("expected the hit") };
        let BackendEvent::CheckpointHit { handle, .. } = e[0].clone() else { panic!() };

        b.release(handle).unwrap();
        assert_eq!(
            b.inner().released,
            vec![handle],
            "released exactly the handle the engine was given, unchanged"
        );
    }

    #[test]
    fn a_hit_gates_the_thread_group_and_release_ungates_it() {
        if skip() {
            return;
        }
        let inner = StubBackend::new().task(task(10)).hit(10, "openat");
        let mut b = GateBackend::new(inner).unwrap();
        b.poll().unwrap();
        let Poll::Events(e) = b.poll().unwrap() else { panic!() };
        let BackendEvent::CheckpointHit { handle, .. } = e[0].clone() else { panic!() };

        assert_eq!(b.stats().gates, 1, "the hit gated something");
        b.release(handle).unwrap();
        assert_eq!(b.stats().ungates, 1, "the release ungated it");
    }

    #[test]
    fn releasing_the_exit_handle_ungates_nothing() {
        if skip() {
            return;
        }
        let inner = StubBackend::new().task(task(10)).hit(10, "openat");
        let mut b = GateBackend::new(inner).unwrap();
        b.poll().unwrap();
        b.poll().unwrap();
        b.release(EXIT_HANDLE).unwrap();
        assert_eq!(b.stats().ungates, 0, "a synthetic exit has no task to ungate");
    }
}
```

Note the stub's pids do not exist, so `tgid_of` must fall back to treating the pid as its own tgid — asserted implicitly by these tests passing.

- [ ] **Step 2: Run it to verify it fails**

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz backend_gate 2>&1 | tail -20'
```

Expected: compile error, `backend_gate` module not found.

- [ ] **Step 3: Implement the module header and types**

```rust
// SPDX-License-Identifier: GPL-2.0
//
// The intended holding mechanism: a `sched_ext` scheduler declines to place a
// gated thread group on a CPU.
//
// A decorator over another backend, sitting exactly where `FreezerBackend`
// sits and for the same reason: seccomp supplies the precision (stop at
// exactly this syscall), the gate supplies the coverage (nothing else in the
// thread group gets CPU).
//
// WHAT THIS FIXES, AND WHAT IT DOES NOT.
//
// Fixed: the freezer perturbs the syscall it holds. Freezing wakes every task
// in the cgroup including one parked in a seccomp notification; that wait is
// interruptible, so the kernel restarts the syscall and a fresh notification
// id replaces the one the engine was told about. The gate never touches the
// held thread -- it stays parked for the whole hold -- so `owner`, `live`,
// `reported` and `deferred` all disappear from this backend's state. Only
// `owner` survives, and only to map a handle back to a thread group.
//
// Not fixed: the boundary is sharper, not zero. Between the notification
// arriving and this code writing the gate entry, siblings still run -- one
// userspace round trip, against the freezer's measured ~350 us convergence.
// `GateStats` measures it rather than asserting it away. Closing it needs the
// gate set in-kernel in the trapping task's own context; see the spec's
// "Residual window, and phase 2".
//
// Also not fixed: which thread inside a thread group arrives first. That is
// section 14-A and the gate does not touch it. The gate makes the other
// threads stop; it does not make them stop in a chosen order.

use crate::backend::BackendEvent;
use crate::backend::CheckpointBackend;
use crate::backend::NotifyHandle;
use crate::backend::Poll;
use crate::backend::EXIT_HANDLE;
use crate::checkpoint::CheckpointDecl;
use crate::role::Pid;
use anyhow::bail;
use anyhow::Result;
use scx_crfuzz_gate::GateMap;
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

/// What the gate cost and how fuzzy its boundary was.
///
/// Mirrors `backend_freezer::FreezeStats` deliberately: the freezer's header
/// argues the case against a mechanism should be evidence rather than theory,
/// and the case *for* one is held to the same standard.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GateStats {
    pub gates: usize,
    pub ungates: usize,
    /// Notification-to-kick-complete, summed. The window in which sibling
    /// threads were still running.
    pub total_gate_latency: Duration,
    pub max_gate_latency: Duration,
}

pub struct GateBackend<B: CheckpointBackend> {
    inner: B,
    map: GateMap,
    /// Handle as the engine knows it -> the thread group it belongs to.
    ///
    /// Unlike the freezer there is no second map: the handle the engine was
    /// given stays valid for the whole hold, because nothing disturbs it.
    owner: HashMap<NotifyHandle, Pid>,
    stats: GateStats,
}
```

- [ ] **Step 4: Implement construction and tgid resolution**

```rust
/// The thread group a task belongs to, from `/proc/<pid>/status`.
///
/// `CheckpointHit` carries only a pid, and gating is per-thread-group, so this
/// is the one lookup the gate needs. A pid that has already gone (or never
/// existed, as in the stub tests) is treated as its own leader, matching the
/// engine's own default in `role.rs`.
fn tgid_of(pid: Pid) -> Pid {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return pid;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(pid)
}

impl<B: CheckpointBackend> GateBackend<B> {
    pub fn new(inner: B) -> Result<Self> {
        Ok(GateBackend {
            inner,
            map: GateMap::open()?,
            owner: HashMap::new(),
            stats: GateStats::default(),
        })
    }

    pub fn stats(&self) -> &GateStats {
        &self.stats
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Fail the run if the kernel ejected the scheduler underneath us.
    ///
    /// Checked every round. An ejection releases every gate at once, and the
    /// engine would go on believing it holds tasks that are in fact running
    /// free -- producing a clean-looking verdict from a run that enforced
    /// nothing. That is worse than a crash, so it is treated as one.
    fn check_still_attached(&self) -> Result<()> {
        if !GateMap::scheduler_enabled() {
            bail!(
                "the sched_ext scheduler was ejected mid-run: every gate is gone and \
                 nothing was being held. Check `dmesg` for the ops.timeout_ms watchdog \
                 -- a hold longer than 30s ejects the scheduler."
            );
        }
        Ok(())
    }
}
```

- [ ] **Step 5: Implement the trait**

```rust
impl<B: CheckpointBackend> CheckpointBackend for GateBackend<B> {
    fn attach(&mut self, checkpoints: &[CheckpointDecl]) -> Result<()> {
        self.check_still_attached()?;
        self.inner.attach(checkpoints)
    }

    fn poll(&mut self) -> Result<Poll> {
        self.check_still_attached()?;
        let polled = self.inner.poll()?;
        let Poll::Events(events) = polled else {
            return Ok(polled);
        };

        for event in &events {
            let BackendEvent::CheckpointHit { pid, handle, .. } = event else {
                continue;
            };
            let started = Instant::now();
            let tgid = tgid_of(*pid);
            self.map.gate(tgid)?;
            // Gating only takes effect at a task's next enqueue, so a sibling
            // already on-CPU needs a preempting kick to get there.
            self.map.kick()?;
            let latency = started.elapsed();

            self.owner.insert(*handle, tgid);
            self.stats.gates += 1;
            self.stats.total_gate_latency += latency;
            self.stats.max_gate_latency = self.stats.max_gate_latency.max(latency);
        }

        Ok(Poll::Events(events))
    }

    fn release(&mut self, handle: NotifyHandle) -> Result<()> {
        self.check_still_attached()?;
        if handle == EXIT_HANDLE {
            // A synthetic exit hit has no task to ungate.
            return self.inner.release(handle);
        }

        // Order is load-bearing: ungate before answering the notification, or
        // the notifying thread returns from the kernel into a still-gated
        // thread group and is parked again immediately.
        if let Some(tgid) = self.owner.remove(&handle) {
            self.map.ungate(tgid)?;
            self.map.kick()?;
            self.stats.ungates += 1;
        }
        self.inner.release(handle)
    }
}

impl<B: CheckpointBackend> Drop for GateBackend<B> {
    /// Clear this run's gates.
    ///
    /// Without it a crashed run leaves its thread groups gated forever, and
    /// the next run's tasks inherit a machine that will not schedule them --
    /// the gate's analogue of the freezer's "a frozen process keeps its
    /// inherited stdout open and the shell hangs forever".
    fn drop(&mut self) {
        if let Err(e) = self.map.clear_epoch() {
            log::warn!("clearing this run's gates: {e:#}");
        }
        let _ = self.map.kick();
    }
}
```

- [ ] **Step 6: Export it**

In `lib.rs`, beside the `backend_freezer` declaration:

```rust
/// The `ops.dispatch` gate -- the intended holding mechanism.
///
/// Linux-only. Unlike `backend_freezer`, this one does not perturb the syscall
/// it holds: the held thread stays parked in its seccomp notification for the
/// whole hold, so the notification id the engine was given stays valid.
#[cfg(target_os = "linux")]
pub mod backend_gate;
```

- [ ] **Step 7: Run the tests**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz backend_gate 2>&1 | tail -20'
```

Expected: 3 passed.

- [ ] **Step 8: Commit**

```bash
git add scheds/experimental/scx_crfuzz
git commit -m "$(cat <<'EOF'
scx_crfuzz: GateBackend, holding a thread group without touching it

A decorator sitting where FreezerBackend sits: on a checkpoint hit it gates the
held task's thread group and kicks CPUs; on release it ungates, kicks, and only
then answers the notification.

The held thread is never touched, so the notification id the engine was given
stays valid for the whole hold -- which deletes live/reported/deferred from the
freezer's state and, more importantly, means the held syscall is not
re-executed. Ejection of the scheduler is checked every round, because an
ejection would otherwise produce a clean-looking verdict from a run that
enforced nothing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: `--gate` on the CLI

**Files:**
- Modify: `scheds/experimental/scx_crfuzz/src/main.rs` (flag near line 65, backend selection near line 288)

**Interfaces:**
- Consumes: `GateBackend::new`, `GateStats` (Task 7); `with_sched_ext` (Task 6).

- [ ] **Step 1: Add the flag**

Beside the `freezer` field:

```rust
    /// Hold thread groups with the `sched_ext` gate instead of the cgroup
    /// freezer. Requires `scx_crfuzz_gated` to be running.
    ///
    /// This is the intended mechanism: unlike `--freezer` it does not restart
    /// the syscall it holds. Mutually exclusive with `--freezer`.
    #[arg(long, conflicts_with = "freezer")]
    gate: bool,
```

`conflicts_with` makes the exclusivity clap's problem rather than a runtime check.

- [ ] **Step 2: Wire the backend**

Insert a branch before the existing `if args.freezer`:

```rust
    if args.gate {
        use scx_crfuzz::backend_gate::GateBackend;
        // No per-spawn cgroups: unlike the freezer, the gate acts on the
        // thread group the held task belongs to, so roles sharing one cgroup
        // do not interfere.
        let backend = GateBackend::new(seccomp.with_sched_ext(true))?;
        return run_engine(
            config,
            backend,
            |b| {
                let s = b.stats();
                format!(
                    "{}\ngate: {} gate(s), {} ungate(s), max gate latency {:?} \
                     (the window in which siblings were still running)",
                    b.inner().arrival_trace().join(" "),
                    s.gates,
                    s.ungates,
                    s.max_gate_latency
                )
            },
            |b| b.inner().child_exit_code(),
        );
    }
```

Note the contrast worth keeping in the comment: `--freezer` forces `with_per_spawn_cgroups(true)` precisely because a shared cgroup would make one role's freeze stop every other role. The gate has no such coupling.

- [ ] **Step 3: Verify the flags conflict**

```bash
limactl shell sched-ext -- bash -lc \
  '/workspace/scx/target-linux/debug/scx_crfuzz --config /dev/null --gate --freezer'
```

Expected: clap's `the argument '--gate' cannot be used with '--freezer'`.

- [ ] **Step 4: Run a real scenario under the gate**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   cd /workspace/scx/scheds/experimental/scx_crfuzz/scenarios && make
   sudo /workspace/scx/target-linux/debug/scx_crfuzz \
     --config race_wins.json --cgroup-path /crfuzz/gate0 --gate \
     --spawn ./victim --spawn ./racer'
```

Expected: the same verdict `race_wins.json` gives under `--freezer`, plus a `gate:` line reporting latency. **Record the `max gate latency` number** — it is the measurement the spec's residual-window claim rests on, and it goes into the README in Task 10.

- [ ] **Step 5: Commit**

```bash
git add scheds/experimental/scx_crfuzz
git commit -m "$(cat <<'EOF'
scx_crfuzz: add --gate

Mutually exclusive with --freezer via clap. Unlike --freezer it does not force
per-spawn cgroups: the gate acts on the held task's thread group, so roles
sharing one cgroup do not interfere, which was the whole reason the freezer
needed them.

Reports max gate latency alongside the arrival trace -- the window in which
siblings were still running, which is the number the design's residual-window
claim rests on.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: The measurements

The tests that decide whether the gap is actually closed.

**Files:**
- Modify: `scheds/experimental/scx_crfuzz/tests/thread_group_holding.rs`
- Create: `scheds/experimental/scx_crfuzz/tests/handle_stability.rs`

**Interfaces:**
- Consumes: `GateBackend` (Task 7), the existing `sibling_progress_while_held` harness.

- [ ] **Step 1: Add the gate row to the parity test**

Read `sibling_progress_while_held`'s signature first — it is generic over `B: CheckpointBackend` and returns `(bytes_at_hit, bytes_after_observing)`. Add, mirroring the existing freezer test:

```rust
#[test]
fn the_gate_holds_the_whole_thread_group() {
    if skip_unless_root("the_gate_holds_the_whole_thread_group") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }
    let fixture = scenarios_dir().join("threaded_victim");
    // Both fixture arguments are load-bearing: threaded_victim.c:49 exits via
    // VERDICT:usage when argc < 3, without ever creating the sibling thread,
    // which would make the assertion below vacuously true. Same construction
    // as the freezer row already in this file.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/gate-tgh")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    let mut backend = GateBackend::new(seccomp).unwrap();

    let (at_hit, after) = sibling_progress_while_held(&mut backend, &progress);
    assert_eq!(
        after, at_hit,
        "the sibling wrote {} bytes during a {:?} hold; the gate must hold the \
         whole thread group, not just the notifying thread",
        after - at_hit,
        OBSERVE
    );
}
```

Then the Go row, which is the one that matters — runc and containerd are Go, and Go's `sysmon` responds to a thread blocked in a syscall by handing its work to another M, so holding one thread is itself what provokes the runtime into running more:

```rust
#[test]
fn the_gate_holds_a_go_runtimes_thread_group() {
    if skip_unless_root("the_gate_holds_a_go_runtimes_thread_group") {
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }
    let fixture = scenarios_dir().join("go_victim");
    // go_victim.go:71 has the same argc guard as threaded_victim -- see the note
    // on the row above.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/gate-go")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    let mut backend = GateBackend::new(seccomp).unwrap();

    let (at_hit, after) = sibling_progress_while_held(&mut backend, &progress);
    assert_eq!(
        after, at_hit,
        "the Go fixture's siblings wrote {} bytes during a {:?} hold; under seccomp \
         alone this is ~920 and under the freezer it is 0",
        after - at_hit,
        OBSERVE
    );
}
```

Both tests need `use scx_crfuzz::backend_gate::GateBackend;` added to the file's imports.

- [ ] **Step 2: Run it**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz --test thread_group_holding 2>&1 | tail -20'
```

Expected: PASS, 0 bytes written, matching the freezer's column.

- [ ] **Step 3: Write the soundness test**

`tests/handle_stability.rs`. One test per binary, because `reap` is process-wide:

```rust
// SPDX-License-Identifier: GPL-2.0
//
// The test that distinguishes the gate from the freezer rather than measuring
// them equal.
//
// This draft assumed FreezerBackend could not pass this; Task 9 Step 5 found
// the opposite -- FreezerBackend's poll()/release() machinery is built to
// swallow exactly this restart at the CheckpointBackend trait boundary (its
// `reported` set and `live` map), so a test driven through that boundary
// cannot distinguish the gate from the freezer at all. The shipped
// `tests/handle_stability.rs` was rebuilt below the trait boundary instead;
// see that file's own header for the corrected account.
//
// The gate never touches the held thread, so there is nothing to paper over.
// This asserts that, which is docs/arch/gaps.md #7's soundness claim turned
// into an assertion.
#![cfg(target_os = "linux")]

use scx_crfuzz::backend::BackendEvent;
use scx_crfuzz::backend::CheckpointBackend;
use scx_crfuzz::backend::NotifyHandle;
use scx_crfuzz::backend::Poll;
use scx_crfuzz::backend_gate::GateBackend;
use scx_crfuzz::backend_seccomp::ProcessSpec;
use scx_crfuzz::backend_seccomp::SeccompNotifyBackend;
use scx_crfuzz::checkpoint::CheckpointDecl;
use scx_crfuzz::checkpoint::CheckpointId;
use scx_crfuzz::checkpoint::CheckpointKind;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

#[test]
fn a_held_notification_id_survives_the_hold() {
    if unsafe { libc::getuid() } != 0 {
        eprintln!("skipping: needs root (seccomp listener)");
        return;
    }
    if !scx_crfuzz_gate::GateMap::scheduler_enabled() {
        eprintln!("skipping: scx_crfuzz_gated is not running");
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("threaded_victim");
    // Both arguments required; see Task 9 Step 1's note on the argc guard.
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("target");
    let progress = tmp.path().join("progress");
    std::fs::write(&target, "BENIGN\n").unwrap();
    let spec = ProcessSpec::parse(&format!(
        "{} {} {}",
        fixture.display(),
        target.display(),
        progress.display()
    ))
    .expect("spec");
    let seccomp = SeccompNotifyBackend::new(vec![spec], "/crfuzz/handle-stability")
        .with_sched_ext(true)
        .with_poll_timeout(Duration::from_millis(50));
    let mut backend = GateBackend::new(seccomp).unwrap();
    // A single narrowed checkpoint, NOT default_discovery_checkpoints(): the
    // full structural set holds the fixture at its progress-file openat, which
    // happens before the sibling thread is created. Match the newfstatat
    // narrowing that thread_group_holding.rs already uses for this fixture.
    backend
        .attach(&[CheckpointDecl {
            id: CheckpointId::new("newfstatat"),
            kind: CheckpointKind::Syscall,
            target: "newfstatat".into(),
            category: None,
        }])
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut first: Option<NotifyHandle> = None;
    while Instant::now() < deadline && first.is_none() {
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit { handle, .. } = e {
                    first = Some(handle);
                }
            }
        }
    }
    let handle = first.expect("the fixture never reached a checkpoint");

    // Hold it well past the freezer's ~350us convergence window, and past any
    // plausible restart latency, so a restart would certainly have happened.
    let hold_start = Instant::now();
    while hold_start.elapsed() < Duration::from_millis(300) {
        // Polling during the hold is what would surface a replacement id: a
        // restarted syscall re-enters the filter and notifies again.
        if let Poll::Events(events) = backend.poll().unwrap() {
            for e in events {
                if let BackendEvent::CheckpointHit { handle: h, .. } = e {
                    assert_eq!(
                        h, handle,
                        "a second notification arrived for the held task: the hold \
                         restarted its syscall, which is the freezer's bug"
                    );
                }
            }
        }
    }

    // The original id must still be answerable. Under the freezer this fails:
    // the id the engine was given stopped being valid the moment it froze.
    backend
        .release(handle)
        .expect("the original notification id was still answerable after a 300ms hold");
}
```

- [ ] **Step 4: Run it**

```bash
limactl shell sched-ext -- bash -lc \
  'sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   cd /workspace/scx && sudo CARGO_TARGET_DIR=/workspace/scx/target-linux \
   cargo test -p scx_crfuzz --test handle_stability 2>&1 | tail -20'
```

Expected: PASS.

- [ ] **Step 5: Confirm the freezer fails the same assertion**

Worth one manual run, because a test that passes for both backends proves nothing. Temporarily swap `GateBackend::new(seccomp)` for `FreezerBackend::new(seccomp.with_per_spawn_cgroups(true))` and re-run.

Expected: FAIL, either on the duplicate-id assertion or on `release`. Revert the swap afterwards; do not commit it. If the freezer *passes*, the test is not measuring what it claims and must be strengthened before moving on.

- [ ] **Step 6: End-to-end determinism against the Go target**

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx/scheds/experimental/scx_crfuzz/scenarios
   sudo ./go_run.sh --gate --project-schedule /tmp/go.steps --canonical-log /tmp/go.log
   for i in 1 2 3; do
     sudo ./go_run.sh --gate --canonical-log /tmp/go.$i.log
     diff /tmp/go.log /tmp/go.$i.log && echo "run $i: identical"
   done'
```

`go_run.sh` hardcodes `--freezer` at line 18 (confirmed before dispatch) — add a `--gate`
passthrough rather than editing the flag in place, so the freezer path keeps working. Expected:
no worse than the freezer's result. Section 14-A means this is not guaranteed 100%; record what
it actually is.

- [ ] **Step 7: Record the two latencies, with their definitions, and quote no ratio**

Added after the plan was written, because the spec changed under it. The spec's
"roughly an order of magnitude sharper" claim was **withdrawn** while reviewing Task 8
(commit `d61ad4ff`); see the two-clocks table at
`docs/superpowers/specs/2026-09-19-crfuzz-ops-dispatch-gate-design.md`. `max_gate_latency`
clocks the cost to *issue* a hold; `max_freeze_latency` clocks the kernel *converging*. The
intervals are disjoint, so their quotient means nothing. The spec names Task 9 as the owner
of the resolution and gives it two options; this step takes the second.

**Do not modify `backend_gate.rs` or `backend_freezer.rs`.** Both are reviewed and
spec-compliant; the defect was in the spec's comparison, not in either measurement. This step
only *reports*.

Run the same scenario under each backend and capture both stats lines:

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx/scheds/experimental/scx_crfuzz/scenarios
   sudo /workspace/scx/target-linux/debug/scx_crfuzz_gated & sleep 3
   sudo ../../../../target-linux/debug/scx_crfuzz --gate    race_wins.json 2>&1 | grep -i latency
   sudo ../../../../target-linux/debug/scx_crfuzz --freezer race_wins.json 2>&1 | grep -i latency'
```

Write the result into the report file as a table with three columns — backend, measured
value, and **what the clock actually covers** — reproducing the spec's wording for the
latter. State explicitly that no ratio is quoted and why. This table is what Task 10 Step 3
consumes; Task 10 must not reintroduce a comparison.

If the two numbers happen to land close together, say so plainly. A gate that is not
dramatically faster to *issue* than a cgroup write is an unremarkable result and does not
threaten the claim this branch actually rests on — no `ERESTARTSYS`, no fresh notification
id, a stable `NotifyHandle` — which Step 3's soundness test is what proves.

- [ ] **Step 8: Commit**

```bash
git add scheds/experimental/scx_crfuzz
git commit -m "$(cat <<'EOF'
scx_crfuzz: measure the gate

Two tests. The first adds a --gate column to thread_group_holding's existing
table and only proves parity with the freezer: 0 sibling bytes during a 300ms
hold, for both the 2-thread C fixture and the 11-thread Go one.

The second is the one that distinguishes them. It asserts the notification id
the engine was given is still the id it answers after a 300ms hold, and that no
replacement id arrives in between. The freezer fails this by construction --
its whole pid -> live-handle map exists because freezing restarts the held
syscall. This is gaps.md #7's soundness claim as an assertion.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Documentation

The arch docs assert the gate does not exist and that multi-threaded results are unsound. Both statements are now false, and leaving them is worse than having written no docs.

**Files:**
- Modify: `scheds/experimental/scx_crfuzz/README.md`
- Modify: `docs/arch/backends.md`
- Modify: `docs/arch/gaps.md`
- Modify: `docs/arch/harness.md`
- Modify: `scheds/experimental/scx_crfuzz/src/lib.rs` (crate docs)
- Create: `scheds/experimental/scx_crfuzz_gate/README.md`
- Create: `scheds/experimental/scx_crfuzz_gate/veristat/` baseline

- [ ] **Step 1: Capture the veristat baseline**

Follow `scheds/experimental/scx_mlfq/veristat/` for the file shape:

```bash
limactl shell sched-ext -- bash -lc \
  'cd /workspace/scx && veristat -o json \
   target-linux/debug/build/scx_crfuzz_gate-*/out/bpf.bpf.o \
   > scheds/experimental/scx_crfuzz_gate/veristat/aarch64.json'
```

- [ ] **Step 2: Update the crate README's status table**

Replace the two rows:

```markdown
| `FreezerBackend` — extends a hold to the thread group | **proof of concept**, Linux only — kept as the baseline `GateBackend` is measured against |
| `GateBackend` — `sched_ext` `ops.dispatch` gating | implemented, Linux only, needs `scx_crfuzz_gated` running |
```

- [ ] **Step 3: Replace the README's "TODO: replace the freezer with `ops.dispatch`" section**

It is now a description, not a TODO. Rewrite it as "Holding a thread group: the gate", keeping the three numbered reasons the freezer had to go (they are the motivation and they are still true), and adding:

- the two latencies **as Task 9 Step 7 recorded them**: each with a statement of what its
  clock covers, and **no ratio between them**. The spec's "roughly an order of magnitude
  sharper" claim was withdrawn in `d61ad4ff` because `max_gate_latency` measures the cost to
  issue a hold and `max_freeze_latency` measures the kernel converging — disjoint intervals.
  Do not write "against the freezer's ~350 µs", and do not divide the two numbers;
- the honest statement that the boundary is sharper, not zero, with the phase-2 in-kernel closure named;
- the 30 s `ops.timeout_ms` ceiling, which the freezer had no equivalent of;
- that `scx_crfuzz_gated` must be running first, and `--gate` fails rather than degrading if it is not.

Replace the "**Until `ops.dispatch` lands, results against multi-threaded targets remain unsound**" line with what is now true: results under `--gate` do not suffer the freezer's syscall restart; §14-A is still open, so run-to-run reproducibility against a multi-threaded target is not guaranteed.

- [ ] **Step 4: Update the thread-group table in the README**

Add the measured `--gate` column beside `--freezer`.

- [ ] **Step 5: Update `docs/arch/backends.md`**

Add a `GateBackend` section after `FreezerBackend`, covering the map, `HOLD_DSQ`, the enqueue/dispatch/exit_task behaviour, `SWITCH_PARTIAL` enrollment, and the four failure modes from the spec's error-handling table. Amend "What `ops.dispatch` would fix" from conditional to past tense, and correct its claim that the boundary is "one scheduling round rather than a convergence wait": the kick is one round, but the userspace round trip before it is not, and — per `d61ad4ff` — the gate and freezer latency numbers are not comparable quantities, so state what each covers instead of contrasting them.

- [ ] **Step 6: Update `docs/arch/gaps.md`**

Gap #7 is closed. Rewrite it as closed, naming the spec and what remains (phase 2's in-kernel gate write; the 30 s ceiling). Remove `ops.dispatch` from "Suggested order" item 6, and amend the opening "Where things stand" if it still implies the holding mechanism is missing.

- [ ] **Step 7: Update `docs/arch/harness.md`**

Add `--gate` to the CLI flag table, next to `--freezer`.

- [ ] **Step 8: Update the crate docs in `lib.rs`**

The "Seams" section lists the `sched_ext` `struct_ops` backend as deliberately not in this crate. It is now in `scx_crfuzz_gate`, which is a different statement — rewrite that bullet to point at the new crate and say why it is separate (the `build.rs`/macOS argument). Update the "Status" section's "treat results against multi-threaded targets as unsound" sentence the same way as the README.

- [ ] **Step 9: Write `scx_crfuzz_gate/README.md`**

Short: what the daemon is, why it is a separate crate, how to run it, the three CLI flags, the pinned paths, and the 30 s ceiling.

- [ ] **Step 10: Verify every claim you just wrote**

```bash
cd /Users/suhaasvaddadi/VSCode/senior-thesis/scx && cargo test -p scx_crfuzz 2>&1 | tail -5
```

Expected: `90 passed` on macOS. Then confirm the numbers written into the READMEs are the ones actually measured in Tasks 8 and 9 — not estimates carried over from the spec.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
docs: the gate exists; gaps.md #7 is closed

The arch docs asserted the ops.dispatch backend did not exist and that results
against multi-threaded targets were unsound. Both are now false.

Records both measured latencies with what each clock covers rather than a ratio
between them -- that comparison was withdrawn in d61ad4ff because the two clocks
measure disjoint intervals. Keeps the honest limits (the boundary is sharper,
not zero; ops.timeout_ms caps a hold at 30s; section 14-A is untouched), and
adds the veristat baseline.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Notes for the executor

**Run the daemon first.** Almost every test above skips itself with a message if `scx_crfuzz_gated` is not running. A suite that reports all-green having skipped everything is the failure mode to watch for — check the skip messages, not just the exit code.

**One test per binary for backend tests.** `SeccompNotifyBackend::reap` calls `waitpid(None)`, which is process-wide, so two backends in one test binary reap each other's children. This is why `exit_observation.rs` and `exit_status.rs` are separate files, and why `handle_stability.rs` is a third.

**Separate target dir in the VM.** `CARGO_TARGET_DIR=/workspace/scx/target-linux`. Host and guest share the checkout; without it a macOS `cargo build` drops Mach-O binaries into `./target` and every guest run dies with "cannot execute binary file".

**If Task 2's fallback is taken, stop and amend the spec before Task 3.** The fallback's boundary is worse than the freezer's, which falsifies a claim the spec makes in two places.
