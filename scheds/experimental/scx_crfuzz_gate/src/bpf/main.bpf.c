/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* A DSQ nothing consumes except the ungating path in ops.dispatch. */
#define HOLD_DSQ 1

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct gate_entry);
} gate SEC(".maps");

/*
 * A second gate, keyed by *thread id* rather than thread group. A role is a
 * thread group, but intra-group scheduling (design discussion: "actor
 * granularity") needs to hold one thread while its siblings run, and to
 * release one thread without releasing the rest. The tgid gate above cannot
 * express that: it is all-or-nothing for the group.
 *
 * The two maps are checked independently and either one holds the task, so
 * group granularity (the `gate` map) stays available unchanged and a caller
 * can mix the two.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct gate_entry);
} gate_tid SEC(".maps");

/*
 * A single monotonic counter, bumped atomically by crfuzz_epoch_next() below
 * and read back by userspace. Minting the epoch in BPF rather than with a
 * userspace lookup-then-update is what makes concurrent GateMap::open()
 * calls safe: a plain read-modify-write in userspace would let two racing
 * opens both read the same old value and both write old+1, so two
 * concurrent runs would silently share one epoch -- and then one run's
 * Drop-time cleanup would delete the OTHER run's gates too. Each run stamps
 * its gate entries with the epoch it was handed so its Drop can clear
 * exactly its own.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} epoch SEC(".maps");

static __always_inline bool is_gated(u32 tgid)
{
	return bpf_map_lookup_elem(&gate, &tgid) != NULL;
}

static __always_inline bool is_tid_gated(u32 tid)
{
	return bpf_map_lookup_elem(&gate_tid, &tid) != NULL;
}

/* Held if either the whole thread group is gated or this specific thread is. */
static __always_inline bool is_held(struct task_struct *p)
{
	return is_gated(p->tgid) || is_tid_gated(p->pid);
}

/*
 * Without this op defined, the kernel's default CPU-selection path
 * direct-dispatches a wakeup to an idle CPU's local DSQ entirely in-kernel,
 * the same as if a hand-written select_cpu() had called scx_bpf_dsq_insert()
 * itself -- and per the dispatch contract, direct dispatch from select_cpu()
 * skips ops.enqueue() (verified on target: with no select_cpu op, enqueue's
 * call count stayed at 0 while dispatch fired continuously). A task that
 * never reaches ops.enqueue() never gets gate-checked, which is exactly the
 * silent under-holding this backend must never allow.
 *
 * scx_bpf_select_cpu_dfl() only picks (and, if idle, wakes) a CPU; it does
 * not insert into any DSQ. Returning its result without ever calling
 * scx_bpf_dsq_insert() here means no direct dispatch happens from this op,
 * so ops.enqueue() is guaranteed to run for every task on every wakeup.
 */
s32 BPF_STRUCT_OPS(crfuzz_gate_select_cpu, struct task_struct *p, s32 prev_cpu,
		    u64 wake_flags)
{
	bool is_idle = false;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

void BPF_STRUCT_OPS(crfuzz_gate_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_held(p)) {
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
		if (is_held(p)) {
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

s32 BPF_STRUCT_OPS_SLEEPABLE(crfuzz_gate_init)
{
	return scx_bpf_create_dsq(HOLD_DSQ, -1);
}

void BPF_STRUCT_OPS(crfuzz_gate_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * First of three layers that stop a crashed run's gates wedging the next one.
 * The other two are userspace: GateBackend::Drop clears this run's epoch, and
 * `scx_crfuzz_gated --reset` clears the map wholesale.
 */
void BPF_STRUCT_OPS(crfuzz_gate_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	u32 tgid = p->tgid;
	u32 tid = p->pid;

	/* A per-thread gate must not outlive its thread. Unconditional: any
	 * thread, not just a leader, can own a `gate_tid` entry. */
	bpf_map_delete_elem(&gate_tid, &tid);

	if (p->pid == p->tgid)
		bpf_map_delete_elem(&gate, &tgid);
}

/*
 * Kick every CPU so any thread of a newly-gated thread group that is currently
 * on-CPU goes back through ops.enqueue and lands in the hold queue.
 *
 * Kicking all CPUs rather than tracking which ones run the group's threads:
 * the dev VM has few CPUs, a kick on an idle CPU is cheap, and a per-tgid CPU
 * map would have to be kept correct across migration for no measured benefit.
 *
 * The kernel's own CPU count (scx_bpf_nr_cpu_ids()), not the caller-supplied
 * nr_cpus, is the real bound on the loop: input->nr_cpus is only used to cap
 * it further, so a bad value from userspace can never produce an out-of-range
 * CPU id. The number of CPUs actually kicked is returned so the caller can
 * confirm the loop ran to completion -- this proves the program loads, is
 * callable from userspace while the scheduler is attached, and runs its full
 * loop. It does not prove a running sibling was actually preempted; that is
 * verified in Task 3's gate test, which watches a ticking process stop.
 */
SEC("syscall")
int crfuzz_kick_all(struct kick_arg *input)
{
	u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
	u32 nr = input->nr_cpus;
	u32 i;

	if (nr > nr_cpu_ids)
		nr = nr_cpu_ids;
	bpf_for(i, 0, nr) {
		scx_bpf_kick_cpu(i, SCX_KICK_PREEMPT);
	}
	return nr;
}

/*
 * Atomically bump the epoch counter and return the new value, so
 * GateMap::open() can mint an epoch without a userspace lookup-then-update
 * race: __sync_fetch_and_add is a single atomic RMW on the map's one
 * element, so two callers opening concurrently are guaranteed distinct
 * values. Returns 0 only if the map lookup fails. This function returns
 * `int`, so the u64 counter truncates to 32 bits on the way out; a returned
 * 0 is unambiguous failure only for the first 2^32 mints, since the counter
 * reaching exactly 2^32 truncates to 0 too.
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

/*
 * The thread-state sensor. Each registered run owns one slot and one ringbuf:
 * a ringbuf has a single consumer, and concurrent runs share this scheduler.
 * A run claims a slot via crfuzz_slot_claim() below, inserts its own ringbuf
 * into `sensor_rings` at that index, and only then writes the slot's
 * `cgroup_id`, so no record is ever reserved against a missing ringbuf.
 * Release runs the same steps in reverse.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CRFUZZ_MAX_RUNS);
	__type(key, u32);
	__type(value, struct crfuzz_slot);
} sensor_slots SEC(".maps");

struct crfuzz_ringbuf {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CRFUZZ_RINGBUF_BYTES);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, CRFUZZ_MAX_RUNS);
	__type(key, u32);
	__array(values, struct crfuzz_ringbuf);
} sensor_rings SEC(".maps");

long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;

/* sched_switch's prev_state bit for a task that is exiting, not sleeping. */
#define TASK_DEAD 0x80

/*
 * Reserve a `kind` record for `p` into the ringbuf of every run whose cgroup
 * subtree holds `p`. A full ringbuf bumps that slot's `dropped`: the run then
 * aborts, because its readout is unknowable. There is deliberately no
 * per-record sequence number; a counter taken before the reserve would not
 * match reserve order across CPUs.
 *
 * CRFUZZ_REC_JOINED is special: cgroup_attach_task fires after migration, so
 * `p` under the slot's cgroup means it moved in; otherwise it emits LEFT to
 * every run (the engine ignores LEFT for tids it does not track).
 */
static __always_inline void emit(struct task_struct *p, u32 kind, u32 arg)
{
	struct crfuzz_slot *slot;
	struct crfuzz_rec *rec;
	struct cgroup *cg;
	void *ring;
	long under;
	u32 i;

	bpf_for(i, 0, CRFUZZ_MAX_RUNS) {
		slot = bpf_map_lookup_elem(&sensor_slots, &i);
		if (!slot || !slot->cgroup_id)
			continue;
		cg = bpf_cgroup_from_id(slot->cgroup_id);
		if (!cg)
			continue;
		under = bpf_task_under_cgroup(p, cg);
		bpf_cgroup_release(cg);
		if (!under && kind != CRFUZZ_REC_JOINED)
			continue;
		ring = bpf_map_lookup_elem(&sensor_rings, &i);
		if (!ring)
			continue;
		rec = bpf_ringbuf_reserve(ring, sizeof(*rec), 0);
		if (!rec) {
			__sync_fetch_and_add(&slot->dropped, 1);
			continue;
		}
		rec->tid = p->pid;
		rec->tgid = p->tgid;
		rec->kind = under ? kind : CRFUZZ_REC_LEFT;
		rec->arg = arg;
		bpf_ringbuf_submit(rec, 0);
	}
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(crfuzz_on_wakeup_new, struct task_struct *p)
{
	/* `current` is the creator; the low 32 bits are its tid. */
	emit(p, CRFUZZ_REC_CREATED, (u32)bpf_get_current_pid_tgid());
	return 0;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(crfuzz_on_waking, struct task_struct *p)
{
	emit(p, CRFUZZ_REC_WAKE_START, 0);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(crfuzz_on_wakeup, struct task_struct *p)
{
	emit(p, CRFUZZ_REC_WAKE_DONE, 0);
	return 0;
}

/*
 * Only a voluntary block is a sleep. A signal-pending schedule() reports
 * prev_state == TASK_RUNNING, so it correctly emits nothing.
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(crfuzz_on_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, unsigned int prev_state)
{
	if (!preempt && prev_state && !(prev_state & TASK_DEAD))
		emit(prev, CRFUZZ_REC_ASLEEP, prev_state);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(crfuzz_on_exit, struct task_struct *p)
{
	emit(p, CRFUZZ_REC_EXITED, 0);
	return 0;
}

/*
 * Fires once per attach, with the group leader when `threadgroup` is set, so
 * the engine has to apply a group record to every thread of that tgid.
 */
SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(crfuzz_on_attach, struct cgroup *dst, const char *path,
	     struct task_struct *leader, bool threadgroup)
{
	emit(leader, CRFUZZ_REC_JOINED, threadgroup);
	return 0;
}

/*
 * Claim a free sensor slot for `input->epoch` and return its index, or
 * -ENOSPC when all are taken. The compare-and-swap on `epoch` (0 = free) is
 * what makes concurrent claims safe, the same reasoning as
 * crfuzz_epoch_next() above.
 */
SEC("syscall")
int crfuzz_slot_claim(struct slot_claim_arg *input)
{
	u64 epoch = input->epoch;
	struct crfuzz_slot *slot;
	u32 i;

	if (!epoch)
		return -EINVAL;
	bpf_for(i, 0, CRFUZZ_MAX_RUNS) {
		slot = bpf_map_lookup_elem(&sensor_slots, &i);
		if (slot && __sync_val_compare_and_swap(&slot->epoch, 0, epoch) == 0)
			return i;
	}
	return -ENOSPC;
}

SCX_OPS_DEFINE(crfuzz_gate_ops,
	       .select_cpu	= (void *)crfuzz_gate_select_cpu,
	       .enqueue		= (void *)crfuzz_gate_enqueue,
	       .dispatch	= (void *)crfuzz_gate_dispatch,
	       .init		= (void *)crfuzz_gate_init,
	       .exit		= (void *)crfuzz_gate_exit,
	       .exit_task	= (void *)crfuzz_gate_exit_task,
	       .timeout_ms	= 30000,
	       .name		= "crfuzz_gate");
