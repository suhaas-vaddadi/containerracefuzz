/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crfuzz_gate: a sched_ext scheduler that knows each run's task tree.
 *
 * A run's tree is its root, which joins before it enrolls in SCHED_EXT, and
 * every process forked below it, whatever cgroup, session or namespace it
 * moves to. For that tree the scheduler
 *   - counts the tasks that can run (`busy`): zero is the engine's frontier;
 *   - refuses to run any of them while the run is gated: they are enqueued
 *     on HOLD_DSQ, which the kernel never drains;
 *   - names each process by its place in the creation tree.
 * Only tasks enrolled in SCHED_EXT are scheduled here.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define HOLD_DSQ		0x0c4f
#define MAX_RUNS		1024
#define MAX_PROCS		65536
#define MAX_DEPTH		16
#define SCHED_EXT_POLICY	7

UEI_DEFINE(uei);

/* Userspace only reads and deletes these: every write is a program's. */
struct run {
	u32 owner;	/* the crfuzz that made it; dead: the run is stale */
	u32 gated;
	u32 escaped;	/* part of the tree is out of the gate's reach */
	u32 pad;
	s64 busy;	/* tasks runnable or being woken */
};

/* Key: the run's id, from new_run. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RUNS);
	__type(key, u32);
	__type(value, struct run);
} runs SEC(".maps");

u32 run_seq;

/*
 * A process of a run's tree. Its name is its path from the root: the
 * idx[0]-th process the root forked, that one's idx[1]-th, and so on.
 * depth > MAX_DEPTH: too deep to name.
 */
struct proc {
	u32 run;
	u32 kids;	/* processes it has forked */
	u32 depth;
	u32 idx[MAX_DEPTH];
};

/*
 * Key: tgid. Membership is per process, so threads the kernel makes without
 * a fork event (io_uring workers) are in.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, u32);
	__type(value, struct proc);
} procs SEC(".maps");

/* A task's user pc, stack and frame pointers at its latest syscall. */
struct user_regs {
	u64 pc;
	u64 sp;
	u64 fp;
	u32 tgid;
	u32 pad;
};

/* Key tid. Never cleaned: LRU evicts dead tids. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, struct user_regs);
} sys_regs SEC(".maps");

/* What the syscall programs are run on. */
struct run_arg {
	u32 run;
	u32 on;
};

static struct run *run_of(struct task_struct *p)
{
	u32 tgid = p->tgid;
	struct proc *pr = bpf_map_lookup_elem(&procs, &tgid);

	return pr ? bpf_map_lookup_elem(&runs, &pr->run) : NULL;
}

static void busy(struct task_struct *p, s64 by)
{
	struct run *r = run_of(p);

	if (r)
		__sync_fetch_and_add(&r->busy, by);
}

/*
 * `busy` counts a task from the moment something starts to wake it until it
 * is off its runqueue again. runnable/quiescent alone would miss a wakeup in
 * flight: one queued to another CPU reaches runnable only when that CPU
 * takes the IPI, and the waker can be asleep by then. sched_waking fires in
 * the waker, sched_wakeup once the wakee is on its runqueue (after runnable,
 * if there is one), so the two cover exactly that gap.
 */
/* ponytail: changing a queued task's class, priority or affinity dequeues
 * and re-enqueues it, so the count passes through zero for an instant; the
 * frontier reads it twice around a drain. Skip such pairs by their enqueue
 * and dequeue flags if a SUT that does this to its running threads ever
 * reads quiet. */
void BPF_STRUCT_OPS(crfuzz_gate_runnable, struct task_struct *p, u64 enq_flags)
{
	busy(p, 1);
}

void BPF_STRUCT_OPS(crfuzz_gate_quiescent, struct task_struct *p, u64 deq_flags)
{
	busy(p, -1);
}

SEC("tp_btf/sched_waking")
int BPF_PROG(waking, struct task_struct *p)
{
	busy(p, 1);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(woken, struct task_struct *p)
{
	busy(p, -1);
	return 0;
}

/*
 * A process forked in a run's tree joins it, before it first runs, named
 * after its parent. Threads need nothing: their process is already in.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(forked, struct task_struct *parent, struct task_struct *child)
{
	u32 ptgid = parent->tgid, tgid = child->tgid, depth;
	struct proc *pp, *cp;
	struct run *r;

	if (child->pid != tgid)
		return 0;
	pp = bpf_map_lookup_elem(&procs, &ptgid);
	if (!pp)
		return 0;
	/* The parent's run and path, then our own step. */
	if (bpf_map_update_elem(&procs, &tgid, pp, BPF_ANY) ||
	    !(cp = bpf_map_lookup_elem(&procs, &tgid))) {
		/* Table full: the child runs untracked. */
		r = bpf_map_lookup_elem(&runs, &pp->run);
		if (r)
			r->escaped = 1;
		return 0;
	}
	depth = cp->depth;
	if (depth < MAX_DEPTH)
		cp->idx[depth] = __sync_fetch_and_add(&pp->kids, 1);
	cp->depth = depth + 1;
	cp->kids = 0;
	return 0;
}

/*
 * The process is gone once its leader is freed: every thread is dead by
 * then. An exec from another thread hands the leader's pid to that thread
 * first, so the old leader no longer matches.
 */
/* ponytail: a tgid reused before the RCU-delayed free of its last owner
 * loses the newcomer's entry; compare start_time if pids ever wrap that fast. */
SEC("tp_btf/sched_process_free")
int BPF_PROG(freed, struct task_struct *p)
{
	u32 tgid = p->tgid;

	if (p->pid == tgid)
		bpf_map_delete_elem(&procs, &tgid);
	return 0;
}

/*
 * Runs in the trapping task before seccomp notifies (sys_enter fires only
 * after the release). Saves where to start the unwind; userspace walks the
 * frame pointers through /proc/<tid>/mem while the task is held, since an
 * unwind here can't fault in a cold stack page and stops short. A task of a
 * tree that is no longer in SCHED_EXT can't be gated or counted: its run is
 * flagged instead.
 */
SEC("kprobe/__secure_computing")
int BPF_KPROBE(save_regs)
{
	struct task_struct *p = bpf_get_current_task_btf();
	struct run *r = run_of(p);
	struct user_regs u = {};
	struct pt_regs *regs;
	u32 tid = p->pid;

	if (!r)
		return 0;
	if (p->policy != SCHED_EXT_POLICY) {
		r->escaped = 1;
		return 0;
	}
	regs = (struct pt_regs *)bpf_task_pt_regs(p);
	u.pc = PT_REGS_IP_CORE(regs);
	u.sp = PT_REGS_SP_CORE(regs);
	u.fp = PT_REGS_FP_CORE(regs);
	u.tgid = p->tgid;
	bpf_map_update_elem(&sys_regs, &tid, &u, BPF_ANY);
	return 0;
}

static bool is_held(struct task_struct *p)
{
	struct run *r = run_of(p);

	return r && r->gated;
}

/* Must exist and insert nothing, or wakeups to idle CPUs skip enqueue. */
s32 BPF_STRUCT_OPS(crfuzz_gate_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

void BPF_STRUCT_OPS(crfuzz_gate_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, is_held(p) ? HOLD_DSQ : SCX_DSQ_GLOBAL,
			   SCX_SLICE_DFL, enq_flags);
}

/* The kernel never drains HOLD_DSQ; move ungated tasks out of it here. */
void BPF_STRUCT_OPS(crfuzz_gate_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;

	bpf_for_each(scx_dsq, p, HOLD_DSQ, 0) {
		if (!is_held(p))
			scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_GLOBAL, 0);
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(crfuzz_gate_init)
{
	return scx_bpf_create_dsq(HOLD_DSQ, -1);
}

void BPF_STRUCT_OPS(crfuzz_gate_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* A new run, owned by the caller: its id, or 0 if the table is full. */
SEC("syscall")
int new_run(void *ctx)
{
	struct run r = { .owner = bpf_get_current_pid_tgid() >> 32 };
	u32 id = __sync_add_and_fetch(&run_seq, 1);

	return bpf_map_update_elem(&runs, &id, &r, BPF_NOEXIST) ? 0 : id;
}

/*
 * The caller becomes the root of ctx->run's tree. Called before it enrolls
 * in SCHED_EXT, so every runnable transition it makes there is counted.
 */
SEC("syscall")
int join(struct run_arg *ctx)
{
	struct proc p = { .run = ctx->run };
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	return bpf_map_update_elem(&procs, &tgid, &p, BPF_ANY);
}

/*
 * Gate or ungate ctx->run, then preempt every CPU, so its on-CPU tasks pass
 * through enqueue and dispatch runs. The preemption is an IPI: not a barrier.
 */
SEC("syscall")
int set_gate(struct run_arg *ctx)
{
	u32 id = ctx->run, nr = scx_bpf_nr_cpu_ids();
	struct run *r = bpf_map_lookup_elem(&runs, &id);
	s32 cpu;

	if (!r)
		return 1;
	r->gated = ctx->on;
	bpf_for(cpu, 0, nr)
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	return 0;
}

/*
 * ENQ_LAST: without it a kicked task that is the last runnable one on its CPU
 * keeps running without passing through enqueue, so its gate is never seen.
 */
SCX_OPS_DEFINE(crfuzz_gate_ops,
	       .select_cpu	= (void *)crfuzz_gate_select_cpu,
	       .enqueue		= (void *)crfuzz_gate_enqueue,
	       .dispatch	= (void *)crfuzz_gate_dispatch,
	       .runnable	= (void *)crfuzz_gate_runnable,
	       .quiescent	= (void *)crfuzz_gate_quiescent,
	       .init		= (void *)crfuzz_gate_init,
	       .exit		= (void *)crfuzz_gate_exit,
	       .flags		= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	       .timeout_ms	= 30000,
	       .name		= "crfuzz_gate");
