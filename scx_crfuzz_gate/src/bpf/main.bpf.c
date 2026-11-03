/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crfuzz_gate: a sched_ext scheduler that refuses to run gated tasks.
 * See spec §3.2 / L:Gate. Only tasks enrolled in SCHED_EXT are affected.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define HOLD_DSQ	0x0c4f
#define MAX_GATES	4096

UEI_DEFINE(uei);

/* Gate entries: key tgid / tid, value the owning run's epoch. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GATES);
	__type(key, u32);
	__type(value, u32);
} gate_tgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GATES);
	__type(key, u32);
	__type(value, u32);
} gate_tid SEC(".maps");

u32 epoch_seq;

static bool is_held(struct task_struct *p)
{
	u32 tgid = p->tgid, tid = p->pid;

	return bpf_map_lookup_elem(&gate_tgid, &tgid) ||
	       bpf_map_lookup_elem(&gate_tid, &tid);
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

void BPF_STRUCT_OPS(crfuzz_gate_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	u32 tgid = p->tgid, tid = p->pid;

	bpf_map_delete_elem(&gate_tid, &tid);
	if (tid == tgid)
		bpf_map_delete_elem(&gate_tgid, &tgid);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(crfuzz_gate_init)
{
	return scx_bpf_create_dsq(HOLD_DSQ, -1);
}

void BPF_STRUCT_OPS(crfuzz_gate_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* Preempt every CPU so on-CPU tasks re-enqueue and dispatch runs. Returns nr. */
SEC("syscall")
int kick_all(void *ctx)
{
	u32 nr = scx_bpf_nr_cpu_ids();
	s32 cpu;

	bpf_for(cpu, 0, nr)
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	return nr;
}

/* Minted in BPF so two runs can't draw the same epoch. */
SEC("syscall")
int new_epoch(void *ctx)
{
	return __sync_add_and_fetch(&epoch_seq, 1);
}

/*
 * ENQ_LAST: without it a kicked task that is the last runnable one on its CPU
 * keeps running without passing through enqueue, so its gate is never seen.
 */
SCX_OPS_DEFINE(crfuzz_gate_ops,
	       .select_cpu	= (void *)crfuzz_gate_select_cpu,
	       .enqueue		= (void *)crfuzz_gate_enqueue,
	       .dispatch	= (void *)crfuzz_gate_dispatch,
	       .exit_task	= (void *)crfuzz_gate_exit_task,
	       .init		= (void *)crfuzz_gate_init,
	       .exit		= (void *)crfuzz_gate_exit,
	       .flags		= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	       .timeout_ms	= 30000,
	       .name		= "crfuzz_gate");
