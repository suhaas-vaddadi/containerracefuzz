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

struct kick_arg {
	unsigned int nr_cpus;
};

/* Concurrent runs the thread-state sensor can serve at once. */
#define CRFUZZ_MAX_RUNS 64
/* Per-run ringbuf size: must cover an `auto_attack` window between drains. */
#define CRFUZZ_RINGBUF_BYTES (16 << 20)

/*
 * One sensor slot per registered run. BPF ignores a slot whose `cgroup_id` is
 * 0; `epoch` is the claim (0 = free), so `--reset` and a run's Drop can tell
 * owned slots apart; `dropped` counts records lost to a full ringbuf.
 */
struct crfuzz_slot {
	unsigned long long cgroup_id;
	unsigned long long epoch;
	unsigned long long dropped;
};

struct slot_claim_arg {
	unsigned long long epoch;
};

/* One thread-state record, as reserved into a run's ringbuf. */
struct crfuzz_rec {
	unsigned int tid;
	unsigned int tgid;
	unsigned int kind;
	unsigned int arg;
};

/*
 * `arg` is the creator tid for CREATED, `prev_state` for ASLEEP, the
 * `threadgroup` flag for JOINED/LEFT, and 0 otherwise.
 */
#define CRFUZZ_REC_CREATED	1
#define CRFUZZ_REC_WAKE_START	2
#define CRFUZZ_REC_WAKE_DONE	3
#define CRFUZZ_REC_ASLEEP	4
#define CRFUZZ_REC_EXITED	5
#define CRFUZZ_REC_JOINED	6
#define CRFUZZ_REC_LEFT		7

#endif /* __CRFUZZ_GATE_INTF_H */
