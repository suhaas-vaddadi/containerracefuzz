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

#endif /* __CRFUZZ_GATE_INTF_H */
