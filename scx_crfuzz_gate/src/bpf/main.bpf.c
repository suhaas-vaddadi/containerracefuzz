/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

SCX_OPS_DEFINE(crfuzz_gate_ops,
	       .name = "crfuzz_gate");
