// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// signal-trace: trace signals delivered to processes (kill, timers, faults) and
// print the sender, the target, and the signal number. Read-only (OBSERVE): it
// reads the signal_generate tracepoint and prints; it never sends or blocks a
// signal (bpf_send_signal would make it mutate-class).
//
// The "GPL" license string is the in-kernel program license; it is separate
// from this file's Apache-2.0 license.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// The signal_generate tracepoint fires in the context of the SENDER, so the
// current task is the sender; the record's `pid` field is the TARGET process
// and `sig` is the signal number.
SEC("tracepoint/signal/signal_generate")
int trace_signal(struct trace_event_raw_signal_generate *ctx)
{
	__u32 sender_pid = bpf_get_current_pid_tgid() >> 32;

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	int sig = ctx->sig;
	int target_pid = ctx->pid;

	bpf_printk("signal sig=%d sender_pid=%d sender=%s target_pid=%d",
		   sig, sender_pid, comm, target_pid);
	return 0;
}
