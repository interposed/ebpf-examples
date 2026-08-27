// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// process-lifecycle: two programs in one object that bracket a process's life,
// emitting one trace line when a process execs and one when it exits. This is
// the MULTI-FILE example: the shared helpers live in common.h, which the loader
// stages alongside this .c so the #include resolves. Read-only (OBSERVE): both
// programs only read task fields and print.
//
// The "GPL" license string is the in-kernel program license; it is separate
// from this file's Apache-2.0 license.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// A process has replaced its image with a new program.
SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = current_pid();
	__u32 ppid = current_ppid();

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	bpf_printk("proclife event=exec pid=%d ppid=%d comm=%s", pid, ppid, comm);
	return 0;
}

// A process is exiting.
SEC("tracepoint/sched/sched_process_exit")
int on_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	__u32 pid = current_pid();

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	bpf_printk("proclife event=exit pid=%d comm=%s", pid, comm);
	return 0;
}
