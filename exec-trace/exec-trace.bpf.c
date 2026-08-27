// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// exec-trace: trace every process execution on the host and print, as a
// readable trace line, who ran what. Read-only (OBSERVE): it only reads task
// fields and prints; it never denies, writes, or steers anything.
//
// The BPF program object itself carries a "GPL" license string below because
// the kernel requires a GPL-compatible license to call helpers like
// bpf_probe_read_*. That is the in-kernel program license and is separate from
// this repository's Apache-2.0 license on the source file.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Fires on entry to the execve syscall. The context is the generic syscall
// enter record; args[0] is the userspace `filename` pointer passed to execve.
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;      // userspace PID (kernel tgid)
	__u32 tid = (__u32)id;     // thread ID (kernel pid)

	// Parent PID, read CO-RE-safe from the current task_struct.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	// The path being executed. It lives in user memory at execve entry, so read
	// it with the user-string helper (bounded copy into a stack buffer).
	const char *filename = (const char *)ctx->args[0];
	char fname[256];
	bpf_probe_read_user_str(&fname, sizeof(fname), filename);

	bpf_printk("exec pid=%d tid=%d ppid=%d comm=%s file=%s",
		   pid, tid, ppid, comm, fname);
	return 0;
}
