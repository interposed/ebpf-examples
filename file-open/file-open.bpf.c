// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// file-open: trace openat() calls and print which process is opening which
// path, with the open flags. Read-only (OBSERVE): it reads the syscall
// arguments and prints; it never denies an open (that would need an LSM hook,
// which is mutate-class and tap-gated).
//
// The "GPL" license string is the in-kernel program license required to call
// bpf_probe_read_* helpers; it is separate from this file's Apache-2.0 license.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// long sys_openat(int dfd, const char *filename, int flags, umode_t mode)
// In the generic syscall-enter record: args[0]=dfd, args[1]=filename (user
// pointer), args[2]=flags, args[3]=mode.
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	const char *filename = (const char *)ctx->args[1];
	int flags = (int)ctx->args[2];

	char fname[256];
	bpf_probe_read_user_str(&fname, sizeof(fname), filename);

	bpf_printk("open pid=%d comm=%s flags=0x%x file=%s",
		   pid, comm, flags, fname);
	return 0;
}
