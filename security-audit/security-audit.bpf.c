// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// security-audit: the interposed-flavored example. One observe-class program
// that watches the same class of security-sensitive operations interposed's
// LSM enforcer governs - process exec, privilege change, outbound connect, and
// ptrace - and prints a unified, audit-style line per event with a `kind=` tag
// so the interleaved lines stay readable in one pane.
//
// This is the OBSERVE twin of interposed's decision audit: it SEES the same
// operation classes in the kernel, it does not ENFORCE them. Every hook here is
// a read-only tracepoint or kprobe that only reads state and prints. There is
// no deny, no write helper, no verdict - deny is interposed's LSM side; this is
// the see side.
//
// The "GPL" license string is the in-kernel program license the kernel requires
// to call helpers like bpf_probe_read_*; it is separate from this file's
// Apache-2.0 license on the source.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// kind=exec  - process execution
//
// Fires on entry to execve. args[0] is the userspace `filename` pointer. This
// is the "what started running" signal - the same event class interposed gates
// when it decides whether a binary is allowed to run.
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_execve")
int audit_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	const char *filename = (const char *)ctx->args[0];
	char fname[256];
	bpf_probe_read_user_str(&fname, sizeof(fname), filename);

	bpf_printk("audit kind=exec pid=%d ppid=%d comm=%s file=%s",
		   pid, ppid, comm, fname);
	return 0;
}

// ---------------------------------------------------------------------------
// kind=setuid  - privilege change (requested)
//
// Fires on entry to setuid. args[0] is the requested uid. This traces the
// REQUEST (intent to change credentials), not the result - the syscall may
// still be refused by the kernel. Privilege change is a first-class thing
// interposed watches: an agent trying to become another user.
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_setuid")
int audit_setuid(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 uid = (__u32)ctx->args[0]; // requested new uid

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	bpf_printk("audit kind=setuid pid=%d comm=%s uid=%d",
		   pid, comm, uid);
	return 0;
}

// ---------------------------------------------------------------------------
// kind=connect  - outbound IPv4 TCP connect
//
// int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
//
// At entry the syscall layer has copied the user sockaddr into kernel memory,
// so `uaddr` is a kernel pointer read with BPF_CORE_READ. The source port is
// not assigned yet, so we report only the destination. This is the egress
// signal - where a workload is talking to.
// ---------------------------------------------------------------------------
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(audit_connect, struct sock *sk, struct sockaddr *uaddr)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
	__u32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr); // network byte order
	__u8 *ip = (__u8 *)&daddr;

	bpf_printk("audit kind=connect pid=%d comm=%s dst=%d.%d.%d.%d dport=%d",
		   pid, comm, ip[0], ip[1], ip[2], ip[3], dport);
	return 0;
}

// ---------------------------------------------------------------------------
// kind=ptrace  - one process inspecting/controlling another
//
// long ptrace(long request, long pid, unsigned long addr, unsigned long data)
// args[0] = request, args[1] = target pid. This is the most interposed-relevant
// line of the four: an agent attaching to, reading, or steering another process
// is exactly the tamper class interposed's anti-tamper hooks care about. Here
// we only SEE it.
// ---------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_ptrace")
int audit_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__s32 request = (__s32)ctx->args[0];
	__s32 target = (__s32)ctx->args[1];

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	bpf_printk("audit kind=ptrace pid=%d comm=%s target=%d req=%d",
		   pid, comm, target, request);
	return 0;
}
