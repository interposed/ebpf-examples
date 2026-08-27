// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// exec-ringbuf: the same execution event as exec-trace, but delivered through a
// BPF ring buffer as a structured record instead of a printk text line. This
// demonstrates the STRUCTURED path the loader supports: when an object declares
// a ring-buffer map, the daemon reads that map per-program (a clean, isolated
// feed) instead of the host-global trace_pipe.
//
// Honesty caveat: the operator does not yet decode the struct. It shows each
// record as byte-count + hex + |ascii| (formatRecord in the interpose repo), so
// the readable part is the comm/filename tail; the leading pid/ppid ints show as
// dots in the ascii column. A per-program decoder is future work. For legible
// fields today, use a bpf_printk example.
//
// Read-only (OBSERVE): reserving/submitting a ring-buffer record is not a write
// helper and a tracepoint cannot steer the kernel, so this classifies observe.
//
// The "GPL" license string is the in-kernel program license; it is separate
// from this file's Apache-2.0 license.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// The ring-buffer map. max_entries is the byte size of the ring and must be a
// power of two and page-aligned; 256 KiB satisfies both. (The daemon also
// normalizes an out-of-spec size before load, but declaring a valid one keeps
// the object portable to plain libbpf loaders.)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
	struct exec_event *e;

	// Reserve space in the ring; a NULL return means the ring is full.
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
