// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 milsiz LLC
//
// tcp-connect: trace outbound IPv4 TCP connects and print the calling process
// and the destination address:port. Read-only (OBSERVE): a kprobe that only
// reads the connect arguments and prints; it never blocks or rewrites the
// connection (that would be a cgroup/sockaddr hook, which is mutate-class).
//
// The "GPL" license string is the in-kernel program license required to call
// bpf_probe_read_* helpers; it is separate from this file's Apache-2.0 license.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
//
// At entry the syscall layer has already copied the user sockaddr into kernel
// memory, so `uaddr` is a kernel pointer we can read with BPF_CORE_READ. The
// destination address/port live in the sockaddr_in; the source port is not
// assigned yet, so we report only the destination.
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
	__u32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr); // network byte order

	// Split the big-endian address into octets so the trace line is a readable
	// dotted quad. ip[0] is the most-significant octet in network order.
	__u8 *ip = (__u8 *)&daddr;
	bpf_printk("connect pid=%d comm=%s dport=%d dst=%d.%d.%d.%d",
		   pid, comm, dport, ip[0], ip[1], ip[2], ip[3]);
	return 0;
}
