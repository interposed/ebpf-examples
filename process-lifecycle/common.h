/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 milsiz LLC
 *
 * common.h: helpers shared by the two programs in process-lifecycle. This file
 * exists to exercise the loader's MULTI-FILE fileset path: the daemon stages
 * every file you upload into one build dir so `#include "common.h"` resolves,
 * then compiles the single .c that includes it (see bpfbuild in the interpose
 * repo). Headers are not compilation units; they only ride along for includes.
 *
 * Include this AFTER <bpf/bpf_helpers.h> and <bpf/bpf_core_read.h>, since the
 * inline helpers below call bpf_get_current_pid_tgid / bpf_get_current_task and
 * use BPF_CORE_READ.
 */

#ifndef __PROCLIFE_COMMON_H
#define __PROCLIFE_COMMON_H

/* The current userspace PID (kernel tgid): the high 32 bits of pid_tgid. */
static __always_inline __u32 current_pid(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

/* The parent's PID, read CO-RE-safe from the current task_struct. */
static __always_inline __u32 current_ppid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(task, real_parent, tgid);
}

#endif /* __PROCLIFE_COMMON_H */
