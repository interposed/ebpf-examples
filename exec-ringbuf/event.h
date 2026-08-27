/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 milsiz LLC
 *
 * event.h: the fixed-layout record exec-ringbuf pushes into its ring buffer.
 * Kept in its own header so a userspace consumer could share the exact same
 * struct definition. This is also the second MULTI-FILE example: the loader
 * stages event.h next to the .c so `#include "event.h"` resolves.
 *
 * IMPORTANT: the interposed operator does NOT yet decode this struct. It renders
 * each ring-buffer record as byte-count + hex + |ascii| (see formatRecord in the
 * interpose repo). The layout below is what those bytes mean; a per-program
 * field decoder in the operator is future work. For human-legible fields today,
 * prefer a bpf_printk program (see the other examples).
 */

#ifndef __EXEC_EVENT_H
#define __EXEC_EVENT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME  256

struct exec_event {
	__u32 pid;                    /* offset 0:  userspace PID (kernel tgid) */
	__u32 ppid;                   /* offset 4:  parent PID                  */
	__u8  comm[TASK_COMM_LEN];    /* offset 8:  NUL-padded process name     */
	__u8  filename[MAX_FILENAME]; /* offset 24: NUL-terminated exec path    */
};

#endif /* __EXEC_EVENT_H */
