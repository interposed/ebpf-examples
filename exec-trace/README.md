# exec-trace

The canonical first example. Prints one readable line for every process
execution on the host.

## What it observes

Every `execve(2)` syscall - i.e. every time a process starts a new program
image. This is the single best signal for "what is running on this machine".

## Hook

`SEC("tracepoint/syscalls/sys_enter_execve")` - the stable syscall-enter
tracepoint. A tracepoint is read-only by construction, so this classifies as
**observe** (no tap required). The context is `struct trace_event_raw_sys_enter`;
`args[0]` is the userspace pointer to the program path.

## Fields emitted

Emitted with `bpf_printk`, so these appear verbatim as a `bpf.trace` line:

| Field  | Type              | Meaning |
|--------|-------------------|---------|
| `pid`  | `u32`             | Userspace PID (the kernel `tgid`) of the process calling execve |
| `tid`  | `u32`             | Thread ID (the kernel `pid`) - equals `pid` for a single-threaded caller |
| `ppid` | `u32`             | Parent's PID, read from `task->real_parent->tgid` |
| `comm` | `char[16]`        | Name of the process calling execve (the caller, before the image is replaced) |
| `file` | string (<=255 ch) | The path passed to execve, copied from user memory |

## Sample bpf.trace line

```
exec pid=48213 tid=48213 ppid=1422 comm=bash file=/usr/bin/ls
```

## Classification

`observe` - a tracepoint that only reads task fields and prints. It never
denies, writes memory, or steers a syscall.

## Caveats

- `comm` is the *caller's* name at execve entry (e.g. `bash`), not the new
  program - the new image has not been installed yet. The new program is `file`.
- Output goes to the host-global kernel trace pipe. If several bpf_printk
  programs are attached at once, their lines interleave in `bpf.trace`; the
  operator flags this with a caveat on the pane.
- The `bpf_printk` line has 5 substituted arguments, which uses
  `bpf_trace_vprintk` under the hood - available on kernel 5.13+.

## Load it

Policies -> Observability -> **+ New**, paste `exec-trace.bpf.c`, **Build**
(expect `class: observe`), **Save**, then **Load** with streaming. On Monitor,
add a widget -> eBPF program -> pick `exec-trace` -> choose machines.
