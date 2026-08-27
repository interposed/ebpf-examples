# file-open

Prints one line per `openat` call: which process is opening which path, with the
open flags. Great for "what files is this agent touching".

## What it observes

Every `openat(2)` syscall - the modern path for opening a file. Most file access
on Linux flows through `openat`.

## Hook

`SEC("tracepoint/syscalls/sys_enter_openat")` - the stable syscall-enter
tracepoint, **observe** by construction. Context is
`struct trace_event_raw_sys_enter`; the arguments are
`args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode`.

## Fields emitted

Emitted with `bpf_printk`, so these appear verbatim as a `bpf.trace` line:

| Field   | Type              | Meaning |
|---------|-------------------|---------|
| `pid`   | `u32`             | Userspace PID of the process opening the file |
| `comm`  | `char[16]`        | Name of that process |
| `flags` | `int` (hex)       | Open flags, e.g. `0x0`=O_RDONLY, `0x241`=O_WRONLY\|O_CREAT\|O_TRUNC |
| `file`  | string (<=255 ch) | The path passed to openat, copied from user memory |

## Sample bpf.trace line

```
open pid=48213 comm=cat flags=0x0 file=/etc/hostname
```

## Classification

`observe` - reads the syscall arguments and prints. Denying an open would need
an LSM hook (`lsm/file_open`), which is mutate-class and tap-gated; this program
does not do that.

## Caveats

- High volume. `openat` fires constantly (every library load, config read, etc.),
  so expect a busy stream. Filter by `comm` or path in the operator if you only
  care about one workload.
- Relative paths appear as-given; resolving them against `dfd` (the directory fd)
  is not done here.
- `flags` is printed in hex; decode against the `O_*` constants in `fcntl.h`.
- Host-global trace pipe: lines interleave with other bpf_printk programs.

## Load it

Policies -> Observability -> **+ New**, paste `file-open.bpf.c`, **Build**
(expect `class: observe`), **Save**, **Load** with streaming, then add it as a
Monitor eBPF-program widget.
