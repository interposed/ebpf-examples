# exec-ringbuf (multi-file + ring buffer)

The same execution event as `exec-trace`, but delivered as a **structured record
through a BPF ring buffer** instead of a printk text line. This example exists to
show the structured path - and to document honestly what the operator does with
it today.

## Files

- `exec-ringbuf.bpf.c` - the compilation unit (declares the ring-buffer map and
  the program).
- `event.h` - the fixed-layout `struct exec_event` the program pushes. Kept in
  its own header so a userspace consumer could share the exact struct. This is
  the second **multi-file** example; upload both files together.

## What it observes

Every `execve(2)`, exactly like `exec-trace`.

## Hook and map

- `SEC("tracepoint/syscalls/sys_enter_execve")` - **observe** by construction.
- A `BPF_MAP_TYPE_RINGBUF` map named `events`, `max_entries = 256 * 1024`
  (256 KiB). Ring-buffer byte sizes must be a power of two and page-aligned;
  256 KiB satisfies both. (The daemon normalizes an out-of-spec size before load,
  but a valid declared size keeps the object portable to plain libbpf loaders.)

Because the object declares a ring buffer, the daemon reads **that map**
per-program - a clean, isolated feed - rather than the host-global trace pipe.

## Record layout (`struct exec_event`)

| Offset | Field      | Type       | Meaning |
|--------|------------|------------|---------|
| 0      | `pid`      | `u32`      | Userspace PID |
| 4      | `ppid`     | `u32`      | Parent PID |
| 8      | `comm`     | `u8[16]`   | NUL-padded process name |
| 24     | `filename` | `u8[256]`  | NUL-terminated exec path |

Total 280 bytes per record.

## What the operator shows today (important)

The interposed operator does **not** yet decode this struct. Each ring-buffer
record is rendered as byte-count + hex preview + an ASCII column (printable bytes
verbatim, others as `.`). So the readable part is the `comm`/`filename` tail; the
leading `pid`/`ppid` integers show as dots in the ASCII column.

Sample `bpf.trace` line for `exec pid=48213 comm=ls file=/usr/bin/ls`:

```
280B  d5 bc 00 00 8e 05 00 00 6c 73 00 00 00 00 00 00 00 00 00 00 2f 75 73 72 …  |........ls..........­/usr…|
```

- `d5 bc 00 00` = 0x0000bcd5 = 48341 (pid, little-endian)
- `8e 05 00 00` = 1422 (ppid)
- `6c 73` = `ls` (comm), then NUL padding
- `/usr...` = the start of the filename

A per-program field decoder in the operator is future work. **For human-legible
fields today, prefer a `bpf_printk` example** (exec-trace, etc.). This example is
here to demonstrate the structured plumbing and to make the current hex/ascii
behavior explicit.

## Classification

`observe` - a tracepoint that reserves/submits a ring-buffer record. Ring-buffer
helpers are not write helpers, so this is not mutate-class.

## Load it

Policies -> Observability -> **+ New**, add both `exec-ringbuf.bpf.c` and
`event.h`, **Build** (expect `class: observe`), **Save**, **Load** with
streaming, then add it as a Monitor eBPF-program widget. The pane source will
read `ringbuf` (not `trace_pipe`), with no host-global interleave caveat.
