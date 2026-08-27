# signal-trace

Prints one line per signal delivered to a process: who sent it, to whom, and
which signal. Useful for spotting kills, crashes, and timer storms.

## What it observes

The `signal:signal_generate` tracepoint, which fires whenever a signal is
generated for a target task - `kill(2)`, timer expirations, faults (SIGSEGV),
job control, etc.

## Hook

`SEC("tracepoint/signal/signal_generate")` - a stable tracepoint, **observe** by
construction. The tracepoint fires in the context of the *sender*, so the current
task is the sender; the record carries the target's PID and the signal number.

## Fields emitted

Emitted with `bpf_printk`, so these appear verbatim as a `bpf.trace` line:

| Field        | Type       | Meaning |
|--------------|------------|---------|
| `sig`        | `int`      | Signal number (e.g. 9=SIGKILL, 15=SIGTERM, 11=SIGSEGV, 17=SIGCHLD) |
| `sender_pid` | `u32`      | PID of the process generating the signal (the current task) |
| `sender`     | `char[16]` | Name of the sending process |
| `target_pid` | `int`      | PID of the process the signal is aimed at (from the record) |

## Sample bpf.trace line

```
signal sig=15 sender_pid=1422 sender=bash target_pid=48213
```

## Classification

`observe` - reads the tracepoint record and prints. It does **not** send or
block signals: `bpf_send_signal` is a write helper and would make the program
mutate-class (tap-gated). This program never calls it.

## Caveats

- Kernel-originated signals (timers, faults) show a `sender` that is whatever
  task context the kernel was in - often the target itself for a fault, or a
  timer's owning task. Read `sig` together with `sender`/`target` to interpret.
- `sig` numbers are architecture-stable for the common signals but decode against
  `signal.h` on the target to be sure.
- Host-global trace pipe: lines interleave with other bpf_printk programs.

## Load it

Policies -> Observability -> **+ New**, paste `signal-trace.bpf.c`, **Build**
(expect `class: observe`), **Save**, **Load** with streaming, then add it as a
Monitor eBPF-program widget.
