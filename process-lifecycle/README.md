# process-lifecycle (multi-file)

Two programs in one object that bracket a process's life: one line when a process
execs, one line when it exits. This is the **multi-file** example - it exists to
exercise the loader's fileset path.

## Files

- `proclife.bpf.c` - the single compilation unit, holding both programs.
- `common.h` - shared inline helpers (`current_pid`, `current_ppid`) used by both
  programs.

The loader stages every file you upload into one build dir so
`#include "common.h"` resolves, then compiles the `.c`. Headers are not
compilation units; they only ride along for include resolution. (If you ever
upload two or more `.c` files, each is compiled and then linked into one object
with `bpftool gen object` - but this example uses the common single-`.c` shape.)

Upload BOTH files together in the editor. `proclife.bpf.c` is the entry `.c`;
`common.h` accompanies it.

## What it observes

- Process exec, via `sched:sched_process_exec`.
- Process exit, via `sched:sched_process_exit`.

## Hooks

| Program   | SEC | Why |
|-----------|-----|-----|
| `on_exec` | `tracepoint/sched/sched_process_exec` | Fires when a task installs a new program image |
| `on_exit` | `tracepoint/sched/sched_process_exit` | Fires when a task exits |

Both are tracepoints, so both are **observe**.

## Fields emitted

Both programs share a `proclife event=<exec|exit>` prefix so the two streams are
distinguishable in one pane.

`on_exec`:

| Field   | Type       | Meaning |
|---------|------------|---------|
| `event` | literal    | `exec` |
| `pid`   | `u32`      | Userspace PID |
| `ppid`  | `u32`      | Parent PID (`task->real_parent->tgid`) |
| `comm`  | `char[16]` | Process name |

`on_exit`:

| Field   | Type       | Meaning |
|---------|------------|---------|
| `event` | literal    | `exit` |
| `pid`   | `u32`      | Userspace PID |
| `comm`  | `char[16]` | Process name |

## Sample bpf.trace lines

```
proclife event=exec pid=48213 ppid=1422 comm=sleep
proclife event=exit pid=48213 comm=sleep
```

## Classification

`observe` - both programs are tracepoints that only read and print. The whole
object is observe because every program in it is.

## Caveats

- On `sched_process_exec` the current task's `comm` may still read as the old
  name depending on ordering; treat it as an approximation and pair with
  exec-trace if you need the exact new program path.
- Host-global trace pipe: the two programs' lines interleave (by design here),
  and also interleave with any other bpf_printk program on the host.

## Load it

Policies -> Observability -> **+ New**, add both `proclife.bpf.c` and
`common.h`, **Build** (expect `class: observe`, two programs listed), **Save**,
**Load** with streaming, then add it as a Monitor eBPF-program widget.
