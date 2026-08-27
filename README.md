# ebpf-examples

Ready-to-load eBPF programs for interposed's **bring-your-own eBPF** loader.

Each example is a small, well-documented, read-only observer: it watches one kind
of system event and prints a legible line you can read live in the operator. Load
one on your machines to see what your workloads are doing - what runs, what
connects out, what files get opened, what signals fly.

Every example is written so the **#1 thing you can tell at a glance** is: *what it
observes, which fields it emits, and how it works.* That is the top of every
per-example README.

## What this is for

interposed governs eBPF the way it governs everything else: kernel-enforced,
capability-gated, reversible. The bring-your-own path lets you (the machine
owner) bring or write an eBPF program and load it under control - classified,
gated, compiled on the target, verified, attached, and detachable. These examples
are the friendly starting set for the **observe** side of that door.

You drive it from the operator: **Policies -> Observability** (create/build/save/
load a program) and the **Monitor** page (add an "eBPF program" widget to watch
its output live across machines).

## The CO-RE model (how these compile)

These are [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/) programs
(Compile Once - Run Everywhere). You upload C source; the **daemon compiles it on
each target machine** against that machine's own kernel type information (BTF), so
one source file runs across kernel versions.

- Each program `#include "vmlinux.h"`. You do **not** ship that file. When your
  source references it but does not stage its own copy, the daemon generates it
  from the running kernel's BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux
  format c`) and puts it in the build dir before compiling.
- Compilation is `clang -O2 -g -target bpf` with the target's arch macro and the
  Debian multiarch include path. You never run clang yourself; the machine that
  will load the program is the machine that builds it.
- **Multi-file** is supported: upload a `.c` plus any `.h` it includes, and the
  loader stages them together so `#include "common.h"` resolves. (Several `.c`
  files are compiled separately and linked into one object with `bpftool gen
  object`; the common case is a single `.c`.)
- Programs **Build on-machine**. If a program fails to compile, the operator shows
  clang's verbatim log - Build-check a program on one machine before rolling it
  out.

## Where the output shows up

Two delivery paths, and the choice drives how legible your fields are:

1. **bpf_printk (preferred here).** A program that calls
   `bpf_printk("exec pid=%d comm=%s ...", ...)` writes readable text to the
   kernel trace pipe. The operator streams those lines **verbatim** into
   `bpf.trace`. Your format string *is* the output - so a self-documenting format
   string gives you self-documenting telemetry. Every example except one uses
   this.

   Caveat: the kernel trace pipe is **host-global**. If several bpf_printk
   programs are attached on one machine, their lines interleave in the pane; the
   operator flags this with a caveat. It is one shared stream, not a per-program
   feed.

2. **Ring buffer (structured).** A program that declares a
   `BPF_MAP_TYPE_RINGBUF` map and submits records gets a clean, **per-program**
   feed - the daemon reads that map directly, no interleave. But today the
   operator renders each record as byte-count + hex + `|ascii|`, **not** decoded
   into fields (a per-program decoder is future work). The `exec-ringbuf` example
   demonstrates this path and documents the hex/ascii view honestly.

**Design choice for this repo:** we optimize for legibility, so almost every
example uses `bpf_printk` with a clear, self-documenting format string. One
example (`exec-ringbuf`) shows the structured ring-buffer path so you can see the
trade-off.

## Observe-only, and why

Every program here classifies as **observe**: read-only tracepoints, kprobes, or
fentry that only read kernel state and print. Observe programs load without a
hardware tap.

The loader classifies a program **offline, before it ever reaches the kernel
verifier**, and refuses to auto-attach anything that can change kernel behavior.
A program is **mutate** (and is held for a hardware tap, never auto-loaded) if:

- its attach point grants power by construction - LSM (can deny), XDP/tc (can
  drop/redirect packets), cgroup/socket hooks (can block connections), etc.; or
- it calls a write helper - `bpf_probe_write_user`, `bpf_override_return`,
  `bpf_set_retval`, `bpf_send_signal`, packet-store, redirect, `bpf_sk_assign`,
  and friends.

**A mutating / LSM example is intentionally omitted from this repo.** It would be
classified mutate and held for a tap rather than loaded, so it does not belong in
a "load these freely to observe" set. That gate is the point: the same `bpf()`
door that a watched workload is forbidden from touching is opened only for the
daemon's authorized, observe-class path.

## Kernel requirements

- **BTF**: a kernel built with `CONFIG_DEBUG_INFO_BTF=y`, exposing
  `/sys/kernel/btf/vmlinux`. This is standard on recent Ubuntu/Debian/Fedora.
  Without it, `vmlinux.h` cannot be generated and CO-RE will not build.
- **Toolchain on the target**: `clang` and `bpftool` (Debian/Ubuntu:
  `apt install clang libbpf-dev bpftool`). The operator surfaces a clear message
  naming the missing package if one is absent.
- **Kernel 5.13+ recommended.** Several examples pass more than 3 arguments to
  `bpf_printk`, which uses `bpf_trace_vprintk` under the hood (added in 5.13).
  On older kernels, reduce a format string to 3 arguments or fewer.

## The examples

| Example | Observes | Hook (SEC) | Fields emitted | Notes |
|---|---|---|---|---|
| [exec-trace](exec-trace/) | Process executions | `tracepoint/syscalls/sys_enter_execve` | `pid, tid, ppid, comm, file` | The canonical first example |
| [tcp-connect](tcp-connect/) | Outbound IPv4 TCP connects | `kprobe/tcp_v4_connect` | `pid, comm, dport, dst` (dotted quad) | kprobe; reads the dest sockaddr |
| [file-open](file-open/) | `openat` calls | `tracepoint/syscalls/sys_enter_openat` | `pid, comm, flags, file` | High volume; filter by comm/path |
| [signal-trace](signal-trace/) | Signals delivered | `tracepoint/signal/signal_generate` | `sig, sender_pid, sender, target_pid` | Sender = current task |
| [process-lifecycle](process-lifecycle/) | Exec + exit | `tracepoint/sched/sched_process_exec` + `.../sched_process_exit` | `event, pid, ppid, comm` | **Multi-file** (`common.h` + `.c`), two programs |
| [exec-ringbuf](exec-ringbuf/) | Process executions (structured) | `tracepoint/syscalls/sys_enter_execve` | `struct exec_event {pid, ppid, comm, filename}` | **Multi-file** + **ring buffer**; operator shows hex/ascii today |
| [security-audit](security-audit/) | Security-sensitive ops interposed governs (exec, privilege change, outbound connect, ptrace) | 4 hooks: `.../sys_enter_execve` + `.../sys_enter_setuid` + `kprobe/tcp_v4_connect` + `.../sys_enter_ptrace` | `kind` + per-event fields (`pid, comm` always; then `ppid/file`, `uid`, `dst/dport`, `target/req`) | **interposed-specific**, **multi-hook**; unified `kind=`-tagged audit line |

Two examples are multi-file (`process-lifecycle`, `exec-ringbuf`); one uses a
ring buffer (`exec-ringbuf`); one is multi-hook (`security-audit`). All seven
classify as observe.

`security-audit` is the **interposed-flavored** example - the audit/enforcement
domain. It watches the same operation classes interposed's LSM enforcer governs
(exec, privilege change, outbound connect, ptrace) and prints one `kind=`-tagged
audit line per event: the observe twin of interposed's decision audit, watching
the same events in the kernel without enforcing them.

## How to load one (operator)

1. **Policies -> Observability -> + New.**
2. Paste the example's `.c` (and any `.h` - for the multi-file examples add both
   files).
3. **Build.** The daemon compiles it on the target against that kernel's BTF and
   shows the classification. Expect `class: observe`. A compile error shows
   clang's verbatim log; fix and rebuild.
4. **Save.**
5. **Load** (with streaming) to attach it live. Detach is the kill-switch - it
   unlinks and unloads the program from the kernel.
6. On **Monitor**, add a widget -> **eBPF program** -> pick your program -> choose
   the machines to run it on. The `bpf.trace` lines are your `bpf_printk` text
   (or, for `exec-ringbuf`, the hex/ascii record view).

## Per-program license

Each `.c` carries an Apache-2.0 SPDX header (this repo's license). Separately,
each program declares `char LICENSE[] SEC("license") = "GPL";` inside the object -
the **in-kernel program license** the kernel requires to permit GPL-only helpers
such as `bpf_probe_read_*`. The two are different things: Apache-2.0 governs the
source file; the `SEC("license")` string governs which kernel helpers the loaded
program may call.

## License

Apache-2.0. See [LICENSE](LICENSE).
