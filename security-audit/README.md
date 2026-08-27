# security-audit

The interposed-flavored example. One observe-class program that watches the same
class of security-sensitive operations interposed's LSM enforcer governs, and
prints a unified, audit-style line per event.

Think of it as **the observe twin of interposed's decision audit**: it watches
the same operation classes in the kernel *without enforcing them*. interposed's
LSM enforcer is the **deny** side; this is the **see** side.

## What it observes

Four security-sensitive operation classes, in one program, each tagged with a
`kind=` so the interleaved lines stay readable:

| `kind=`   | Operation | Hook (SEC) | Why interposed cares |
|-----------|-----------|------------|----------------------|
| `exec`    | Process execution (`execve`) | `tracepoint/syscalls/sys_enter_execve` | What binary started running - the allow/deny-to-run class |
| `setuid`  | Privilege change (requested) | `tracepoint/syscalls/sys_enter_setuid` | A process trying to change credentials |
| `connect` | Outbound IPv4 TCP connect | `kprobe/tcp_v4_connect` | Where a workload is talking to (egress) |
| `ptrace`  | One process inspecting/controlling another | `tracepoint/syscalls/sys_enter_ptrace` | The tamper class - an agent attaching to another process |

Every line begins `audit kind=<class> ...` so you can grep, sort, or read the
shared trace pane and still tell the classes apart.

## Fields emitted

All lines share `pid` (userspace PID, the kernel `tgid`) and `comm` (the calling
process name, `char[16]`). Per-kind fields:

### `kind=exec`

| Field  | Type              | Meaning |
|--------|-------------------|---------|
| `ppid` | `u32`             | Parent's PID, read from `task->real_parent->tgid` |
| `file` | string (<=255 ch) | The path passed to execve, copied from user memory |

```
audit kind=exec pid=48213 ppid=1422 comm=bash file=/usr/bin/ls
```

### `kind=setuid`

| Field | Type  | Meaning |
|-------|-------|---------|
| `uid` | `u32` | The **requested** new uid (the syscall argument, before the kernel accepts or refuses it) |

```
audit kind=setuid pid=5310 comm=su uid=0
```

### `kind=connect`

| Field   | Type        | Meaning |
|---------|-------------|---------|
| `dst`   | dotted quad | Destination IPv4 address, printed `a.b.c.d` |
| `dport` | `u16`       | Destination TCP port, host byte order (`bpf_ntohs`) |

```
audit kind=connect pid=5120 comm=curl dst=140.82.113.3 dport=443
```

### `kind=ptrace`

| Field    | Type  | Meaning |
|----------|-------|---------|
| `target` | `s32` | The PID being traced (`ptrace` arg 1) |
| `req`    | `s32` | The `ptrace` request number (arg 0), e.g. `16` = `PTRACE_ATTACH`, `4` = `PTRACE_POKETEXT` |

```
audit kind=ptrace pid=9001 comm=gdb target=8800 req=16
```

## Classification

**observe.** All four hooks are read-only: three stable syscall-enter
tracepoints and one kprobe that only reads arguments and prints. No LSM hook, no
XDP/tc verdict, no cgroup/socket gate, and no write helper
(`bpf_probe_write_user`, `bpf_override_return`, `bpf_send_signal`, ...). The
loader classifies this offline, before it reaches the verifier, as `observe`, so
it loads without a hardware tap.

## The honest caveat: this OBSERVES, it does not ENFORCE

This program **cannot deny anything**. It watches; it does not gate. In
particular:

- `kind=setuid` and `kind=ptrace` trace the syscall **request** at entry - the
  intent - not the outcome. The kernel may still refuse the call. You are seeing
  what was *attempted*.
- The deny/allow decision for these same operation classes is interposed's LSM
  enforcer, which is a separate, mutate-class, tap-gated path. That program would
  be classified **mutate** and held for a hardware tap - it is deliberately not
  in this repo. This example is the free-to-load counterpart: same operation
  classes, see-only.

Together they are two halves of one audit: the enforcer records the **decision**;
this records the **observation** in the kernel next to it.

## Other caveats

- Output goes to the host-global kernel trace pipe. With four hooks in one
  program plus any other bpf_printk programs attached, lines interleave in
  `bpf.trace` - the `kind=` tag is what keeps them legible. The operator flags
  the shared-pipe caveat on the pane.
- IPv4 only for `connect`. IPv6 goes through `tcp_v6_connect`; add a second
  kprobe if you need it.
- `sys_enter_setuid` traces the `setuid` syscall. Some C libraries route
  privilege changes through `setreuid`/`setresuid` instead; if you want those,
  add `tracepoint/syscalls/sys_enter_setreuid` (arg layout: `ruid`, `euid`) as a
  sibling hook. **Build-check `setuid` on your target first** - the exact set of
  `setuid*` tracepoints exposed can vary by arch/kernel config.
- `comm` on `kind=exec` is the *caller's* name (e.g. `bash`), not the new image
  - the new program is in `file`.
- Each `bpf_printk` line stays at a modest argument count; the widest is
  `kind=connect` (7 substituted args, the four octets + pid + comm + dport),
  which uses `bpf_trace_vprintk` under the hood - kernel **5.13+**.

## Builds on-machine

Like every example here, this is CO-RE: you upload the `.c`, and the daemon
compiles it on each target against that machine's own BTF (`vmlinux.h` is
generated there). If it fails to compile, the operator shows clang's verbatim
log - Build-check it on one machine before rolling it out.

## Load it

Policies -> Observability -> **+ New**, paste `security-audit.bpf.c`, **Build**
(expect `class: observe`), **Save**, then **Load** with streaming. On Monitor,
add a widget -> eBPF program -> pick `security-audit` -> choose machines. Filter
the pane by `kind=` to focus on one operation class.
