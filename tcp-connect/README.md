# tcp-connect

Prints one line per outbound IPv4 TCP connection attempt: who is connecting, and
where to.

## What it observes

Every call to `tcp_v4_connect` in the kernel - the function that initiates an
outbound IPv4 TCP connection. This is the "what is this process talking to"
signal.

## Hook

`SEC("kprobe/tcp_v4_connect")` - a kprobe on the kernel function, entered via the
`BPF_KPROBE(...)` macro so the function arguments are typed. A kprobe that only
reads and prints is **observe**. (Blocking or rewriting a connection would need a
cgroup/sockaddr hook, which is mutate-class and tap-gated.)

At entry the syscall layer has already copied the user-supplied `sockaddr` into
kernel memory, so the destination is read with `BPF_CORE_READ` (a kernel read).
The source port is not assigned yet at this point, so only the destination is
reported.

## Fields emitted

Emitted with `bpf_printk`, so these appear verbatim as a `bpf.trace` line:

| Field   | Type       | Meaning |
|---------|------------|---------|
| `pid`   | `u32`      | Userspace PID of the connecting process |
| `comm`  | `char[16]` | Name of the connecting process |
| `dport` | `u16`      | Destination TCP port, host byte order (converted with `bpf_ntohs`) |
| `dst`   | dotted quad | Destination IPv4 address, printed as `a.b.c.d` |

## Sample bpf.trace line

```
connect pid=5120 comm=curl dport=443 dst=140.82.113.3
```

## Classification

`observe` - a kprobe that reads the connect arguments and prints. No write
helper, no verdict.

## Caveats

- IPv4 only. IPv6 connects go through `tcp_v6_connect`; add a second kprobe on
  that function if you need them.
- The address is read from the caller-supplied `sockaddr`; a program that passes
  a malformed address may produce an odd-looking `dst`. This traces intent (the
  requested destination), not a confirmed established connection.
- `bpf_printk` here has 7 substituted arguments, which uses `bpf_trace_vprintk`
  (kernel 5.13+).
- Host-global trace pipe: lines interleave with other bpf_printk programs.

## Load it

Policies -> Observability -> **+ New**, paste `tcp-connect.bpf.c`, **Build**
(expect `class: observe`), **Save**, **Load** with streaming, then add it as a
Monitor eBPF-program widget.
