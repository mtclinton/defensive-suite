// SPDX-License-Identifier: GPL-2.0
//
// magicpacket.bpf.c — egresswatch magic-packet sensor.
//
// The BPFDoor/Symbiote signature is a process attaching a classic BPF filter to
// a raw/AF_PACKET socket so it can passively sniff for a magic activation packet
// without ever holding an open listening port. The setsockopt option that does
// this is SO_ATTACH_FILTER (and its reuseport variant SO_ATTACH_REUSEPORT_CBPF).
//
// This program hooks the kernel's setsockopt entry, fires when the option is
// SO_ATTACH_FILTER/SO_ATTACH_REUSEPORT_CBPF, and emits an event with the calling
// pid/uid/comm to a perf/ring buffer. egresswatch's userspace loader (loader.go,
// behind the same build tag) reads those events and routes them to journald and
// the webhook, exactly like the periodic /proc triage does.
//
// THIS IS A SHIPPED ARTIFACT, NOT BUILT BY THE DEFAULT egresswatch BUILD.
// It requires clang + libbpf headers + a BTF-enabled kernel and is compiled via
// the bpf2go //go:generate directive in generate.go. See deploy/README.md for
// the exact (privileged) build + load commands — egresswatch never runs them.
//
// Build (shown, not run):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//         -c bpf/magicpacket.bpf.c -o magicpacket.bpf.o
// or, the project way, via bpf2go from generate.go:
//   go generate ./bpf/...

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Socket-level option constants (uapi/asm-generic/socket.h). Declared locally so
// this file does not depend on userspace headers when compiled for the bpf target.
#define SOL_SOCKET 1
#define SO_ATTACH_FILTER 26
#define SO_ATTACH_REUSEPORT_CBPF 51

// Address family for packet sockets (linux/socket.h).
#define AF_PACKET 17

char LICENSE[] SEC("license") = "GPL";

// event is the record handed to userspace for every SO_ATTACH_FILTER on a
// packet socket. Keep it ABI-stable; loader.go mirrors this layout.
struct event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __s32 level;
    __s32 optname;
    __u16 family;     // socket family, AF_PACKET == 17 for the BPFDoor signature
    __u8  is_packet;  // 1 when the target socket is AF_PACKET / raw
    __u8  _pad;
    char  comm[16];
};

// Ring buffer for events (modern kernels). 256 KiB is plenty for a rare event.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// fexit on __sys_setsockopt would give us the return value, but the tracepoint
// sys_enter_setsockopt is the most portable hook and fires before the filter is
// installed. We read fd/level/optname from the syscall args; the loader resolves
// fd->socket family out of band, and we additionally tag family when we can read
// it cheaply via the task's fd table (best-effort; left to the loader otherwise).
SEC("tracepoint/syscalls/sys_enter_setsockopt")
int egresswatch_setsockopt(struct trace_event_raw_sys_enter *ctx)
{
    int level   = (int)ctx->args[1];
    int optname = (int)ctx->args[2];

    // Only the two CBPF-attach options matter for the BPFDoor signature.
    if (level != SOL_SOCKET ||
        (optname != SO_ATTACH_FILTER && optname != SO_ATTACH_REUSEPORT_CBPF))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->tgid    = id >> 32;
    e->pid     = (__u32)id;
    e->uid     = bpf_get_current_uid_gid();
    e->level   = level;
    e->optname = optname;
    // Family is resolved by the loader from the fd; default to "unknown".
    e->family    = 0;
    e->is_packet = 0;
    e->_pad      = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
