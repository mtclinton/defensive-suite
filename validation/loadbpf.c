// loadbpf.c — a synthetic, NON-allowlisted eBPF program loader.
//
// It loads the most trivial valid eBPF program (set r0=0; exit) via
// bpf(BPF_PROG_LOAD). The validation harness uses it two ways:
//   - OBSERVE mode: it loads successfully and Tetragon reports the load, which
//     agentd turns into a "realtime.bpf" finding (this binary is not on the
//     loader allow-list, so it's High).
//   - ENFORCE mode: the dsuite-enforce policy SIGKILLs any non-allowlisted binary
//     that reaches security_bpf_prog_load — so THIS process should be killed
//     (exit via signal 9) before it can print the success line.
//
// Build:  cc -O2 -o loadbpf loadbpf.c
// It needs root (or CAP_BPF) to load; the harness runs it as root in a VM.
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    // r0 = 0 ; exit   — the minimal program the verifier accepts.
    struct bpf_insn insns[] = {
        {.code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0}, // BPF_MOV64_IMM(r0, 0)
        {.code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0}, // BPF_EXIT_INSN()
    };

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
    attr.insns = (unsigned long)insns;
    attr.license = (unsigned long)"GPL";

    int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        perror("BPF_PROG_LOAD");
        return 1; // load failed (e.g. unprivileged_bpf_disabled) — not the kill we test for
    }
    // Reached only if NOT killed: in enforce mode this line must never print.
    printf("loaded eBPF prog (fd=%d) — NOT killed\n", fd);
    return 0;
}
