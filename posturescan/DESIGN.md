# posturescan — DESIGN

**Threats:** Copy Fail / DirtyDecrypt / Dirty Frag (kernel LPE + container escape),
ssh-keysign-pwn (ptrace race), and the whole `bpf()` attack-surface argument.

## What it does

Measures and enforces the specific sysctls and kernel settings these incidents turn on.

Checks and remediates:

- `kernel.unprivileged_bpf_disabled` → want **1 or 2**
- `kernel.yama.ptrace_scope` → want **2** (this *is* the ssh-keysign-pwn fix)
- kernel `lockdown=confidentiality` → IronWorm's best hiding tricks fail under lockdown;
  hidden processes reappear
- `kptr_restrict`, `dmesg_restrict`, module-signing enforcement

Audits container specs / systemd units for `CAP_SYS_ADMIN` / `CAP_BPF` granted to anything
that isn't a legitimate eBPF tool, and scores the Podman setup (rootless, `--cap-drop=all`,
`no-new-privileges`, seccomp, read-only rootfs, user namespaces).

## Build

- Wrap **Lynis** (hardening index + suggestions) and **OpenSCAP** / `oscap` with a CIS or
  workstation profile (`scap-security-guide` ships datastreams) for compliance-grade
  scoring. Authoring custom OVAL/XCCDF here is the natural extension of day-job SCAP work.
- Add `systemd-analyze security` for per-service exposure scores.
- Thin Go/Python layer diffs current sysctls against a target profile and writes
  `/etc/sysctl.d/` drop-ins.
- Containers: generate per-workload seccomp profiles with `oci-seccomp-bpf-hook`; verify
  rootless Podman posture.

## What it verifies

A before/after hardening index and a per-sysctl `OK` / `DIFFERENT` table. Goal state:
`unprivileged_bpf_disabled=2`, `ptrace_scope=2`, lockdown on, no stray `CAP_BPF`.
Re-run after changes to confirm the numbers moved.

## Effort

1 week. Lynis/OpenSCAP are immediate; custom SCAP content + the sysctl-enforcement layer
is the bulk.