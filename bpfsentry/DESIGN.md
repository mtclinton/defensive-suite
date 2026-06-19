# bpfsentry — DESIGN (flagship)

**Threat:** the structural blind spot — eBPF rootkits (IronWorm, atomic-lockfile, QLNX,
LinkPro, BPFDoor) that hide from `bpftool` by hooking `sys_bpf`, defeating every live,
on-box tool including eBPF EDR.

## Thesis

Build at least one detection path that does not run on the compromised kernel.

## Three layers

### 1. Early-boot allowlist baseline
At boot, before any third-party agent or implant loads, enumerate all BPF programs/maps/
links (`bpftool prog show`, `map show`, attachment points) and persist the allowlist of
programs your real tools load (Cilium, your tracer, your EDR). Re-enumerate and diff
later: an attached program at a tracepoint/LSM hook nobody can name is the highest-signal
indicator.

### 2. Load-time alerting
- **Tetragon:** kprobe on `bpf_check` / `security_bpf_prog_load`, optional `SIGKILL`
  enforcement, PID-allowlist of legit loaders. Catches a rootkit at the moment it loads,
  before it hides.
- **Tracee:** `bpf_attach` event surfaces eBPF malware (e.g. Pamspy); `LdPreload` /
  TRC-7 catches `ld.so.preload` injection.
- **auditd:** `-a always,exit -F arch=b64 -S bpf -k bpf_activity` on hosts that shouldn't
  run eBPF.

### 3. Out-of-band memory forensics (the part that can't be lied to)
Acquire RAM from outside the live kernel and walk the kernel's `prog_idr` structure
directly — bypassing the hooked `sys_bpf` entirely.

- **Volatility 3** with the `ebpf_programs` plugin (Asaf Eitani) walks `prog_idr` in the
  memory image, bypassing the syscall interface. Flag suspicious helpers:
  `bpf_override_return`, `bpf_probe_write_user`, `bpf_send_signal`.
  - Productized alternatives: mainline `volatility3` `linux.ebpf` plugin; FKIE-CAD BPFVol3.
  - Heuristic origin: Ben-Gurion U., *Detecting eBPF Rootkits Using Virtualization and
    Memory Forensics* (SciTePress 2024).
- **Acquisition under hardening** (Secure Boot / module signing / lockdown break LiME and
  AVML): **LEMON** (EURECOM S3, `eurecom-s3/lemon`, DFRWS EU 2026) — x86_64 + ARM64,
  kernels ≥ 5.5, outputs LiME format.
  - Constraint: kernel lockdown must not be in confidentiality mode (or must allow
    `bpf_probe_read_kernel()`).
  - **Homelab path:** run workloads in a KVM guest and take hypervisor memory snapshots
    (`virsh dump --memory-only`) as the trusted out-of-band acquisition — sidesteps
    live-kernel acquisition entirely.

## Build

Go + `cilium/ebpf` for the enumerator/differ; a systemd early-boot unit for the baseline;
Tetragon/Tracee as agents; Volatility 3 (Python) for the offline pass with BTF-derived
profiles. Learn from `ebpfkit-monitor` (static-ELF analysis + runtime `bpf()` monitor) and
`bpftop` for live-enumeration UI — noting both are defeated by a `sys_bpf` hook, which is
*why* layer 3 exists.

## What it verifies

"Live BPF program set matches early-boot allowlist; Tetragon recorded 0 unexpected `bpf()`
loads; offline `prog_idr` walk of last night's snapshot shows 0 programs with
`bpf_probe_write_user`/`bpf_override_return` and 0 unnamed kretprobe/XDP programs."

Any divergence between the live `bpftool` view and the memory-dump view is itself proof of
a `sys_bpf`-hooking rootkit. If a kernel-resident implant is confirmed: **reinstall — do
not clean.**

## Effort

Multi-week. Tetragon/Tracee + auditd is week one; the early-boot enumerator/differ is week
two; the Volatility/LEMON offline pipeline + KVM-snapshot automation is the deep end.

## Suggested directory layout

```
bpfsentry/
├── cmd/bpfsentry/        # Go CLI: baseline, diff, agent
├── internal/enumerate/   # cilium/ebpf prog/map/link enumeration
├── internal/baseline/    # early-boot allowlist capture + diff
├── deploy/               # systemd units, Tetragon/Tracee policies, auditd rules
└── forensics/            # Python: Volatility 3 prog_idr walk, LEMON acquisition wrappers
```