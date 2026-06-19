# bpfsentry — out-of-band memory forensics (layer 3)

The part that can't be lied to. A `sys_bpf`-hooking eBPF rootkit hides its
programs from every live, on-box tool — `bpftool`, eBPF EDR, even bpfsentry's own
live enumeration. This pipeline acquires RAM from **outside** the live kernel and
walks the kernel's `prog_idr` structure directly in the image, bypassing the
hooked syscall. The divergence between that offline view and the live `bpftool`
view is itself proof of an implant.

> **A confirmed kernel-resident implant means reinstall — do not clean.**

## Everything here is privileged and documented, not run

These scripts **execute nothing privileged**. The acquisition and Volatility
commands need root, a hypervisor, or a kernel and a real memory image, so the
scripts only *print* the exact, reviewed commands. There is deliberately no flag
that makes them shell out. The build/CI never touch RAM, a hypervisor, Volatility,
LEMON, or `virsh`.

```
forensics/
├── acquire.py      # print out-of-band acquisition commands (KVM snapshot / LEMON / LiME)
├── vol_ebpf.py     # print the Volatility 3 prog_idr-walk command (linux.ebpf / ebpf_programs)
├── oob_parser.py   # pure transform: Volatility JSON → the shape `bpfsentry diff --oob` ingests
└── README.md
```

## The pipeline

```sh
# 1. Acquire RAM out of band (PREFERRED: a KVM guest snapshot — the host kernel
#    dumps the guest, so a guest-resident rootkit cannot interfere).
python3 acquire.py kvm --domain workstation        # prints the virsh command
#    -> virsh dump --memory-only --verbose workstation /trust-anchor/mem.dump

# 2. Walk prog_idr offline with Volatility 3 (prints the command; runs nothing).
python3 vol_ebpf.py /trust-anchor/mem.dump
#    -> vol -r json -f /trust-anchor/mem.dump linux.ebpf > vol-ebpf.json

# 3. Normalize Volatility's JSON to the bpfsentry interchange shape (this step
#    IS safe to run — pure data transformation).
python3 oob_parser.py vol-ebpf.json > oob-prog-idr.json

# 4. Diverge the offline view against the live view on the suspect host.
bpfsentry diff --config /etc/bpfsentry/config.json --oob oob-prog-idr.json
#    Any program present out-of-band but missing live  → hidden implant (Critical).
```

## Acquisition paths

| Environment | Tool | Note |
|-------------|------|------|
| Homelab KVM guest (**preferred**) | `virsh dump --memory-only` | host dumps the guest; sidesteps live-kernel acquisition entirely |
| Hardened bare metal (Secure Boot / lockdown) | **LEMON** (`eurecom-s3/lemon`, DFRWS EU 2026) | x86_64 + ARM64, kernels ≥ 5.5, LiME format; lockdown must not be confidentiality-mode |
| Legacy / unhardened | LiME | fails under module signing — use LEMON or a snapshot |

## Volatility plugins

- mainline `volatility3` `linux.ebpf` (productized)
- Asaf Eitani's `ebpf_programs` (the original heuristic)
- FKIE-CAD **BPFVol3** (fork with extra plugins)

Heuristic origin: Ben-Gurion University, *Detecting eBPF Rootkits Using
Virtualization and Memory Forensics* (SciTePress 2024). Flag programs whose used
helpers include `bpf_override_return`, `bpf_probe_write_user`, or
`bpf_send_signal` — `bpfsentry diff` does this for the live and allowlist paths;
`oob_parser.py` carries the helper list through so the same rule applies offline.

## Interchange shape

`oob_parser.py` emits exactly the JSON `internal/enumerate.Inventory`
unmarshals, so the Go `diff` command ingests it with no extra glue:

```json
{
  "source": "oob",
  "programs": [
    {"id": 99, "name": "", "type": "kprobe", "tag": "deadbeefcafef00d",
     "attach_to": "__x64_sys_bpf", "helpers": ["bpf_probe_write_user"],
     "pinned": [], "gpl_compatible": false}
  ],
  "maps": [],
  "links": []
}
```

Store every image and every normalized file on the **off-host trust anchor** —
the isolated host the monitored machines can write to but not read or rewrite.
