# Threat Model

The attacker objective these tools defend against, in one sentence: compromise a Linux
developer workstation through a poisoned dependency, harvest the credential files that
gate build pipelines (`.npmrc`, `.aws/credentials`, `.kube/config`, SSH keys, Vault
tokens), and then hide kernel-resident via an eBPF rootkit.

## Source threats → defenses

| Threat | What it does | Defended by |
|--------|--------------|-------------|
| **eBPF rootkits (commodity)** — IronWorm, atomic-lockfile, LinkPro, BPFDoor lineage | Hides files (`getdents64`), processes (`/proc`), sockets (`/proc/net/tcp` + netlink), and itself from `bpftool` (`sys_bpf` hook); magic-packet C2 | `bpfsentry`, `egresswatch` |
| **atomic-lockfile / "Atomic Arch" AUR** | 400+ AUR packages; PKGBUILD runs `npm install atomic-lockfile`; preinstall ELF steals `.npmrc`/`.aws`/`.kube`/`.docker`/Vault/browser/Electron data; optional root eBPF rootkit | `instguard`, `credsentinel` |
| **QLNX (Quasar Linux RAT)** | Compiles two PAM backdoors on-host; persists via `LD_PRELOAD`/`ld.so.preload`; eBPF rootkit; fake X11 lockfile | `authwatch`, `posturescan` |
| **Velvet Ant / Operation Highland** | Backdoored `pam_unix.so` (9 variants) + OpenSSH binaries; appended `authorized_keys` | `authwatch` |
| **npm/registry attacks** — Mastra/easy-day-js, IronWorm, Miasma/Shai-Hulud, codexui-android, Nx Console, TrapDoor | Typosquats + install-time stealers; cross-registry (npm/PyPI/Crates) | `instguard`, `credsentinel` |
| **Kernel LPE + container escape** — Copy Fail, DirtyDecrypt, Dirty Frag, ssh-keysign-pwn | Privilege escalation; isolation breakout; ptrace race (fixed by `yama.ptrace_scope=2`) | `posturescan` |
| **BPFDoor/Symbiote magic-packet backdoors** | Passive, portless raw-socket BPF filter; magic-packet activation | `egresswatch` |
| **Secret/credential exposure** — Private-CISA GitHub leak | Long-lived credentials at rest in dotfiles / repos | `credsentinel` |

## Decision thresholds

- **Any** TruffleHog verified-live hit or Canarytoken trip → stop, rotate all credentials from a clean device, escalate to `bpfsentry`'s offline check.
- A divergence between live `bpftool` and the memory-dump `prog_idr` walk, or any unnamed program using `bpf_probe_write_user` / `bpf_override_return` → confirmed kernel implant → **reinstall, don't clean.**
- Lynis hardening index below ~70, or any of `unprivileged_bpf_disabled` / `ptrace_scope` / lockdown wrong → remediate before further building.

## Out of scope

Most cybercrime.club coverage is vendor-appliance CVEs (Fortinet, Ivanti, Cisco, Splunk,
Veeam, Windows) that don't run on a Linux laptop. Those are patch-management policy, not
tooling, and are intentionally excluded here.