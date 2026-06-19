# authwatch — DESIGN

**Threats:** Velvet Ant (PAM/OpenSSH/`authorized_keys` backdoor), QLNX (PAM modules +
`LD_PRELOAD` + `ld.so.preload`), persistence layer of every stealer.

## What it does

A scheduled integrity-and-anomaly checker for the Linux trust path:

1. Verify every `pam_*.so`, `sshd`, `ssh`, and libc against package-manager checksums
   (`rpm -V` on Fedora/RHEL; `debsums` / `dpkg -V` on Debian).
2. Flag any `.so` under `/lib*/security/` or `/usr/lib*/security/` that **no package
   owns** — the highest-fidelity PAM-backdoor signal.
3. Hash those files against a baseline captured at known-good state, stored **off-box**.
4. Audit all `authorized_keys` files against an allowlist of attributable keys.
5. Check `/etc/ld.so.preload`, shell init files, and systemd unit `Environment=`
   directives for `LD_PRELOAD` entries.
6. Detect QLNX's fake-X11-lockfile pattern (`/tmp/.X*-lock` not owned by an X server).

## Build

- **Language:** Go — single static binary that shells out to `rpm`/`dpkg` and parses output.
- **Integrity engine:** AIDE over `/etc`, `/lib*/security`, `/usr/bin`, `/usr/sbin`,
  `/root/.ssh`. The AIDE database is the trust anchor — copy it to read-only / off-host
  media. If it's writable on the box, it's worthless.
- **Live watches:** auditd rules — `-w /etc/ld.so.preload -p wa`, `-w /etc/pam.d/ -p wa`,
  `-w /etc/ssh/sshd_config -p wa`, watches on `/root/.ssh`.
- **Detections:** ship matching Sigma rules (`lnx_auditd_ld_so_preload_mod`,
  T1574.006; T1556.003 for PAM).
- **Schedule:** systemd timer; emit to journald + webhook.

## What it verifies

A diff report: "all auth binaries match distro checksums; 0 unowned PAM modules;
0 unattributable `authorized_keys`; `ld.so.preload` empty." Any non-clean line is a
high-confidence compromise indicator.

> On RHEL, `rpm -V` flags config files that legitimately change. Mask to checksum-only
> (`5`) for binaries to cut noise.

## Effort

Weekend. AIDE + auditd + wrapper gets 80% in an afternoon; the Go binary that unifies
checks and diffs against an off-host baseline is day two.