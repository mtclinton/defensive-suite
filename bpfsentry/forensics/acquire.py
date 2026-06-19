#!/usr/bin/env python3
"""Print the out-of-band memory-acquisition commands bpfsentry's layer-3 forensics
depend on. PRIVILEGED -- DOCUMENTED, NOT RUN.

Acquiring RAM from outside the live kernel is what makes the ``prog_idr`` walk
trustworthy: a ``sys_bpf``-hooking rootkit can lie to every on-box tool, but it
cannot rewrite a memory image taken out of band. This module prints the exact,
reviewed commands for each acquisition path; it executes NONE of them. There is
deliberately no flag that runs an acquisition -- the build and CI never touch RAM,
a hypervisor, or a kernel.

Acquisition paths, by environment:

  homelab (KVM guest) -- PREFERRED, sidesteps live-kernel acquisition entirely:
      Take a hypervisor memory snapshot of the guest. The host kernel does the
      dump, so a guest-resident rootkit cannot interfere.
          virsh dump --memory-only --verbose <domain> /trust-anchor/mem.dump

  hardened bare metal (Secure Boot / module signing / lockdown) -- LiME and AVML
  often FAIL here; use LEMON (EURECOM S3, eurecom-s3/lemon, DFRWS EU 2026),
  x86_64 + ARM64, kernels >= 5.5, outputs LiME format:
          sudo ./lemon -o /trust-anchor/memory.lime
      Constraint: kernel lockdown must NOT be in confidentiality mode, or it must
      permit bpf_probe_read_kernel().

  legacy / unhardened -- LiME directly:
          sudo insmod lime.ko "path=/trust-anchor/memory.lime format=lime"

After acquisition, walk prog_idr offline with vol_ebpf.py, normalize with
oob_parser.py, and diverge against the live view with `bpfsentry diff --oob`.

Store every image on the OFF-HOST trust anchor -- the same isolated host the
monitored machines can write to but not read or rewrite (see CLAUDE.md).
"""

from __future__ import annotations

import argparse
import sys


def kvm_commands(domain: str, out: str) -> list[str]:
    return [
        f"virsh dump --memory-only --verbose {domain} {out}",
        f"# {out} is now a trusted out-of-band image; analyze it with vol_ebpf.py.",
    ]


def lemon_commands(out: str) -> list[str]:
    return [
        "# Build LEMON for the target kernel first (see eurecom-s3/lemon).",
        f"sudo ./lemon -o {out}",
        "# Requires lockdown NOT in confidentiality mode (or bpf_probe_read_kernel allowed).",
    ]


def lime_commands(out: str) -> list[str]:
    return [
        "# Build lime.ko against the running kernel headers first.",
        f'sudo insmod lime.ko "path={out} format=lime"',
        "# Fails under Secure Boot / module signing — use LEMON or a KVM snapshot instead.",
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Print out-of-band memory-acquisition commands. Runs nothing.",
    )
    parser.add_argument("method", nargs="?", default="kvm",
                        choices=("kvm", "lemon", "lime"),
                        help="acquisition path (kvm = preferred homelab snapshot)")
    parser.add_argument("--domain", default="workstation",
                        help="libvirt domain name (kvm method)")
    parser.add_argument("--out", default="/trust-anchor/memory.lime",
                        help="output image path on the off-host trust anchor")
    args = parser.parse_args(argv[1:])

    if args.method == "kvm":
        out = args.out if args.out.endswith(".dump") else "/trust-anchor/mem.dump"
        lines = kvm_commands(args.domain, out)
    elif args.method == "lemon":
        lines = lemon_commands(args.out)
    else:
        lines = lime_commands(args.out)

    sys.stdout.write("# Out-of-band memory acquisition (PRIVILEGED; review, then run by hand):\n")
    for line in lines:
        sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
