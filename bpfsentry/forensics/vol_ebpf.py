#!/usr/bin/env python3
"""Drive a Volatility 3 ``prog_idr`` walk over a Linux memory image to enumerate
eBPF programs OUT OF BAND -- bypassing the live, possibly-hooked ``sys_bpf``.

This is layer 3 of bpfsentry's design: the part that can't be lied to. Volatility
walks the kernel's ``prog_idr`` structure directly in a memory image, so a
rootkit that hooks the ``bpf()`` syscall to hide its programs from ``bpftool``
cannot hide them here. The output is then normalized by ``oob_parser.py`` into
the shape ``bpfsentry diff --oob`` ingests, and the divergence between the live
``bpftool`` view and this offline view is itself proof of a kernel implant.

PRIVILEGED -- DOCUMENTED, NOT RUN.
=================================
Running Volatility against a memory image is an offline analysis step, but it
requires a memory image (acquired with elevated privilege, see ``acquire.py``)
and a kernel symbol table (ISF/BTF). This script DOES NOT execute Volatility by
default; it PRINTS the exact command(s) you would run, so the build and CI never
touch a real image. Pass ``--print`` (the default) to see the command; there is
intentionally no flag that makes this module shell out.

Plugins, in order of preference:
  * mainline volatility3 ``linux.ebpf``                  (productized)
  * Asaf Eitani's ``ebpf_programs``                      (the original heuristic)
  * FKIE-CAD ``BPFVol3``                                 (fork with extra plugins)

Heuristic origin: Ben-Gurion University, *Detecting eBPF Rootkits Using
Virtualization and Memory Forensics* (SciTePress 2024). Flag suspicious helpers:
``bpf_override_return``, ``bpf_probe_write_user``, ``bpf_send_signal``.

Typical (privileged, offline) workflow -- shown, not run here:

    # 1. Acquire RAM out of band (see acquire.py for the privileged commands).
    # 2. Build/obtain the ISF symbol table for the target kernel (BTF-derived).
    # 3. Walk prog_idr and render JSON:
    vol -r json -f memory.lime linux.ebpf > vol-ebpf.json
    # 4. Normalize to the bpfsentry interchange shape:
    python3 oob_parser.py vol-ebpf.json > oob-prog-idr.json
    # 5. Diverge against the live view on the suspect host:
    bpfsentry diff --config /etc/bpfsentry/config.json --oob oob-prog-idr.json
"""

from __future__ import annotations

import argparse
import shlex
import sys


# Candidate Volatility plugin names, most-productized first.
PLUGINS = ("linux.ebpf", "linux.ebpf_programs", "ebpf_programs")

# Helpers whose presence in a program is high-signal per the design / BGU paper.
SUSPICIOUS_HELPERS = (
    "bpf_override_return",
    "bpf_probe_write_user",
    "bpf_send_signal",
    "bpf_send_signal_thread",
)


def build_command(image: str, plugin: str, isf: str | None, vol_bin: str) -> list[str]:
    """Build the argv for a Volatility 3 prog_idr walk rendering JSON.

    The returned list is for DISPLAY and for an operator to run by hand; this
    module never executes it.
    """
    cmd = [vol_bin, "-r", "json", "-f", image]
    if isf:
        # Point Volatility at a specific ISF (kernel symbol table) directory.
        cmd += ["-s", isf]
    cmd.append(plugin)
    return cmd


def acquisition_note() -> str:
    return (
        "Acquire the memory image OUT OF BAND first (see acquire.py). Under Secure\n"
        "Boot / module signing / kernel lockdown, LiME and AVML may fail; use LEMON\n"
        "(eurecom-s3/lemon) or, for a KVM guest, a hypervisor snapshot via\n"
        "`virsh dump --memory-only`. All of those are privileged and are documented,\n"
        "not run, by this toolkit."
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Print the Volatility 3 prog_idr-walk command for an eBPF "
        "out-of-band enumeration. Does not run Volatility.",
    )
    parser.add_argument("image", nargs="?", default="memory.lime",
                        help="path to the acquired memory image (LiME/AVML/raw)")
    parser.add_argument("--plugin", choices=PLUGINS, default=PLUGINS[0],
                        help="Volatility eBPF plugin to use")
    parser.add_argument("--isf", default=None,
                        help="path to the ISF symbol-table directory for the target kernel")
    parser.add_argument("--vol-bin", default="vol",
                        help="Volatility 3 entrypoint (vol / vol.py / volatility3)")
    parser.add_argument("--print", dest="do_print", action="store_true", default=True,
                        help="print the command (default; this tool never executes it)")
    args = parser.parse_args(argv[1:])

    cmd = build_command(args.image, args.plugin, args.isf, args.vol_bin)
    sys.stdout.write("# Out-of-band eBPF enumeration (privileged; run by hand, reviewed):\n")
    sys.stdout.write("# " + acquisition_note().replace("\n", "\n# ") + "\n")
    sys.stdout.write(shlex.join(cmd) + " > vol-ebpf.json\n")
    sys.stdout.write("python3 oob_parser.py vol-ebpf.json > oob-prog-idr.json\n")
    sys.stdout.write(
        "# Then flag programs whose used-helpers include any of: "
        + ", ".join(SUSPICIOUS_HELPERS)
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
