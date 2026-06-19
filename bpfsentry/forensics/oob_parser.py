#!/usr/bin/env python3
"""Normalize an out-of-band eBPF enumeration into the JSON shape `bpfsentry diff
--oob` ingests.

The thesis of bpfsentry is that at least one detection path must not run on the
(possibly compromised) live kernel. The out-of-band path walks the kernel's
``prog_idr`` structure directly in a memory image -- bypassing the hooked
``sys_bpf`` syscall entirely -- using Volatility 3 (the ``linux.ebpf`` /
``ebpf_programs`` plugin). That walk emits Volatility's own JSON; this module
translates it into the small, stable interchange shape the Go side already
parses (``internal/enumerate.Inventory``), so the same `bpfsentry diff` that
compares the live ``bpftool`` view against the early-boot allowlist can ALSO
ingest the offline view and report any program present out-of-band but missing
live -- a hidden implant.

Interchange shape (matches internal/enumerate.Inventory JSON tags):

    {
      "source": "oob",
      "programs": [
        {"id": 99, "name": "", "type": "kprobe", "tag": "deadbeefcafef00d",
         "attach_type": "", "attach_to": "__x64_sys_bpf",
         "helpers": ["bpf_probe_write_user"], "pinned": [], "gpl_compatible": false}
      ],
      "maps": [],
      "links": []
    }

This module runs NOTHING privileged. It is pure data transformation over JSON
that Volatility produced earlier (see vol_ebpf.py for how that JSON is obtained,
and note those commands are privileged and documented-not-run). It is safe to run
and unit-friendly:

    python3 oob_parser.py volatility-output.json > oob-prog-idr.json
    # then, on the host under investigation:
    #   bpfsentry diff --config /etc/bpfsentry/config.json --oob oob-prog-idr.json
"""

from __future__ import annotations

import json
import sys
from typing import Any


# Volatility's linux.ebpf / ebpf_programs plugins have used a few different field
# names across versions and forks (mainline volatility3 vs. FKIE-CAD BPFVol3 vs.
# Asaf Eitani's ebpf_programs). We accept any of them and normalize.
_NAME_KEYS = ("Name", "name", "prog_name")
_TYPE_KEYS = ("Type", "type", "prog_type", "ProgType")
_TAG_KEYS = ("Tag", "tag", "prog_tag")
_ID_KEYS = ("ID", "Id", "id", "prog_id")
_ATTACH_KEYS = ("Attach", "attach_to", "AttachTo", "attached_func", "symbol", "Func")
_ATTACH_TYPE_KEYS = ("AttachType", "attach_type", "expected_attach_type")
_HELPER_KEYS = ("Helpers", "helpers", "used_helpers", "UsedHelpers")


def _first(record: dict[str, Any], keys: tuple[str, ...], default: Any) -> Any:
    """Return the first present, non-null value among keys, else default."""
    for k in keys:
        if k in record and record[k] is not None:
            return record[k]
    return default


def _as_int(value: Any) -> int:
    """Coerce an id to int; tolerate strings and hex like '0x7'."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(text)
        except ValueError:
            return 0
    return 0


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _as_helpers(value: Any) -> list[str]:
    """Normalize a helpers field that may be a list, a comma string, or None."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v)]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def normalize_program(record: dict[str, Any]) -> dict[str, Any]:
    """Map one Volatility program record to the bpfsentry interchange shape."""
    return {
        "id": _as_int(_first(record, _ID_KEYS, 0)),
        "name": _as_str(_first(record, _NAME_KEYS, "")),
        "type": _as_str(_first(record, _TYPE_KEYS, "")),
        "tag": _as_str(_first(record, _TAG_KEYS, "")),
        "attach_type": _as_str(_first(record, _ATTACH_TYPE_KEYS, "")),
        "attach_to": _as_str(_first(record, _ATTACH_KEYS, "")),
        "helpers": _as_helpers(_first(record, _HELPER_KEYS, None)),
        "pinned": [],
        "gpl_compatible": bool(_first(record, ("GPL", "gpl_compatible"), False)),
    }


def _records(vol_output: Any) -> list[dict[str, Any]]:
    """Extract the program records from Volatility output.

    Volatility 3 renders JSON either as a bare list of row dicts, or as an object
    with a top-level key (e.g. {"rows": [...]} or a plugin-named key). Accept both.
    """
    if isinstance(vol_output, list):
        return [r for r in vol_output if isinstance(r, dict)]
    if isinstance(vol_output, dict):
        for key in ("rows", "programs", "data", "ebpf_programs"):
            value = vol_output.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        # A dict of {index: row} also occurs.
        rows = [v for v in vol_output.values() if isinstance(v, dict)]
        if rows:
            return rows
    return []


def to_inventory(vol_output: Any) -> dict[str, Any]:
    """Build the full interchange inventory from parsed Volatility output."""
    programs = [normalize_program(r) for r in _records(vol_output)]
    programs.sort(key=lambda p: p["id"])
    return {
        "source": "oob",
        "programs": programs,
        "maps": [],
        "links": [],
    }


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] in ("-h", "--help"):
        sys.stderr.write(__doc__ or "")
        return 0
    raw = sys.stdin.read() if len(argv) < 2 else open(argv[1], encoding="utf-8").read()
    try:
        vol_output = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"oob_parser: input is not valid JSON: {exc}\n")
        return 1
    inventory = to_inventory(vol_output)
    json.dump(inventory, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
