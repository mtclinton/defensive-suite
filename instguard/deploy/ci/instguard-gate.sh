#!/usr/bin/env sh
# instguard CI / pre-commit gate.
#
# Drop this into a CI step or a git pre-commit/pre-push hook to BLOCK an install
# of a poisoned dependency before it executes. instguard `check` exits 1 on any
# BLOCK verdict (lockfile drift, an OSV MAL- advisory on a pinned version, an
# obfuscated AUR npm hook, a critical install hook), so a non-zero exit fails the
# pipeline. It is a *static* gate: it never runs `npm install` or any package
# script.
#
# The recommended install flow (documented, NOT run by this script):
#
#   npm ci --ignore-scripts        # install with all lifecycle scripts disabled
#   instguard check --project .    # vet the now-on-disk tree (this gate)
#   npm audit signatures           # require SLSA provenance / publish attestations
#   # only then, if you must, a second pass that enables vetted scripts:
#   npm rebuild                    # runs install scripts for packages you trust
#
# Usage:
#   sh deploy/ci/instguard-gate.sh [PROJECT_DIR]
#
# Offline CI (no egress to OSV.dev) still runs every static check:
#   INSTGUARD_OFFLINE_OSV=1 sh deploy/ci/instguard-gate.sh
set -eu

PROJECT_DIR="${1:-.}"

# Resolve the binary: prefer one on PATH, fall back to a repo-local build.
if command -v instguard >/dev/null 2>&1; then
  INSTGUARD=instguard
elif [ -x ./bin/instguard ]; then
  INSTGUARD=./bin/instguard
else
  echo "instguard: binary not found (build with 'make static' or install it)" >&2
  exit 1
fi

echo "instguard: vetting ${PROJECT_DIR} (BLOCK fails the build) ..."

# exit 0 clean/SAFE · 1 a BLOCK verdict (gate) · 2 a medium REVIEW finding.
# Treat exit 2 (REVIEW) as a soft warning here; only a BLOCK fails the pipeline.
set +e
"$INSTGUARD" check --project "$PROJECT_DIR"
rc=$?
set -e

case "$rc" in
  0) echo "instguard: SAFE — no blocking supply-chain findings." ;;
  2) echo "instguard: REVIEW — medium findings present; not blocking the build." ;;
  1) echo "instguard: BLOCK — refusing the install. Review the verdicts above." >&2; exit 1 ;;
  *) echo "instguard: operational error (exit $rc)." >&2; exit "$rc" ;;
esac
