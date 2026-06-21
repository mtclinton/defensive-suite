#!/usr/bin/env bash
# defensive-suite — stop the FP-soak (see soak-start.sh / docs/PHASE4_FP_SOAK.md).
# Stops the shadow agentd + the local collector. Leaves the collector DATA (so a
# final soak-report.sh still works) and, by default, leaves the observe policy
# loaded (it is harmless + useful). Use --unload to also remove the observe policy.
#
# Usage:  sudo ./validation/soak-stop.sh [--unload]
set -uo pipefail

SOAK_DIR="${DSUITE_SOAK_DIR:-/var/lib/dsuite-soak}"
UNLOAD=0; [ "${1:-}" = "--unload" ] && UNLOAD=1
c_g=$'\e[32m'; c_y=$'\e[33m'; c_0=$'\e[0m'
info(){ printf '    %s\n' "$*"; }
ok(){ printf '  %s[ok]%s %s\n' "$c_g" "$c_0" "$*"; }

printf '\n%s=== stopping the FP-soak ===%s\n' "$c_y" "$c_0"
stop(){ local p="$SOAK_DIR/$1.pid"; if [ -f "$p" ]; then kill "$(cat "$p" 2>/dev/null)" 2>/dev/null && ok "stopped $1 (pid $(cat "$p"))"; rm -f "$p"; else info "$1 not running"; fi; }
stop agentd
stop collector

if [ "$UNLOAD" = 1 ]; then
  command -v tetra >/dev/null 2>&1 && tetra tracingpolicy delete dsuite-observe 2>/dev/null && ok "unloaded the observe policy"
else
  info "left the observe policy loaded (--unload to remove it)."
fi
info "collector data kept at $SOAK_DIR/collector-data — a final ./validation/soak-report.sh still works."
