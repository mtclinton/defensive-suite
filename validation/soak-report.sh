#!/usr/bin/env bash
# defensive-suite — FP-soak report (see docs/PHASE4_FP_SOAK.md §5-§7).
# Reads the shadow findings the running soak accumulated in the collector and prints
# the arming-gate metric: distinct (resolved-binary, would_action=quarantine)
# auto-action CANDIDATES, the per-candidate triage list, the throttle count, and the
# elapsed window. It does NOT judge TP/FP — YOU triage each candidate (§6).
#
# Usage:  ./validation/soak-report.sh        (no root needed — just queries the collector)
#   env:  DSUITE_SOAK_DIR (default /var/lib/dsuite-soak)  DSUITE_SOAK_PORT (default 8787)
set -uo pipefail

SOAK_DIR="${DSUITE_SOAK_DIR:-/var/lib/dsuite-soak}"
PORT="${DSUITE_SOAK_PORT:-8787}"
BASE="http://127.0.0.1:$PORT"
c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
die(){ printf '%sABORT:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || die "needs 'jq' (apt install jq)"
command -v curl >/dev/null 2>&1 || die "needs 'curl'"

F="$(curl -fsS "$BASE/api/findings" 2>/dev/null)" || die "collector not reachable at $BASE — is the soak running? (soak-start.sh)"

printf '\n%s=== FP-soak report ===%s\n' "$c_y" "$c_0"
if [ -f "$SOAK_DIR/started_at" ]; then
  start="$(cat "$SOAK_DIR/started_at")"
  days=$(( ( $(date -u +%s) - $(date -u -d "$start" +%s 2>/dev/null || echo "$(date -u +%s)") ) / 86400 ))
  printf '  started %s  (~%d day(s) elapsed; soak target >= 14d with real build/CI/dev churn)\n' "$start" "$days"
fi

# The metric numerator: distinct resolved targets among would_action=quarantine shadow findings.
cands="$(printf '%s' "$F" | jq -r '.[]
  | select(.check=="realtime.autoresponse.shadow")
  | select(any(.related[]?; . == "would_action=quarantine"))
  | (.related[] | select(startswith("resolved_target=")))' 2>/dev/null | sort -u)"
n=$(printf '%s' "$cands" | grep -c . || true)
shadow_total=$(printf '%s' "$F" | jq '[.[]|select(.check=="realtime.autoresponse.shadow")]|length' 2>/dev/null || echo 0)
throttled=$(printf '%s' "$F" | jq '[.[]|select(.check=="realtime.autoresponse.throttled")]|length' 2>/dev/null || echo 0)

printf '\n  %sdistinct would-QUARANTINE candidates: %d%s   (the number that gates arming)\n' "$c_y" "$n" "$c_0"
printf '  shadow findings total: %s   |   throttle events: %s   (a flood/abuse signal — should be ~0)\n' "$shadow_total" "$throttled"

if [ "$n" -gt 0 ]; then
  printf '\n  triage EACH of these (TP = real C2/exfil → good; FP of a legit binary → blocks arming, §6):\n'
  printf '  %-22s %-26s %s\n' "WOULD" "DST" "RESOLVED TARGET"
  printf '%s' "$F" | jq -r '.[]
    | select(.check=="realtime.autoresponse.shadow")
    | select(any(.related[]?; . == "would_action=quarantine"))
    | [(.title), ((.related[]|select(startswith("dst=")))//"dst=?"), ((.related[]|select(startswith("resolved_target=")))//"resolved_target=?")] | @tsv' \
    | sort -u | awk -F'\t' '{printf "  %-22.22s %-26.26s %s\n", $1, $2, $3}'
fi

printf '\n%s=== verdict ===%s\n' "$c_y" "$c_0"
if [ "$n" -eq 0 ]; then
  printf '  %s[clean so far]%s 0 would-quarantine candidates. Keep soaking to >=14d incl real build/CI churn.\n' "$c_g" "$c_0"
else
  printf '  %s[triage needed]%s %d candidate(s). Target: ~<=1 / 30 days AND every one a TRUE positive.\n' "$c_r" "$c_0" "$n"
  printf '  Any FP of a legitimate binary => do NOT arm; tune AGENT_MGMT_SUBNETS / AGENT_AUTO_NEVER_QUARANTINE\n'
  printf '  / AGENT_AUTO_PROTECTED_PATHS and re-soak. See the arm checklist in docs/PHASE4_FP_SOAK.md §7.\n'
fi
