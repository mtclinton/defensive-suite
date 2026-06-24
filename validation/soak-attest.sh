#!/usr/bin/env bash
# defensive-suite — FP-soak attestation generator (Phase 4, see docs/PHASE4_FP_SOAK.md §7).
#
# Turns a FINISHED shadow soak into the machine-checked attestation artifact the arm
# gate validates (schema dsuite.soak.attestation/v1, parsed by agent/internal/respond/
# armgate.go: soakUnmetReason). It DERIVES the mechanical facts from the real soak data
# (elapsed days from the soak's started_at; the distinct would_action=quarantine
# candidate count from the collector) and REFUSES to fabricate a pass: every candidate
# counts as a blocking false positive UNLESS you explicitly attest, after review, that it
# is a confirmed TRUE positive (--true-positive N --reviewed). It then SELF-VALIDATES the
# result against the exact arm-gate rules and tells you PASS / REFUSE before you ever try
# to arm.
#
# It does NOT arm anything. Even a PASS attestation cannot fire on this build: canary/armed
# stay fatally refused until the remaining rails (console push channel, authenticated
# Tetragon export) are built and the armed path is VM-validated. See docs/PHASE4_UNGATING.md.
#
# Usage:
#   ./validation/soak-attest.sh --host-class <class> [--true-positive N --reviewed] \
#       [--out PATH] [--unexplained-fp N] [--started RFC3339] [--days N]
#   env: DSUITE_SOAK_DIR (default /var/lib/dsuite-soak)  DSUITE_SOAK_PORT (default 8787)
#        DSUITE_SOAK_FINDINGS (a file of /api/findings JSON, instead of querying the collector)
set -uo pipefail

SOAK_DIR="${DSUITE_SOAK_DIR:-/var/lib/dsuite-soak}"
PORT="${DSUITE_SOAK_PORT:-8787}"
BASE="http://127.0.0.1:$PORT"
SCHEMA="dsuite.soak.attestation/v1"
MIN_DAYS=14

HOST_CLASS=""; TRUE_POS=0; REVIEWED=0; OUT=""; UNEXPLAINED=""; STARTED=""; DAYS=""
c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
info(){ printf '    %s\n' "$*"; }
die(){ printf '%sABORT:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --host-class) HOST_CLASS="${2:-}"; shift 2;;
    --true-positive) TRUE_POS="${2:-0}"; shift 2;;
    --unexplained-fp) UNEXPLAINED="${2:-}"; shift 2;;
    --reviewed) REVIEWED=1; shift;;
    --out) OUT="${2:-}"; shift 2;;
    --started) STARTED="${2:-}"; shift 2;;
    --days) DAYS="${2:-}"; shift 2;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
    *) die "unknown arg: $1 (see --help)";;
  esac
done
command -v jq >/dev/null 2>&1 || die "needs 'jq' (apt install jq)"
[ -n "$HOST_CLASS" ] || die "--host-class is REQUIRED and must match the arming host's AGENT_AUTORESPONSE_HOST_CLASS (a soak on one class does not attest another)."
[ -n "$OUT" ] || OUT="$SOAK_DIR/soak-attestation.json"

printf '\n%s=== FP-soak attestation ===%s\n' "$c_y" "$c_0"

# ---- 1. findings (collector, or a snapshot file for offline/testing) ----
if [ -n "${DSUITE_SOAK_FINDINGS:-}" ]; then
  [ -f "$DSUITE_SOAK_FINDINGS" ] || die "DSUITE_SOAK_FINDINGS=$DSUITE_SOAK_FINDINGS not found"
  F="$(cat "$DSUITE_SOAK_FINDINGS")"; info "findings: $DSUITE_SOAK_FINDINGS (snapshot)"
else
  command -v curl >/dev/null 2>&1 || die "needs 'curl'"
  F="$(curl -fsS "$BASE/api/findings" 2>/dev/null)" || die "collector not reachable at $BASE — is the soak running? (or pass DSUITE_SOAK_FINDINGS=<snapshot.json>)"
  info "findings: live collector $BASE"
fi
printf '%s' "$F" | jq -e . >/dev/null 2>&1 || die "findings is not valid JSON"

# ---- 2. duration_days: from the soak's started_at marker (or --started/--days override) ----
if [ -n "$DAYS" ]; then
  duration="$DAYS"
else
  [ -z "$STARTED" ] && [ -f "$SOAK_DIR/started_at" ] && STARTED="$(cat "$SOAK_DIR/started_at")"
  [ -n "$STARTED" ] || die "no soak start time: $SOAK_DIR/started_at is absent — pass --started <RFC3339> or --days N."
  start_s="$(date -u -d "$STARTED" +%s 2>/dev/null)" || start_s="$(date -u -jf %Y-%m-%dT%H:%M:%SZ "$STARTED" +%s 2>/dev/null)" || die "could not parse start time '$STARTED'"
  now_s="$(date -u +%s)"
  duration="$(awk -v a="$now_s" -v b="$start_s" 'BEGIN{printf "%.2f",(a-b)/86400}')"
  info "started: $STARTED  →  duration: $duration day(s)"
fi

# ---- 3. distinct would-quarantine candidates (the metric numerator, same jq as soak-report) ----
cands="$(printf '%s' "$F" | jq -r '.[]
  | select(.check=="realtime.autoresponse.shadow")
  | select(any(.related[]?; . == "would_action=quarantine"))
  | (.related[] | select(startswith("resolved_target=")))' 2>/dev/null | sort -u | sed '/^$/d')"
n=0; [ -n "$cands" ] && n="$(printf '%s\n' "$cands" | grep -c .)"
info "distinct would-quarantine candidates observed: $n"
if [ "$n" -gt 0 ]; then
  printf '%s    each candidate is a BLOCKING false positive unless you attest it is a TRUE positive:%s\n' "$c_y" "$c_0"
  printf '%s\n' "$cands" | sed 's/^/      - /'
fi

# ---- 4. triage → distinct_would_quarantine (FPs) + unexplained_fp ----
# Default is conservative: 0 confirmed TPs ⇒ all N candidates are FPs ⇒ blocks. The
# operator may only reduce the FP tally by attesting confirmed true positives AFTER review.
if [ "$TRUE_POS" -gt 0 ] && [ "$REVIEWED" != 1 ]; then
  die "--true-positive requires --reviewed (you must attest you triaged each candidate; this script will not fabricate a pass)."
fi
[ "$TRUE_POS" -gt "$n" ] && die "--true-positive $TRUE_POS exceeds the $n observed candidate(s)."
distinct=$(( n - TRUE_POS ))          # would-quarantine FALSE positives that remain
[ -z "$UNEXPLAINED" ] && UNEXPLAINED="$distinct"   # default: every remaining FP is unexplained
[ "$UNEXPLAINED" -gt "$distinct" ] 2>/dev/null && die "--unexplained-fp $UNEXPLAINED exceeds the $distinct remaining FP(s)."

# ---- 5. emit the attestation (exact schema the validator decodes) ----
gen_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$(dirname "$OUT")"
jq -n \
  --arg schema "$SCHEMA" \
  --argjson duration "$duration" \
  --argjson distinct "$distinct" \
  --argjson unexplained "$UNEXPLAINED" \
  --arg gen "$gen_at" \
  --arg host "$HOST_CLASS" \
  '{schema:$schema, duration_days:$duration, distinct_would_quarantine:$distinct, unexplained_fp:$unexplained, generated_at:$gen, host_class:$host}' \
  > "$OUT" || die "failed to write $OUT"
printf '\n  wrote attestation: %s\n' "$OUT"
cat "$OUT" | sed 's/^/    /'

# ---- 6. self-validate against the EXACT arm-gate rules (armgate.go: soakUnmetReason) ----
printf '\n%s=== self-check (mirrors the arm gate) ===%s\n' "$c_y" "$c_0"
reason=""
awk "BEGIN{exit !($duration < $MIN_DAYS)}" && reason="duration_days $duration < $MIN_DAYS (soak too short)"
[ -z "$reason" ] && [ "$distinct" -gt 0 ] && reason="distinct_would_quarantine=$distinct > 0 (un-triaged would-quarantine false positives → do NOT arm; tune AGENT_AUTO_NEVER_QUARANTINE / AGENT_MGMT_SUBNETS and re-soak)"
[ -z "$reason" ] && [ "$UNEXPLAINED" != 0 ] && reason="unexplained_fp=$UNEXPLAINED != 0"
if [ -n "$reason" ]; then
  printf '  %s[WOULD BE REFUSED]%s %s\n' "$c_r" "$c_0" "$reason"
  printf '  This attestation does NOT meet the gate. Fix the cause and regenerate.\n'
  exit 2
fi
printf '  %s[soak gate would be SATISFIED]%s duration=%s, 0 FP candidates, fresh on use.\n' "$c_g" "$c_0" "$duration"
printf '\n  To present it (does NOT arm — canary/armed are still fatally refused in this build):\n'
printf '    export AGENT_AUTORESPONSE_SOAK_ATTESTED=%s\n' "$OUT"
printf '    export AGENT_AUTORESPONSE_HOST_CLASS=%s\n' "$HOST_CLASS"
printf '  %sReality check:%s arming still requires the unbuilt rails (console push channel,\n' "$c_y" "$c_0"
printf '  authenticated Tetragon export) + VM validation of the armed path. The file-tail\n'
printf '  Tetragon source caps trust at shadow (forgeable, §8). See docs/PHASE4_UNGATING.md.\n'
