#!/usr/bin/env bash
# defensive-suite — FP-soak launcher (Phase 4 gate, see docs/PHASE4_FP_SOAK.md).
#
# Runs agentd in MODE=shadow + a local collector on THIS Linux host. Shadow is the
# observe pipeline + a READ-ONLY decision layer: it computes what auto-response WOULD
# do and emits realtime.autoresponse.shadow findings — it loads NO enforcement,
# arms NO actuator, and touches NO file/process. Leave it running >=14 days while you
# do your NORMAL build/CI/dev work, then `soak-report.sh` to read the candidate rate.
#
# This is the one Phase-4 gate that can't be automated — it must measure YOUR real
# workload. For a survive-reboot soak prefer the systemd path (install.sh + set
# AGENT_AUTORESPONSE_MODE=shadow in /etc/agentd/agentd.env); this script is the quick
# self-contained start (nohup; dies on reboot).
#
# Usage:  sudo ./validation/soak-start.sh [--restart]
#   env:  DSUITE_SOAK_DIR (default /var/lib/dsuite-soak)  DSUITE_SOAK_PORT (default 8787)
set -uo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SELF/.." && pwd)"
SOAK_DIR="${DSUITE_SOAK_DIR:-/var/lib/dsuite-soak}"
PORT="${DSUITE_SOAK_PORT:-8787}"
TLOG="${AGENT_TETRAGON_LOG:-/var/log/tetragon/tetragon.log}"
RESTART=0; [ "${1:-}" = "--restart" ] && RESTART=1

c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
info(){ printf '    %s\n' "$*"; }
ok(){ printf '  %s[ok]%s %s\n' "$c_g" "$c_0" "$*"; }
die(){ printf '%sABORT:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing '$1' ($2)"; }

printf '\n%s=== defensive-suite FP-soak — SHADOW mode (never acts) ===%s\n' "$c_y" "$c_0"

# --- guards ---
[ "$(uname -s)" = Linux ] || die "must run on Linux (this is $(uname -s)) — agentd tails Tetragon, which is Linux-only."
[ "$(id -u)" = 0 ] || die "run as root (reads the root-owned Tetragon export + loads the observe policy): sudo $0"
need go "build agentd/collector"; need tetra "Tetragon CLI"; need curl "health/queries"
systemctl is-active --quiet tetragon || die "tetragon is not active — install + start it first (agent/deploy/ENFORCE.md step b)."
[ -f "$TLOG" ] || die "Tetragon JSON export not found at $TLOG — enable file export (export-filename) or set AGENT_TETRAGON_LOG."
ok "Linux + root; tetragon active; export at $TLOG"

mkdir -p "$SOAK_DIR/bin" "$SOAK_DIR/collector-data"
PID_C="$SOAK_DIR/collector.pid"; PID_A="$SOAK_DIR/agentd.pid"

running(){ local p="$1"; [ -f "$p" ] && kill -0 "$(cat "$p" 2>/dev/null)" 2>/dev/null; }
if running "$PID_A" || running "$PID_C"; then
  [ "$RESTART" = 1 ] || die "a soak is already running (pids in $SOAK_DIR). Use --restart to relaunch, or soak-report.sh / soak-stop.sh."
  info "--restart: stopping the existing soak first"; "$SELF/soak-stop.sh" || true
fi

# --- build (shadow agentd + the local collector) ---
( cd "$REPO_ROOT/agent"     && CGO_ENABLED=0 go build -o "$SOAK_DIR/bin/agentd" . )    || die "agentd build failed"
( cd "$REPO_ROOT/collector" && CGO_ENABLED=0 go build -o "$SOAK_DIR/bin/collector" . ) || die "collector build failed"
ok "built agentd + collector → $SOAK_DIR/bin"

# --- observe policy (observe-only: reports, never enforces) ---
if tetra tracingpolicy list 2>/dev/null | grep -q dsuite-observe; then
  ok "observe policy already loaded"
else
  info "loading the observe policy (observe-only — includes the tcp_connect egress hook the correlator needs):"
  info "  tetra tracingpolicy add $REPO_ROOT/agent/deploy/tetragon/dsuite-observe.yaml"
  tetra tracingpolicy add "$REPO_ROOT/agent/deploy/tetragon/dsuite-observe.yaml" || die "failed to load the observe policy"
  ok "observe policy loaded"
fi

# --- collector (loopback; receives + serves the shadow findings) ---
CTOKEN="soak-$(head -c12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "$CTOKEN" > "$SOAK_DIR/collector.token"; chmod 600 "$SOAK_DIR/collector.token"
COLLECTOR_TOKEN="$CTOKEN" \
  nohup "$SOAK_DIR/bin/collector" --addr "127.0.0.1:$PORT" --data "$SOAK_DIR/collector-data" \
  >"$SOAK_DIR/collector.log" 2>&1 &
echo $! > "$PID_C"
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 || die "collector did not come up — see $SOAK_DIR/collector.log"
ok "collector up on 127.0.0.1:$PORT (dashboard: http://127.0.0.1:$PORT/)"

# --- agentd in SHADOW (decides + emits would-findings; NO --enable-response, NO actuator) ---
AGENT_AUTORESPONSE_MODE=shadow \
AGENT_TETRAGON_LOG="$TLOG" \
AGENT_COLLECTOR_URL="http://127.0.0.1:$PORT/ingest" AGENT_COLLECTOR_AUTH="Bearer $CTOKEN" \
AGENT_HOST="$(hostname)" AGENT_FLUSH_SECONDS=5 \
  nohup "$SOAK_DIR/bin/agentd" run >"$SOAK_DIR/agentd.log" 2>&1 &
echo $! > "$PID_A"
sleep 2
running "$PID_A" || die "agentd did not stay up — see $SOAK_DIR/agentd.log"
# Confirm it is actually in shadow (and refuses to ever execute): preflight prints the mode.
"$SOAK_DIR/bin/agentd" preflight 2>/dev/null | grep -iE 'autoresp|shadow|mode' | head -3 | sed 's/^/    /' || true
ok "agentd running in SHADOW (decides + emits realtime.autoresponse.shadow; cannot act)"

date -u +%Y-%m-%dT%H:%M:%SZ > "$SOAK_DIR/started_at"
printf '\n%s=== soak started ===%s\n' "$c_g" "$c_0"
info "started: $(cat "$SOAK_DIR/started_at")  (run >= 14 days, WITH your normal build/CI/dev churn)"
info "check progress:  ./validation/soak-report.sh        (or: make soak-report)"
info "stop the soak:   sudo ./validation/soak-stop.sh     (or: sudo make soak-stop)"
info "live dashboard:  http://127.0.0.1:$PORT/"
info "what to look for + the arm checklist: docs/PHASE4_FP_SOAK.md"
