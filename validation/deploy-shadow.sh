#!/usr/bin/env bash
# defensive-suite — turnkey SHADOW deployment for a real Linux host.
#
# One command to actually USE the EDR safely: installs Tetragon + the observe
# policy, runs install.sh (the observe/detect tier — agentd + collector + the 6
# detectors as systemd units), and sets agentd to MODE=shadow. SHADOW = the full
# detect + correlate pipeline + a READ-ONLY auto-response decision layer: it
# computes what auto-response WOULD do and emits realtime.autoresponse.shadow
# findings — it loads NO enforcement, arms NO actuator, and touches NO file or
# process. It survives reboot (systemd).
#
# This is ALSO the FP-soak running passively: leave it, do your normal work, and
# `make soak-report` reads the would-quarantine candidate rate. You never have to
# arm — shadow is a legitimate permanent mode (detection value, zero containment
# risk). If you ever do want to arm, `make soak-attest` turns the accumulated data
# into the attestation the (still-gated) arm path checks.
#
# Usage:  sudo ./validation/deploy-shadow.sh [options]
#   --mgmt-subnets CIDR[,CIDR]  your LAN/Tailscale ranges (G7: never count as external egress)
#   --skip-tetragon            Tetragon is already installed + exporting JSON; just deploy dsuite
#   --tetragon-log PATH        Tetragon JSON export path (default /var/log/tetragon/tetragon.log)
#   --dry-run                  print what would happen; change nothing
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLOG="/var/log/tetragon/tetragon.log"
MGMT=""; SKIP_TG=0; DRY=0
c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
step(){ printf '\n%s== %s ==%s\n' "$c_y" "$*" "$c_0"; }
info(){ printf '    %s\n' "$*"; }
ok(){ printf '  %s[ok]%s %s\n' "$c_g" "$c_0" "$*"; }
die(){ printf '%sABORT:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
run(){ if [ "$DRY" = 1 ]; then printf '  + %s\n' "$*"; else eval "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --mgmt-subnets) MGMT="${2:-}"; shift 2;;
    --skip-tetragon) SKIP_TG=1; shift;;
    --tetragon-log) TLOG="${2:-}"; shift 2;;
    --dry-run) DRY=1; shift;;
    -h|--help) sed -n '2,26p' "$0"; exit 0;;
    *) die "unknown arg: $1 (see --help)";;
  esac
done

printf '\n%s=== defensive-suite — SHADOW deploy (detect + decide, NEVER acts) ===%s\n' "$c_y" "$c_0"

# ---------- guards ----------
[ "$(uname -s)" = Linux ] || die "must run on Linux (this is $(uname -s)) — agentd tails Tetragon (Linux-only)."
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root: sudo $0 $*"
[ -e /sys/kernel/btf/vmlinux ] || die "no kernel BTF (/sys/kernel/btf/vmlinux) — Tetragon needs CONFIG_DEBUG_INFO_BTF=y. Most LTS kernels have it; a custom kernel may not."
for t in curl tar; do command -v "$t" >/dev/null 2>&1 || die "missing '$t'"; done
case "$(uname -m)" in
  x86_64) ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) die "unsupported arch $(uname -m) (need x86_64 or arm64)";;
esac
ok "Linux $(uname -r) $(uname -m) ($ARCH); BTF present"

# ---------- 1. Tetragon + JSON export + the observe policy ----------
if [ "$SKIP_TG" = 1 ]; then
  step "Tetragon — skipped (--skip-tetragon); assuming it is active + exporting to $TLOG"
elif systemctl is-active --quiet tetragon 2>/dev/null; then
  step "Tetragon already active — ensuring JSON export to $TLOG"
else
  step "Install Tetragon ($ARCH) + enable JSON export"
  command -v jq >/dev/null 2>&1 || die "missing 'jq' (needed to resolve the latest Tetragon release)"
  TAG="$(curl -fsSL https://api.github.com/repos/cilium/tetragon/releases/latest | jq -r .tag_name)"
  [ -n "$TAG" ] && [ "$TAG" != null ] || die "could not resolve the latest Tetragon release tag"
  info "Tetragon $TAG"
  run "curl -fsSL 'https://github.com/cilium/tetragon/releases/download/${TAG}/tetragon-${TAG}-${ARCH}.tar.gz' -o /tmp/tetragon.tgz"
  run "tar -C /tmp -xzf /tmp/tetragon.tgz"
  run "/tmp/tetragon-${TAG}-${ARCH}/install.sh"
fi
if [ "$SKIP_TG" != 1 ]; then
  run "mkdir -p /etc/tetragon/tetragon.conf.d"
  run "printf '%s\n' '$TLOG' > /etc/tetragon/tetragon.conf.d/export-filename"
  # autoload the (kernel-portable, bpf_check) observe policy across reboots
  run "mkdir -p /etc/tetragon/tetragon.tp.d"
  run "install -m 0644 '$REPO_ROOT/agent/deploy/tetragon/dsuite-observe.yaml' /etc/tetragon/tetragon.tp.d/dsuite-observe.yaml"
  run "systemctl restart tetragon"
  if [ "$DRY" != 1 ]; then
    for _ in $(seq 1 40); do systemctl is-active --quiet tetragon && [ -s "$TLOG" ] && break; sleep 1; done
    systemctl is-active --quiet tetragon || die "tetragon did not become active — check: journalctl -u tetragon"
    [ -s "$TLOG" ] || info "WARN: $TLOG is empty so far (no events yet — it will fill as activity occurs)"
    command -v tetra >/dev/null 2>&1 && tetra tracingpolicy list 2>/dev/null | grep -q dsuite-observe && ok "observe policy loaded (dsuite-observe)" || info "observe policy: verify with 'tetra tracingpolicy list'"
  fi
  ok "Tetragon active; JSON export $TLOG; observe policy installed (autoloads on boot)"
fi

# ---------- 2. install dsuite (observe/detect tier — agentd + collector + detectors) ----------
step "Install defensive-suite (observe tier — does NOT install agentd-response)"
[ -x "$REPO_ROOT/install.sh" ] || die "install.sh not found/executable at $REPO_ROOT"
run "(cd '$REPO_ROOT' && ./install.sh $([ "$DRY" = 1 ] && echo --dry-run))"

# ---------- 3. flip agentd to MODE=shadow (the only new setting) ----------
step "Enable shadow mode in /etc/agentd/agentd.env"
ENVF=/etc/agentd/agentd.env
set_env(){ # idempotently set KEY=VAL in $ENVF
  local k="$1" v="$2"
  if [ "$DRY" = 1 ]; then printf '  + set %s=%s in %s\n' "$k" "$v" "$ENVF"; return; fi
  mkdir -p "$(dirname "$ENVF")"; touch "$ENVF"
  if grep -qE "^${k}=" "$ENVF"; then
    sed -i "s|^${k}=.*|${k}=${v}|" "$ENVF"
  else
    printf '%s=%s\n' "$k" "$v" >> "$ENVF"
  fi
}
set_env AGENT_AUTORESPONSE_MODE shadow
set_env AGENT_TETRAGON_LOG "$TLOG"
[ -n "$MGMT" ] && set_env AGENT_MGMT_SUBNETS "$MGMT"
ok "agentd.env set: AGENT_AUTORESPONSE_MODE=shadow$([ -n "$MGMT" ] && echo ", AGENT_MGMT_SUBNETS=$MGMT")"
run "systemctl restart agentd 2>/dev/null || true"

# ---------- 4. verify + report ----------
if [ "$DRY" != 1 ]; then
  step "Verify"
  systemctl is-active --quiet agentd 2>/dev/null && ok "agentd active" || info "agentd: check 'systemctl status agentd'"
  PORT="${DSUITE_PORT:-8787}"
  curl -fsS "http://127.0.0.1:$PORT/api/summary" >/dev/null 2>&1 && ok "collector responding on :$PORT" || info "collector: check 'systemctl status collector' (port may differ)"
  "$REPO_ROOT"/*/bin 2>/dev/null; "$REPO_ROOT/bin/agentd" preflight 2>/dev/null | grep -iE 'autoresp|shadow|mode' | head -3 | sed 's/^/    /' || true
fi

printf '\n%s=== SHADOW deploy complete — it detects + decides, never acts ===%s\n' "$c_g" "$c_0"
info "Dashboard:   http://127.0.0.1:${DSUITE_PORT:-8787}/   (findings + the C2 correlation + what it WOULD do)"
info "Soak report: (cd $REPO_ROOT && make soak-report)     # would-quarantine candidate rate, the arming metric"
info "Mode:        AGENT_AUTORESPONSE_MODE=shadow in $ENVF  # canary/armed stay fatally refused in this build"
printf '  %sThis is the FP-soak running passively.%s Leave it, do your normal work. Shadow never\n' "$c_y" "$c_0"
info "acts — to ever ARM you would need the deferred rails + a passed soak (make soak-attest) + VM"
info "validation of the armed path. See docs/PHASE4_FP_SOAK.md and docs/PHASE4_UNGATING.md."
