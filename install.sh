#!/usr/bin/env bash
#
# install.sh — scripted, review-first, idempotent installer for the
# defensive-suite EDR DETECTION / OBSERVE tier.
#
#   >>> READ THIS BEFORE YOU RUN IT. It is SHIPPED for an operator to run; the
#       project's build and CI never run a real install. <<<
#
# WHAT IT DOES (the safe, observe-only tier):
#   - Builds all 8 Go modules as static binaries (CGO_ENABLED=0, version injected
#     via -ldflags "-X main.version=$VERSION") and installs them to $PREFIX/bin.
#   - Installs the collector service, the 6 detector .service+.timer pairs, and
#     agentd.service (OBSERVE), and enables the timers + collector + agentd.
#   - Creates /etc/{collector,agentd} (0750) + /var/lib/{collector,agentd} (0750).
#   - ONE-PASS TOKEN FAN-OUT: generates ONE bearer token (openssl rand -hex 32)
#     and writes it to the collector AND every reporter's env so they all share
#     one consistent token. Never overwrites an existing token on re-run.
#
# WHAT IT DELIBERATELY DOES NOT DO (armed response / enforce — manual by design):
#   - It does NOT install or enable agentd-response.service.
#   - It does NOT load any Tetragon enforce policy.
#   These remain the documented manual steps; see the pointers it prints and
#   agent/deploy/{ENFORCE.md,RESPONSE.md}.
#
# FLAGS:
#   --prefix DIR     install binaries under DIR/bin            (default /usr/local)
#   --destdir DIR    stage the whole layout under DIR (DESTDIR-style) WITHOUT
#                    touching the real system or needing systemd — for packaging
#                    and testing. Implies no systemctl calls.
#   --version V      version string to inject (default: git describe / "dev")
#   --dry-run        print every action, change nothing
#   --uninstall      stop/disable units, remove binaries + units; KEEP data
#   --purge          with --uninstall, also remove /etc + /var/lib data
#   -h, --help       this help
#
# A real (non --dry-run / non --destdir) install requires root.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants: the suite's module → binary → build-path map, and the unit lists.
# ---------------------------------------------------------------------------

# Repo root = the directory this script lives in.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Module spec: "module_dir:binary_name:build_pkg". build_pkg is relative to the
# module dir (most are ".", bpfsentry builds from ./cmd/bpfsentry).
MODULES=(
  "authwatch:authwatch:."
  "credsentinel:credsentinel:."
  "instguard:instguard:."
  "posturescan:posturescan:."
  "egresswatch:egresswatch:."
  "bpfsentry:bpfsentry:./cmd/bpfsentry"
  "collector:collector:."
  "agent:agentd:."
)

# The 6 detector timers (service+timer pairs) that get enabled. bpfsentry has a
# diff.timer plus a oneshot baseline.service (run early at boot, no timer).
DETECTOR_UNITS=(
  "authwatch:authwatch.service authwatch.timer"
  "credsentinel:credsentinel-scan.service credsentinel-scan.timer"
  "instguard:instguard.service instguard.timer"
  "posturescan:posturescan.service posturescan.timer"
  "egresswatch:egresswatch.service egresswatch.timer"
  "bpfsentry:bpfsentry-baseline.service bpfsentry-diff.service bpfsentry-diff.timer"
)
# Timers that get `systemctl enable --now`.
DETECTOR_TIMERS=(
  authwatch.timer
  credsentinel-scan.timer
  instguard.timer
  posturescan.timer
  egresswatch.timer
  bpfsentry-diff.timer
)
# bpfsentry-baseline.service is enabled (WantedBy=sysinit.target) so the early-boot
# allowlist is captured on the next boot; it is NOT started now.
BASELINE_UNIT="bpfsentry-baseline.service"

# Per-detector reporter env: "module:env_filename:auth_var:url_var:ingest_path".
# Each detector reads <TOOL>_WEBHOOK_AUTH / <TOOL>_WEBHOOK_URL; agentd reads
# AGENT_COLLECTOR_AUTH / AGENT_COLLECTOR_URL. All Authorization values are the
# SAME bearer token fanned out from the collector token.
REPORTERS=(
  "authwatch:authwatch.env:AUTHWATCH_WEBHOOK_AUTH:AUTHWATCH_WEBHOOK_URL:/ingest"
  "credsentinel:credsentinel.env:CREDSENTINEL_WEBHOOK_AUTH:CREDSENTINEL_WEBHOOK_URL:/ingest"
  "instguard:instguard.env:INSTGUARD_WEBHOOK_AUTH:INSTGUARD_WEBHOOK_URL:/ingest"
  "posturescan:posturescan.env:POSTURESCAN_WEBHOOK_AUTH:POSTURESCAN_WEBHOOK_URL:/ingest"
  "egresswatch:egresswatch.env:EGRESSWATCH_WEBHOOK_AUTH:EGRESSWATCH_WEBHOOK_URL:/ingest"
  "bpfsentry:bpfsentry.env:BPFSENTRY_WEBHOOK_AUTH:BPFSENTRY_WEBHOOK_URL:/ingest"
)

# Collector bind address used in the fanned-out reporter URLs.
COLLECTOR_ADDR_DEFAULT="127.0.0.1:8787"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
PREFIX="/usr/local"
DESTDIR=""
VERSION=""
DRY_RUN=0
DO_UNINSTALL=0
DO_PURGE=0

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; s/^#$//' | sed '/^set -euo/d'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)    PREFIX="${2:?--prefix needs a DIR}"; shift 2 ;;
    --prefix=*)  PREFIX="${1#*=}"; shift ;;
    --destdir)   DESTDIR="${2:?--destdir needs a DIR}"; shift 2 ;;
    --destdir=*) DESTDIR="${1#*=}"; shift ;;
    --version)   VERSION="${2:?--version needs a value}"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    --purge)     DO_PURGE=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "install.sh: unknown argument: $1" >&2; echo "try: install.sh --help" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Are we staging into a DESTDIR (packaging/testing) rather than a real install?
staging() { [ -n "$DESTDIR" ]; }

# Should we touch systemd? Only on a real install (no destdir, not dry-run).
use_systemctl() { ! staging && [ "$DRY_RUN" -eq 0 ]; }

# Resolve a logical absolute path to its on-disk location, prefixed by DESTDIR
# when staging. e.g. dest /usr/local/bin -> $DESTDIR/usr/local/bin.
dest() { printf '%s%s' "$DESTDIR" "$1"; }

log()  { printf '%s\n' "$*"; }
step() { printf '\n== %s ==\n' "$*"; }

# run CMD... — execute, or just print under --dry-run.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRY-RUN: %s\n' "$*"
  else
    "$@"
  fi
}

# mkdirp MODE DIR — create a dir (under DESTDIR when staging) with a mode.
mkdirp() {
  local mode="$1" d; shift
  for d in "$@"; do
    run mkdir -p "$(dest "$d")"
    run chmod "$mode" "$(dest "$d")"
  done
}

# install_file MODE SRC DEST — install a file (under DESTDIR when staging).
install_file() {
  local mode="$1" src="$2" dst; dst="$(dest "$3")"
  run mkdir -p "$(dirname "$dst")"
  run cp -f "$src" "$dst"
  run chmod "$mode" "$dst"
}

# A file existence test that respects DESTDIR and dry-run (in dry-run we can't
# know, so we treat the staged path).
exists() { [ -e "$(dest "$1")" ]; }

require_root_if_real() {
  if ! staging && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: a real install needs root. Re-run with sudo, or use" >&2
    echo "            --dry-run to preview or --destdir DIR to stage for packaging." >&2
    exit 1
  fi
}

# Where systemd units live. Under DESTDIR we still use the canonical path so the
# staged tree mirrors a real install.
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR=""   # set after PREFIX is final
SHARE_DIR="" # docs / deploy trees

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
resolve_version() {
  if [ -n "$VERSION" ]; then return; fi
  if command -v git >/dev/null 2>&1 && git -C "$SCRIPT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    VERSION="$(git -C "$SCRIPT_DIR" describe --tags --always --dirty 2>/dev/null || true)"
  fi
  [ -n "$VERSION" ] || VERSION="dev"
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build_all() {
  step "Build 8 Go modules as static binaries (version=$VERSION)"
  if ! command -v go >/dev/null 2>&1; then
    echo "install.sh: 'go' not found on PATH; cannot build." >&2
    exit 1
  fi
  local ldflags="-s -w -X main.version=$VERSION"
  mkdirp 0755 "$PREFIX/bin"
  local spec mod bin pkg out
  for spec in "${MODULES[@]}"; do
    IFS=':' read -r mod bin pkg <<<"$spec"
    out="$(dest "$BIN_DIR/$bin")"
    log ">> $mod -> $bin"
    if [ "$DRY_RUN" -eq 1 ]; then
      printf 'DRY-RUN: (cd %s && CGO_ENABLED=0 go build -trimpath -ldflags %q -o %s %s)\n' \
        "$SCRIPT_DIR/$mod" "$ldflags" "$out" "$pkg"
      continue
    fi
    ( cd "$SCRIPT_DIR/$mod" && CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$out" "$pkg" )
    chmod 0755 "$out"
  done
}

# ---------------------------------------------------------------------------
# Units + config + token fan-out
# ---------------------------------------------------------------------------

# generate_token — one bearer token for the whole fan-out.
generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    # Fallback that needs no openssl.
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# read_token_from_collector_env — extract an existing COLLECTOR_TOKEN if present
# (idempotent re-runs reuse it). Echoes the token or nothing.
read_token_from_collector_env() {
  local f; f="$(dest /etc/collector/collector.env)"
  [ -f "$f" ] || return 0
  sed -n 's/^COLLECTOR_TOKEN=\(..*\)$/\1/p' "$f" | head -n1
}

# ensure_token — return the shared token, generating once and never overwriting.
# Stores the chosen value in the global SHARED_TOKEN.
SHARED_TOKEN=""
ensure_token() {
  local existing
  existing="$(read_token_from_collector_env || true)"
  if [ -n "$existing" ] && [ "$existing" != "replace-with-a-long-random-token" ]; then
    SHARED_TOKEN="$existing"
    log "Reusing existing collector token (idempotent; not overwritten)."
    return
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    SHARED_TOKEN="<one-token-generated-here>"
    log "DRY-RUN: would generate one bearer token (openssl rand -hex 32) and fan it out."
    return
  fi
  SHARED_TOKEN="$(generate_token)"
  log "Generated one new bearer token; fanning it out to collector + all reporters."
}

# write_env_kv FILE MODE KEY VALUE [KEY VALUE ...] — write a 0600-ish env file,
# but NEVER overwrite an existing token line (idempotent). Existing files are
# left in place; we only create them if absent.
write_collector_env() {
  local f; f="$(dest /etc/collector/collector.env)"
  if exists /etc/collector/collector.env; then
    log "Keeping existing /etc/collector/collector.env (token preserved)."
    return
  fi
  log "Writing /etc/collector/collector.env (0600)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRY-RUN: write %s with COLLECTOR_TOKEN=%s and COLLECTOR_ADDR=%s\n' \
      "$f" "$SHARED_TOKEN" "$COLLECTOR_ADDR_DEFAULT"
    return
  fi
  mkdir -p "$(dirname "$f")"
  cat >"$f" <<EOF
# /etc/collector/collector.env  — generated by install.sh
# Bearer token every reporter presents as: Authorization: Bearer <token>
COLLECTOR_TOKEN=$SHARED_TOKEN

# Bind loopback by default. To accept reports from other hosts, set a PRIVATE
# (e.g. Tailscale) address here and restart the collector — never 0.0.0.0.
# COLLECTOR_ADDR=$COLLECTOR_ADDR_DEFAULT
EOF
  chmod 0600 "$f"
}

write_reporter_env() {
  local mod="$1" envfile="$2" authvar="$3" urlvar="$4" path="$5"
  local f; f="$(dest "/etc/$mod/$envfile")"
  if exists "/etc/$mod/$envfile"; then
    log "Keeping existing /etc/$mod/$envfile (token preserved)."
    return
  fi
  log "Writing /etc/$mod/$envfile (0600) — $authvar = same shared token"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRY-RUN: write %s with %s=Bearer %s and %s=http://%s%s\n' \
      "$f" "$authvar" "$SHARED_TOKEN" "$urlvar" "$COLLECTOR_ADDR_DEFAULT" "$path"
    return
  fi
  mkdir -p "$(dirname "$f")"
  cat >"$f" <<EOF
# /etc/$mod/$envfile — generated by install.sh (mode 0600, secrets only)
# Authorization header for the collector POST — SAME token as COLLECTOR_TOKEN.
$authvar=Bearer $SHARED_TOKEN
# Local collector /ingest endpoint.
$urlvar=http://$COLLECTOR_ADDR_DEFAULT$path
EOF
  chmod 0600 "$f"
}

write_agentd_env() {
  local f; f="$(dest /etc/agentd/agentd.env)"
  if exists /etc/agentd/agentd.env; then
    log "Keeping existing /etc/agentd/agentd.env (token preserved)."
    return
  fi
  log "Writing /etc/agentd/agentd.env (0600) — AGENT_COLLECTOR_AUTH = same shared token"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRY-RUN: write %s with AGENT_COLLECTOR_AUTH=Bearer %s and AGENT_COLLECTOR_URL=http://%s/ingest\n' \
      "$f" "$SHARED_TOKEN" "$COLLECTOR_ADDR_DEFAULT"
    return
  fi
  mkdir -p "$(dirname "$f")"
  cat >"$f" <<EOF
# /etc/agentd/agentd.env — generated by install.sh (mode 0600).
# OBSERVE mode. Real-time Tetragon→collector pipeline; no response.
# Authorization header for the collector POST — SAME token as COLLECTOR_TOKEN.
AGENT_COLLECTOR_AUTH=Bearer $SHARED_TOKEN
AGENT_COLLECTOR_URL=http://$COLLECTOR_ADDR_DEFAULT/ingest

# --- ARMED RESPONSE (M3) IS NOT CONFIGURED HERE BY DESIGN. ---
# To arm manual response, see agent/deploy/RESPONSE.md and
# agent/deploy/agentd-response.env.example. Do NOT enable on this host casually.
EOF
  chmod 0600 "$f"
}

install_units() {
  step "Install systemd units (collector + 6 detectors + agentd OBSERVE)"
  # collector
  install_file 0644 "$SCRIPT_DIR/collector/deploy/systemd/collector.service" "$SYSTEMD_DIR/collector.service"
  # detectors
  local spec mod units u
  for spec in "${DETECTOR_UNITS[@]}"; do
    IFS=':' read -r mod units <<<"$spec"
    for u in $units; do
      install_file 0644 "$SCRIPT_DIR/$mod/deploy/systemd/$u" "$SYSTEMD_DIR/$u"
    done
  done
  # agentd OBSERVE only (NOT agentd-response.service)
  install_file 0644 "$SCRIPT_DIR/agent/deploy/systemd/agentd.service" "$SYSTEMD_DIR/agentd.service"
  log "NOTE: agentd-response.service intentionally NOT installed (manual arming)."
}

install_docs() {
  step "Stage deploy trees + docs under $SHARE_DIR"
  # Stage each module's deploy/ tree (config examples, sigma, profiles, etc.) and
  # the dashboard, so the on-disk install carries the operator references.
  local spec mod
  for spec in "${MODULES[@]}"; do
    IFS=':' read -r mod _ _ <<<"$spec"
    if [ -d "$SCRIPT_DIR/$mod/deploy" ]; then
      run mkdir -p "$(dest "$SHARE_DIR/$mod")"
      run cp -R "$SCRIPT_DIR/$mod/deploy" "$(dest "$SHARE_DIR/$mod/")"
    fi
  done
  if [ -d "$SCRIPT_DIR/dashboard" ]; then
    run mkdir -p "$(dest "$SHARE_DIR")"
    run cp -R "$SCRIPT_DIR/dashboard" "$(dest "$SHARE_DIR/")"
  fi
}

make_dirs_and_config() {
  step "Create config + state dirs and fan out the shared token"
  # config dirs 0750
  mkdirp 0750 /etc/collector /etc/agentd
  local spec mod
  for spec in "${REPORTERS[@]}"; do
    IFS=':' read -r mod _ _ _ _ <<<"$spec"
    mkdirp 0750 "/etc/$mod"
  done
  # state dirs 0750
  mkdirp 0750 /var/lib/collector /var/lib/agentd

  ensure_token
  write_collector_env
  for spec in "${REPORTERS[@]}"; do
    IFS=':' read -r mod envfile authvar urlvar path <<<"$spec"
    write_reporter_env "$mod" "$envfile" "$authvar" "$urlvar" "$path"
  done
  write_agentd_env
}

enable_units() {
  step "Enable + start units"
  if ! use_systemctl; then
    if staging; then
      log "DESTDIR set: skipping systemctl (staging only). Units are laid out under $SYSTEMD_DIR."
    else
      log "DRY-RUN: would 'systemctl daemon-reload' then enable --now the collector, agentd, and the 6 timers; enable (not start) $BASELINE_UNIT."
    fi
    return
  fi
  systemctl daemon-reload
  systemctl enable --now collector.service
  systemctl enable --now agentd.service
  local t
  for t in "${DETECTOR_TIMERS[@]}"; do
    systemctl enable --now "$t"
  done
  # baseline runs early at boot; enable so it captures the allowlist next boot.
  systemctl enable "$BASELINE_UNIT"
}

post_install_summary() {
  cat <<EOF

============================================================================
 defensive-suite — observe tier installed (version $VERSION)
============================================================================
 Binaries:    $BIN_DIR  (8 static binaries)
 Units:       $SYSTEMD_DIR  (collector + 6 detectors + agentd OBSERVE)
 Config:      /etc/{collector,agentd,authwatch,credsentinel,instguard,posturescan,egresswatch,bpfsentry}
 State:       /var/lib/{collector,agentd}
 Token:       ONE bearer token shared by collector + all reporters (env-only, 0600).

 Running now (real install): collector.service, agentd.service (observe), and
   the 6 detector timers; $BASELINE_UNIT is enabled to capture the BPF
   allowlist on the next boot.

 Dashboard:   the collector serves it locally — default http://$COLLECTOR_ADDR_DEFAULT/
              (also staged at $SHARE_DIR/dashboard/index.html)

 NOT armed (manual, by design):
   - agentd-response.service was NOT installed/enabled.
   - No Tetragon enforce policy was loaded.
   To ARM manual response / enforcement, REVIEW then follow:
     - agent/deploy/RESPONSE.md   (the privileged response daemon)
     - agent/deploy/ENFORCE.md    (Tetragon enforce policy)
   staged at: $SHARE_DIR/agent/deploy/{RESPONSE.md,ENFORCE.md}
============================================================================
EOF
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
  step "Uninstall — stop/disable units, remove binaries + units"
  # Stop + disable units (real install only).
  if use_systemctl; then
    local t
    for t in "${DETECTOR_TIMERS[@]}" "$BASELINE_UNIT" agentd.service collector.service; do
      systemctl disable --now "$t" 2>/dev/null || true
    done
    # Make sure the armed unit is never left lingering either.
    systemctl disable --now agentd-response.service 2>/dev/null || true
  else
    if staging; then
      log "(destdir mode: skipping systemctl)"
    else
      log "(dry-run mode: skipping systemctl)"
    fi
  fi

  # Remove unit files.
  local spec mod units u
  run rm -f "$(dest "$SYSTEMD_DIR/collector.service")"
  run rm -f "$(dest "$SYSTEMD_DIR/agentd.service")"
  for spec in "${DETECTOR_UNITS[@]}"; do
    IFS=':' read -r mod units <<<"$spec"
    for u in $units; do
      run rm -f "$(dest "$SYSTEMD_DIR/$u")"
    done
  done

  # Remove binaries.
  local bin
  for spec in "${MODULES[@]}"; do
    IFS=':' read -r mod bin _ <<<"$spec"
    run rm -f "$(dest "$BIN_DIR/$bin")"
  done

  # Remove staged deploy/docs.
  run rm -rf "$(dest "$SHARE_DIR")"

  if use_systemctl; then
    systemctl daemon-reload || true
  fi

  if [ "$DO_PURGE" -eq 1 ]; then
    step "Purge — removing /etc + /var/lib data (tokens!)"
    run rm -rf "$(dest /etc/collector)" "$(dest /etc/agentd)" \
               "$(dest /etc/authwatch)" "$(dest /etc/credsentinel)" \
               "$(dest /etc/instguard)" "$(dest /etc/posturescan)" \
               "$(dest /etc/egresswatch)" "$(dest /etc/bpfsentry)" \
               "$(dest /var/lib/collector)" "$(dest /var/lib/agentd)"
  else
    log "Kept /etc/* and /var/lib/* data (tokens preserved). Use --purge to remove."
  fi
  log "Uninstall complete."
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share/defensive-suite"

require_root_if_real

if staging; then
  log "Staging into DESTDIR=$DESTDIR (no systemctl, real system untouched)."
fi
if [ "$DRY_RUN" -eq 1 ]; then
  log "DRY-RUN: no changes will be made."
fi

if [ "$DO_UNINSTALL" -eq 1 ]; then
  do_uninstall
  exit 0
fi

resolve_version
log "defensive-suite installer — version to inject: $VERSION; prefix: $PREFIX"

build_all
install_units
install_docs
make_dirs_and_config
enable_units
post_install_summary
