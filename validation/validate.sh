#!/usr/bin/env bash
# defensive-suite — end-to-end validation harness.
#
#   >>> RUN ON A THROWAWAY LINUX VM ONLY. <<<
# This ARMS Tetragon enforcement (SIGKILL on non-allowlisted eBPF loads) and,
# with --with-response, performs a LIVE kill via agentd. It is the "validate in a
# VM" step from agent/deploy/ENFORCE.md — it does the privileged things that the
# build/tests never do. It cleans up after itself (policies, processes, temp dir).
#
# It proves the live loop CI cannot:
#   stage 2  detect   — a synthetic eBPF load is reported as a finding in the collector
#   stage 2b correlate— a staging-dir exec that CONNECTS OUT is paired (by exec_id)
#                       with its egress into ONE Critical realtime.correlated finding,
#                       proving the tcp_connect hook + sock_arg dst parsing + the
#                       stateful correlator all work on REAL Tetragon output (the
#                       signal Phase 4 auto-response will key on) — plus a non-staging
#                       negative control that must NOT correlate
#   stage 3  enforce  — a NON-allowlisted eBPF load is SIGKILLed; Tetragon survives;
#                       AND the implant program is proven ABSENT (bpftool count
#                       before/after) — or HONESTLY warns if SIGKILL killed the
#                       loader but the program loaded anyway (the async caveat).
#   stage 3b enforce-override — (optional, gated on CONFIG_BPF_KPROBE_OVERRIDE)
#                       the Override variant BLOCKS the load (-EPERM): loadbpf
#                       exits 1, no new prog resident.
#   stage 4  respond  — (optional) a throwaway process is killed via collector→agentd
#
# Prerequisites (install first; see agent/deploy/ENFORCE.md step b):
#   - a running `tetragon` service with JSON file export enabled, the `tetra` CLI
#   - go (build), cc + kernel headers / linux-libc-dev (compile the loader), curl
#   - bpftool (to prove the implant program is absent after enforcement)
#
# Usage:
#   sudo ./validate.sh -y                 # detect + enforce (+ implant-absent check)
#   sudo ./validate.sh -y --with-response # also the live kill (M3)
#   sudo ./validate.sh -y --with-override # also stage 3b: the Override TRUE block
#   Flags: --keep (leave everything up) --force-baremetal (skip the VM guard)
set -uo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SELF/.." && pwd)"
PORT="${DSUITE_VALIDATE_PORT:-8799}"
TLOG="${AGENT_TETRAGON_LOG:-/var/log/tetragon/tetragon.log}"
YES=0 WITH_RESPONSE=0 WITH_OVERRIDE=0 FORCE_BAREMETAL=0 KEEP=0

for a in "$@"; do case "$a" in
  -y|--yes)            YES=1 ;;
  --with-response)     WITH_RESPONSE=1 ;;
  --with-override)     WITH_OVERRIDE=1 ;;
  --force-baremetal)   FORCE_BAREMETAL=1 ;;
  --keep)              KEEP=1 ;;
  -h|--help)           sed -n '2,30p' "$0"; exit 0 ;;
  *) echo "unknown arg: $a (see --help)"; exit 2 ;;
esac; done

c_g=$'\e[32m'; c_r=$'\e[31m'; c_y=$'\e[33m'; c_0=$'\e[0m'
PASS=0; FAIL=0
BG_PIDS=(); VICTIM_PID=""; WORK=""
say(){ printf '\n%s=== %s ===%s\n' "$c_y" "$*" "$c_0"; }
info(){ printf '    %s\n' "$*"; }
pass(){ PASS=$((PASS+1)); printf '  %s[PASS]%s %s\n' "$c_g" "$c_0" "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  %s[FAIL]%s %s\n' "$c_r" "$c_0" "$*"; }
die(){ printf '%sABORT:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing required tool '$1' ($2)"; }
rand(){ head -c12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cleanup(){
  # Only a real run (stage 1 onward) sets WORK. Early exits — --help, the no--y
  # info path, a failed guard — must NOT touch host state (no policy/nft deletes).
  [ -z "${WORK:-}" ] && return
  if [ "$KEEP" = 1 ]; then
    printf '\n--keep set: leaving processes, policies and %s in place.\n' "$WORK"
    return
  fi
  printf '\n%s=== cleanup ===%s\n' "$c_y" "$c_0"
  [ -n "${VICTIM_PID:-}" ] && kill -9 "$VICTIM_PID" 2>/dev/null
  for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  tetra tracingpolicy delete dsuite-enforce-override 2>/dev/null && info "removed enforce-override policy"
  tetra tracingpolicy delete dsuite-enforce 2>/dev/null && info "removed enforce policy"
  tetra tracingpolicy delete dsuite-observe 2>/dev/null && info "removed observe policy"
  nft delete table inet dsuite_isolate 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
  info "done — VM left as it was (Tetragon still installed/running)."
}
# cleanup runs on any normal/error exit; a signal is converted to an exit (130) so
# the EXIT trap runs cleanup exactly ONCE and the script actually ABORTS. A bare
# INT/TERM handler that returns would RESUME the script mid-run — dangerous here
# (it could re-arm enforce or proceed into the live kill after Ctrl-C).
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_http(){ local url="$1" n="${2:-30}"; for _ in $(seq 1 "$n"); do curl -fsS "$url" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
# victim_dead: true if the pid is gone OR a zombie. A SIGKILLed CHILD becomes a
# zombie until reaped, and `kill -0` still succeeds on a zombie — so we must check
# the process STATE, not just existence, to avoid a false "still alive".
victim_dead(){ local s; s="$(ps -o stat= -p "$1" 2>/dev/null | tr -d '[:space:]')"; [ -z "$s" ] || [ "${s:0:1}" = Z ]; }
wait_for_finding(){ # $1=check substring  $2=timeout secs
  local want="$1" deadline=$(( $(date +%s) + ${2:-30} ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    curl -fsS "http://127.0.0.1:$PORT/api/findings" 2>/dev/null | grep -q "\"check\":\"$want\"" && return 0
    sleep 1
  done
  return 1
}
# prog_count: number of currently-resident eBPF programs, per bpftool. Used to
# prove the synthetic implant program is ABSENT after enforcement — we compare a
# baseline taken before arming against the count after the SIGKILL/Override
# attempt. `bpftool prog list` prints one "<id>: <type>" header line per program;
# count those header lines (lines starting with a digit + colon).
prog_count(){ bpftool prog list 2>/dev/null | grep -cE '^[0-9]+:'; }

# ───────────────────────── stage 0 — guards ─────────────────────────
say "stage 0 — guards & prerequisites"
[ "$(uname -s)" = Linux ] || die "must run on Linux (this is $(uname -s)). The whole point is a real kernel."
if [ "$YES" != 1 ]; then
  cat <<EOF
This harness ARMS Tetragon enforcement (SIGKILL on non-allow-listed eBPF program
loads) on THIS machine, and with --with-response will KILL a throwaway process via
agentd. Run it only on a disposable Linux VM you can afford to break.

Re-run with -y to proceed.  Optional: --with-response  --keep  --force-baremetal
EOF
  exit 0
fi
[ "$(id -u)" = 0 ] || die "run as root (it loads Tetragon policies and may kill processes): sudo $0 ..."
if command -v systemd-detect-virt >/dev/null 2>&1; then
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  info "virtualization: ${virt:-unknown}"
  if [ "$virt" = none ] && [ "$FORCE_BAREMETAL" != 1 ]; then
    die "systemd-detect-virt reports 'none' (looks like bare metal). Refusing — use --force-baremetal only on a machine you can wipe."
  fi
fi
need go "build agentd/collector"; need cc "compile the eBPF loader"; need tetra "Tetragon CLI"
need curl "HTTP checks"; need systemctl "service checks"; need nft "isolate cleanup"
need bpftool "prove the implant eBPF program is absent after enforcement"
systemctl is-active --quiet tetragon || die "tetragon service is not active. Install + start Tetragon first (agent/deploy/ENFORCE.md step b), then re-run."
[ -f "$TLOG" ] || die "Tetragon JSON export not found at $TLOG. Enable file export (set export-filename in /etc/tetragon/tetragon.conf.d/ and restart tetragon), or pass AGENT_TETRAGON_LOG=... — agentd consumes that export."
info "tetragon active; JSON export at $TLOG"

# ───────────────────────── stage 1 — build ─────────────────────────
say "stage 1 — build the binaries + the synthetic loader"
WORK="$(mktemp -d /tmp/dsuite-validate.XXXXXX)"; BIN="$WORK/bin"; DATA="$WORK/collector-data"
mkdir -p "$BIN" "$DATA"
( cd "$REPO_ROOT/agent"     && CGO_ENABLED=0 go build -o "$BIN/agentd" . )    || die "agentd build failed"
( cd "$REPO_ROOT/collector" && CGO_ENABLED=0 go build -o "$BIN/collector" . ) || die "collector build failed"
cc -O2 -o "$BIN/loadbpf" "$SELF/loadbpf.c" || die "loadbpf compile failed — install kernel headers (e.g. apt install linux-libc-dev)"
info "built: agentd, collector, loadbpf"
"$BIN/agentd" preflight || info "(preflight notes some not-ready items; the harness sets up the rest — continuing)"

# Resolve the REAL on-disk paths of the legitimate eBPF loaders so enforce never
# kills them (above all, the running tetragon daemon loading its own programs).
ALLOW=()
tpid="$(pgrep -x tetragon | head -1 || true)"
[ -n "$tpid" ] && { e="$(readlink -f "/proc/$tpid/exe" 2>/dev/null || true)"; [ -n "$e" ] && ALLOW+=("$e"); }
for b in tetragon cilium-agent bpftool; do
  p="$(command -v "$b" 2>/dev/null || true)"; [ -n "$p" ] && ALLOW+=("$(readlink -f "$p")")
done
# de-dup
mapfile -t ALLOW < <(printf '%s\n' "${ALLOW[@]:-}" | awk 'NF && !seen[$0]++')
[ "${#ALLOW[@]}" -gt 0 ] || die "could not resolve the tetragon binary path to allow-list; refusing to arm enforce (would risk killing tetragon)."
info "loader allow-list: ${ALLOW[*]}"
ALLOW_CSV="$(IFS=,; echo "${ALLOW[*]}")"

# Response token/socket decided up front so the collector can proxy in stage 4.
RTOKEN="resp-$(rand)"; SOCK="$WORK/agentd.sock"

# ──────────────────── stage 2 — detection (observe) ────────────────────
say "stage 2 — detection: a synthetic eBPF load → a finding in the collector"
CTOKEN="ingest-$(rand)"
COLLECTOR_TOKEN="$CTOKEN" COLLECTOR_AGENT_SOCKET="$SOCK" COLLECTOR_RESPONSE_TOKEN="$RTOKEN" \
  "$BIN/collector" --addr "127.0.0.1:$PORT" --data "$DATA" >"$WORK/collector.log" 2>&1 &
BG_PIDS+=("$!")
wait_http "http://127.0.0.1:$PORT/healthz" 30 || die "collector did not come up — see $WORK/collector.log"
info "collector up on 127.0.0.1:$PORT"

tetra tracingpolicy delete dsuite-observe 2>/dev/null
tetra tracingpolicy add "$REPO_ROOT/agent/deploy/tetragon/dsuite-observe.yaml" || die "failed to load the observe policy"
info "observe policy loaded"

AGENT_TETRAGON_LOG="$TLOG" AGENT_COLLECTOR_URL="http://127.0.0.1:$PORT/ingest" \
AGENT_COLLECTOR_AUTH="Bearer $CTOKEN" AGENT_BPF_ALLOWLIST="$ALLOW_CSV" \
AGENT_FLUSH_SECONDS=2 AGENT_HOST="validate-vm" \
  "$BIN/agentd" run >"$WORK/agentd.log" 2>&1 &
AGENTD_PID="$!"; BG_PIDS+=("$AGENTD_PID")
sleep 2  # agentd tails from EOF; give it a moment to attach before we trigger

info "running the (non-allow-listed) loader under OBSERVE — it should load AND be reported..."
"$BIN/loadbpf" >"$WORK/loadbpf-observe.out" 2>&1 || true
if wait_for_finding "realtime.bpf" 30; then
  pass "agentd reported the eBPF load (real-time detection pipeline works end-to-end)"
else
  fail "no realtime.bpf finding within 30s — see $WORK/agentd.log and $WORK/collector.log"
fi

# ──────────────────── stage 2b — correlation (observe) ────────────────────
# Proves on a REAL kernel what the unit tests (mocked events) cannot, and what
# Phase 4 auto-response will key on: (a) the tcp_connect egress hook in
# dsuite-observe.yaml actually emits connect events, (b) agentd parses the sock_arg
# destination out of REAL Tetragon JSON, and (c) the stateful correlator pairs a
# staging-dir exec with a later egress from the SAME process (same exec_id) into one
# Critical realtime.correlated finding. Reuses the stage-2 collector + agentd +
# observe policy (still loaded; /tmp is a default staging dir).
say "stage 2b — correlation: a staging-dir exec that CONNECTS OUT → one Critical correlated finding"
corr_count(){ curl -fsS "http://127.0.0.1:$PORT/api/findings" 2>/dev/null | grep -o '"check":"realtime.correlated"' | wc -l | tr -d ' '; }
STAGE_BIN="$WORK/staged-$(rand)"            # under /tmp → a default staging dir
cp "$(command -v bash)" "$STAGE_BIN" || die "could not stage a test binary"
CORR_PORT=$(( PORT + 101 )); BENIGN_PORT=$(( PORT + 102 ))
info "running staged exec $STAGE_BIN that opens a TCP connect to 127.0.0.1:$CORR_PORT (same process)..."
# A refused connect is fine: tcp_connect() runs on the active-open path before the
# handshake, so the kprobe fires whether or not anything is listening.
"$STAGE_BIN" -c "exec 3<>/dev/tcp/127.0.0.1/$CORR_PORT" 2>/dev/null || true
if wait_for_finding "realtime.correlated" 40; then
  pass "agentd emitted realtime.correlated (exec→egress correlation fires on a real kernel)"
  if curl -fsS "http://127.0.0.1:$PORT/api/findings" 2>/dev/null | grep -q "127.0.0.1:$CORR_PORT"; then
    pass "the correlated finding carries dst 127.0.0.1:$CORR_PORT (tcp_connect sock_arg parsed from REAL Tetragon output)"
  else
    printf '  %s[WARN]%s realtime.correlated present but dst 127.0.0.1:%s not in it — the egress event/sock_arg shape may differ from the parser; inspect /api/findings + %s/agentd.log\n' "$c_y" "$c_0" "$CORR_PORT" "$WORK"
  fi
else
  fail "no realtime.correlated within 40s — the tcp_connect hook or the correlator did not fire on real data (the connect event/sock_arg shape may differ from the parser); see $WORK/agentd.log"
fi

# Negative control (a basic FALSE-POSITIVE guard): a NON-staging exec that connects
# out must NOT correlate — its exec_id has no suspicious base finding. (A real FP
# RATE needs an observe-mode soak on real workloads — see the summary note.)
info "negative control: a non-staging exec connects to 127.0.0.1:$BENIGN_PORT — must NOT correlate..."
before_corr="$(corr_count)"
bash -c "exec 3<>/dev/tcp/127.0.0.1/$BENIGN_PORT" 2>/dev/null || true   # /bin/bash — not under a staging dir
sleep 6  # let agentd tail + flush
after_corr="$(corr_count)"
if [ "${after_corr:-0}" -le "${before_corr:-0}" ]; then
  pass "the benign non-staging connect did NOT correlate ($before_corr → $after_corr) — no exec→egress false positive"
else
  fail "a benign non-staging connect produced a correlated finding ($before_corr → $after_corr) — false positive"
fi

# ──────────────────── stage 3 — enforcement (SIGKILL) ────────────────────
say "stage 3 — enforcement: the non-allow-listed loader must be SIGKILLed"
tetra tracingpolicy delete dsuite-observe 2>/dev/null  # swap observe → enforce (avoid double-hook)

# Baseline the resident eBPF program count BEFORE arming. After the SIGKILL
# attempt we re-count: if the count rose, the implant program loaded anyway
# (SIGKILL reaped the loader asynchronously, AFTER the program was resident) —
# the honest caveat from dsuite-enforce.yaml / ENFORCE.md part (d).
ENFORCE_YAML="$WORK/dsuite-enforce.generated.yaml"
{
  cat <<'HEAD'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: dsuite-enforce
spec:
  kprobes:
    - call: "security_bpf_prog_load"
      syscall: false
      selectors:
        - matchBinaries:
            - operator: "NotIn"
              values:
HEAD
  for p in "${ALLOW[@]}"; do printf '                - "%s"\n' "$p"; done
  cat <<'TAIL'
          matchActions:
            - action: Sigkill
TAIL
} > "$ENFORCE_YAML"

tetra tracingpolicy add "$ENFORCE_YAML" || die "failed to load the enforce policy"
info "enforce policy loaded (allow-list: ${ALLOW[*]})"
sleep 1

if systemctl is-active --quiet tetragon; then
  pass "tetragon still active after arming enforce (positive control: the allow-list protects it)"
else
  fail "tetragon went INACTIVE after enforce — the allow-list did not cover its real binary path"
fi

# Baseline the resident-program count AFTER the enforce policy (and Tetragon's own
# enforce eBPF program) is loaded + settled, so ONLY the implant's load can change
# it. Capturing before the policy loaded would count the policy's own program as a
# false implant (false WARN).
PROG_BEFORE="$(prog_count)"
info "resident eBPF programs (enforce loaded, baseline): $PROG_BEFORE"

info "running the non-allow-listed loader under ENFORCE — expect: Killed..."
"$BIN/loadbpf" >"$WORK/loadbpf-enforce.out" 2>&1; rc=$?
LOADER_KILLED=0
if [ "$rc" -eq 137 ]; then
  LOADER_KILLED=1
  pass "loader was SIGKILLed (exit 137) — enforcement blocks the non-allow-listed bpf load"
elif grep -q "NOT killed" "$WORK/loadbpf-enforce.out" 2>/dev/null; then
  fail "loader printed success and was not killed (rc=$rc) — enforce did NOT fire"
else
  fail "loader exit=$rc (expected 137=SIGKILL); inconclusive — see $WORK/loadbpf-enforce.out"
fi

# IMPLANT-ABSENT CHECK — prove SIGKILL actually stopped the load, not just the
# loader. Re-count resident eBPF programs; allow the count a moment to settle
# (the killed loader's fd is closed and the program freed asynchronously).
sleep 1
PROG_AFTER="$(prog_count)"
info "resident eBPF programs after the SIGKILL attempt: $PROG_AFTER (baseline $PROG_BEFORE)"
if [ "${PROG_AFTER:-0}" -le "${PROG_BEFORE:-0}" ]; then
  pass "implant ABSENT — no extra eBPF program resident after SIGKILL (the load was actually stopped)"
elif [ "$LOADER_KILLED" = 1 ]; then
  # The honest, load-bearing caveat: the loader DIED (137) but a program is still
  # resident — SIGKILL reaped the loader AFTER the program loaded. Report it as a
  # WARN, not a hard pass, and point at the Override variant (the true block).
  printf '  %s[WARN]%s SIGKILL killed the loader (exit 137) BUT an extra eBPF program is resident\n' "$c_y" "$c_0"
  printf '         (%d → %d). This is the documented async caveat: SIGKILL reaps the loader\n' "$PROG_BEFORE" "$PROG_AFTER"
  printf '         AFTER the program is already loaded — it is best-effort, NOT a guaranteed block.\n'
  printf '         Recommend the Override variant (enforce/dsuite-enforce-override.yaml, -EPERM) on a\n'
  printf '         kernel with CONFIG_BPF_KPROBE_OVERRIDE. Re-run with --with-override to verify it.\n'
else
  fail "an extra eBPF program is resident ($PROG_BEFORE → $PROG_AFTER) and the loader was NOT killed — enforce did not block the load"
fi

# ──────────────────── stage 3b — Override: a TRUE block (optional) ────────────────────
# Gated on the kernel actually supporting CONFIG_BPF_KPROBE_OVERRIDE. We trust
# the agent's own preflight check (kprobe-override row "ok") rather than re-parse
# the kernel config here. Override returns -EPERM from the kprobe, so the bpf()
# load FAILS (loadbpf exits 1 with "Operation not permitted") and NO program is
# resident — unlike SIGKILL, the load never happens.
if [ "$WITH_OVERRIDE" = 1 ]; then
  say "stage 3b — Override: the non-allow-listed load must be BLOCKED (-EPERM), not just killed"
  if "$BIN/agentd" preflight 2>/dev/null | grep -E '^ok[[:space:]]' | grep -q 'kprobe-override'; then
    info "preflight reports CONFIG_BPF_KPROBE_OVERRIDE present — proceeding with the Override variant"
    tetra tracingpolicy delete dsuite-enforce 2>/dev/null  # swap Sigkill → Override (avoid double-hook)

    OVERRIDE_YAML="$WORK/dsuite-enforce-override.generated.yaml"
    {
      cat <<'HEAD'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: dsuite-enforce-override
spec:
  kprobes:
    - call: "security_bpf_prog_load"
      syscall: false
      selectors:
        - matchBinaries:
            - operator: "NotIn"
              values:
HEAD
      for p in "${ALLOW[@]}"; do printf '                - "%s"\n' "$p"; done
      cat <<'TAIL'
          matchActions:
            - action: Override
              argError: -1
TAIL
    } > "$OVERRIDE_YAML"

    tetra tracingpolicy add "$OVERRIDE_YAML" || die "failed to load the override enforce policy"
    info "override policy loaded (allow-list: ${ALLOW[*]})"
    sleep 1
    # Baseline AFTER the override policy (and its own eBPF program) is resident, so
    # the policy's program isn't miscounted as a false implant and a correctly
    # BLOCKING Override isn't reported as a failure.
    PROG_BEFORE_OV="$(prog_count)"

    info "running the non-allow-listed loader under OVERRIDE — expect: BPF_PROG_LOAD fails (EPERM), exit 1..."
    "$BIN/loadbpf" >"$WORK/loadbpf-override.out" 2>&1; orc=$?
    if [ "$orc" -eq 1 ] && grep -qiE 'Operation not permitted|EPERM' "$WORK/loadbpf-override.out"; then
      pass "load was BLOCKED at the source (bpf() returned EPERM, exit 1) — Override is a true block"
    elif grep -q "NOT killed" "$WORK/loadbpf-override.out" 2>/dev/null; then
      fail "loader reported success — Override did NOT block (kernel may lack CONFIG_BPF_KPROBE_OVERRIDE despite preflight)"
    else
      fail "loader exit=$orc (expected 1=EPERM); see $WORK/loadbpf-override.out"
    fi

    sleep 1
    PROG_AFTER_OV="$(prog_count)"
    info "resident eBPF programs after the Override attempt: $PROG_AFTER_OV (baseline $PROG_BEFORE_OV)"
    if [ "${PROG_AFTER_OV:-0}" -le "${PROG_BEFORE_OV:-0}" ]; then
      pass "implant ABSENT — Override prevented the load entirely (no extra program resident)"
    else
      fail "an extra eBPF program is resident ($PROG_BEFORE_OV → $PROG_AFTER_OV) — Override did not block the load"
    fi
    tetra tracingpolicy delete dsuite-enforce-override 2>/dev/null && info "removed override policy"
  else
    printf '  %s[SKIP]%s --with-override requested but preflight does not report CONFIG_BPF_KPROBE_OVERRIDE\n' "$c_y" "$c_0"
    info "this kernel cannot do the Override block; the Sigkill variant (stage 3) is the fallback. Skipping 3b."
  fi
fi

# ──────────────────── stage 4 — manual response (optional, LIVE) ────────────────────
if [ "$WITH_RESPONSE" = 1 ]; then
  say "stage 4 — manual response: kill a throwaway process via collector → agentd (LIVE)"
  kill "$AGENTD_PID" 2>/dev/null; wait "$AGENTD_PID" 2>/dev/null
  AGENT_RESPONSE_TOKEN="$RTOKEN" AGENT_QUARANTINE_DIR="$WORK/quarantine" AGENT_TETRAGON_LOG="$TLOG" \
    "$BIN/agentd" run --response-socket "$SOCK" --enable-response >"$WORK/agentd-resp.log" 2>&1 &
  BG_PIDS+=("$!")
  ok=0; for _ in $(seq 1 20); do [ -S "$SOCK" ] && { ok=1; break; }; sleep 0.3; done
  [ "$ok" = 1 ] || fail "agentd response socket never appeared — see $WORK/agentd-resp.log"

  sleep 600 & VICTIM_PID="$!"
  info "spawned throwaway victim pid=$VICTIM_PID; requesting kill via the collector /api/respond..."
  resp="$(curl -fsS -X POST -H "Authorization: Bearer $RTOKEN" \
    -d "{\"action\":\"kill\",\"target\":\"$VICTIM_PID\",\"reason\":\"validate\",\"actor\":\"validate.sh\"}" \
    "http://127.0.0.1:$PORT/api/respond" 2>&1)"
  info "collector→agentd response: $resp"
  sleep 1
  if victim_dead "$VICTIM_PID"; then
    pass "victim was killed via collector → agentd (live manual-response works)"
    wait "$VICTIM_PID" 2>/dev/null; VICTIM_PID=""
  else
    fail "victim still alive after the kill request (resp above)"
  fi
  if [ -s "$DATA/response-audit.jsonl" ] && grep -q '"action":"kill"' "$DATA/response-audit.jsonl"; then
    pass "the kill was recorded in the collector's append-only response audit log"
  else
    fail "no kill entry in $DATA/response-audit.jsonl (audit trail missing)"
  fi
fi

# ───────────────────────── summary ─────────────────────────
say "summary"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
info "stage 2b proves the correlation signal FIRES correctly (and a benign connect does not),"
info "but a real FALSE-POSITIVE RATE needs an observe-mode soak: run agentd against real"
info "workloads (no enforcement/response) and watch how often realtime.correlated fires before"
info "trusting it for Phase 4 AUTO-response. Auto-acting on an unmeasured signal is the core risk."
if [ "$FAIL" -eq 0 ]; then
  printf '%sVALIDATION PASSED — the live detect→enforce%s loop works on this kernel.%s\n' \
    "$c_g" "$([ "$WITH_RESPONSE" = 1 ] && echo '→respond')" "$c_0"
  exit 0
else
  printf '%sVALIDATION FAILED — %d check(s) failed (logs under %s).%s\n' "$c_r" "$FAIL" "$WORK" "$c_0"
  exit 1
fi
