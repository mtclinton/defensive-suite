package respond

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// auto.go is the Phase 4 / Increment 1 auto-response DECISION engine: the
// "bridge" that turns a correlated finding into a WOULD-action decision and
// shadows it for the FP soak to measure — and NEVER executes.
//
// ═══ HARD SAFETY INVARIANT ═══
// The Bridge holds NO Executor and NO Responder reference of any kind. It is
// STRUCTURALLY incapable of taking a destructive action: it can only (a) read
// findings, (b) read /proc read-only (via an injected procResolver), and
// (c) EMIT findings. There is no code path from Consider to Execute/Respond.
// canary|armed are not buildable in this increment (they require the responder
// lifecycle refactor + reverse actuators, a LATER increment): they clamp to
// shadow here, and cmdRun/cmdPreflight hard-error before a Bridge is even built.
// A test asserts the Bridge type has no executor field and that even a forced
// armed mode only emits findings.

// Mode is the auto-response ladder selector (§7.1 / §4.4).
type Mode int

const (
	// ModeOff: Consider is a no-op. Pure detection — no behaviour change.
	ModeOff Mode = iota
	// ModeDryRun: build the decision, emit a shadow WOULD-finding for the
	// collector to measure. Never executes.
	ModeDryRun
	// ModeShadow: same as dry-run for Increment 1 (both only emit). Shadow is the
	// trust ceiling for the file-tail input; canary+ require a later increment.
	ModeShadow
	// ModeCanary / ModeArmed are NOT buildable in this increment. parseMode clamps
	// them to ModeShadow (belt-and-suspenders) and the run/preflight paths fatal
	// out before a Bridge is constructed.
	ModeCanary
	ModeArmed
)

func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeDryRun:
		return "dry-run"
	case ModeShadow:
		return "shadow"
	case ModeCanary:
		return "canary"
	case ModeArmed:
		return "armed"
	default:
		return "off"
	}
}

// ErrModeNotImplemented is returned by ParseMode for canary/armed: execution is
// not implemented in this build. Callers (cmdRun/cmdPreflight) fail fast on it.
var ErrModeNotImplemented = fmt.Errorf("auto-response execution is not implemented in this build; max mode is shadow")

// ParseMode maps a config string to a Mode. off/dry-run/shadow parse normally.
// canary/armed (including "armed:<csv>") return (ModeShadow, ErrModeNotImplemented)
// so the caller can BOTH hard-error at startup AND, if it proceeds anyway, run
// clamped to shadow. Any unrecognized value is off (fail-safe), no error.
func ParseMode(s string) (Mode, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	// "armed:<csv>" is the broaden-ladder form; treat the prefix as armed.
	if strings.HasPrefix(s, "armed") {
		return ModeShadow, ErrModeNotImplemented
	}
	switch s {
	case "", "off":
		return ModeOff, nil
	case "dry-run", "dryrun":
		return ModeDryRun, nil
	case "shadow":
		return ModeShadow, nil
	case "canary":
		return ModeShadow, ErrModeNotImplemented
	default:
		return ModeOff, nil // unparseable → off (fail-safe)
	}
}

// AutoConfig is the Bridge's configuration, derived from agent config. It is a
// plain value (no executor, no responder) by design.
type AutoConfig struct {
	Mode Mode
	// StagingDirs are the residency-allowed dirs (G5). A target whose live
	// /proc/<pid>/exe is not under one of these is alert-only.
	StagingDirs []string
	// MgmtSubnets / CollectorHost feed G7 (non-external destinations).
	MgmtSubnets   []string
	CollectorHost string // host (no port) of the collector, treated as non-external
	// NeverQuarantine extends the protected-process backstop (§4.1).
	NeverQuarantine []string
	// StaleTTL is the G6 event-time freshness cutoff (default 5s).
	StaleTTL time.Duration
	// RateMax / RateWindow are the AUTO path's OWN budget (default 3/300s). On
	// exhaustion the decision is throttled (never touches the manual kill-switch).
	RateMax    int
	RateWindow time.Duration
	// DisablePath is the AUTO-ONLY disarm latch (distinct from the manual
	// kill-switch). When it exists the auto path is throttled.
	DisablePath string
}

// Bridge is the decision engine. It DELIBERATELY has no Executor/Responder/
// Exec/Respond field — see the file-level invariant. Its only mutable state is
// the action-dedup set and the auto-rate counter, both guarded by mu (§4.7).
type Bridge struct {
	cfg      AutoConfig
	mgmtNets []*net.IPNet // parsed MgmtSubnets (computed once)
	now      func() time.Time
	existsFn func(string) bool // disarm-latch existence probe (injectable)
	proc     procResolver      // /proc identity resolver (injectable)

	mu sync.Mutex
	// actionDedup keys completed would-actions on a STABLE attribute (resolved
	// target + dst + lineage-root), NOT the fresh /tmp name (§4.5 #29), so a
	// rename-per-exec storm collapses instead of burning one decision each.
	actionDedup map[string]bool
	// rate is the auto path's own sliding-window counter of EMITTED would-actions.
	rate []time.Time
	// lastThrottle is when the per-window throttled finding was last emitted, so
	// the throttle alert is rate-limited to ONE per window (§4.5 #16), not per
	// refused attempt.
	lastThrottle time.Time
	throttled    bool // whether a throttle finding has been emitted this window
}

// NewBridge builds a decision Bridge. now/existsFn/proc are injectable for tests;
// nil falls back to the real (read-only) implementations. The Bridge NEVER
// receives an Executor or Responder — there is no parameter for one.
func NewBridge(cfg AutoConfig, now func() time.Time, existsFn func(string) bool, proc procResolver) *Bridge {
	if now == nil {
		now = time.Now
	}
	if existsFn == nil {
		existsFn = statExists
	}
	if proc == nil {
		proc = realProcResolver{}
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 5 * time.Second
	}
	b := &Bridge{
		cfg:         cfg,
		now:         now,
		existsFn:    existsFn,
		proc:        proc,
		actionDedup: make(map[string]bool),
	}
	for _, c := range cfg.MgmtSubnets {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			b.mgmtNets = append(b.mgmtNets, n)
		}
	}
	return b
}

// Would-action classes the decision can select.
const (
	actionWouldQuarantine = "quarantine"
	actionAlertOnly       = "alert-only"
)

// Emitted check names (all flow to the collector for the FP soak to measure).
const (
	checkShadow    = "realtime.autoresponse.shadow"
	checkThrottled = "realtime.autoresponse.throttled"
)

// Consider runs the §3.1 gates over each finding and returns the auto-response
// WOULD-findings (shadow decisions / throttle notices). It NEVER executes: the
// Bridge has no actuator to reach. In ModeOff it returns nil. All calls are on
// the single tail goroutine, but the dedup/rate state is mutex-guarded so a
// concurrent test (and any future async caller) is race-clean.
func (b *Bridge) Consider(findings []report.Finding) []report.Finding {
	if b.cfg.Mode == ModeOff {
		return nil
	}
	var out []report.Finding
	for _, f := range findings {
		dec := b.decide(f)
		if dec == nil {
			continue
		}
		if emitted := b.emit(*dec); emitted != nil {
			out = append(out, *emitted)
		}
	}
	return out
}

// decision is the result of running the gates on one finding. eligible=false
// means a gate failed (alert-only / skip); eligible=true means every gate passed
// and a would-action was selected.
type decision struct {
	finding     report.Finding
	eligible    bool
	wouldAction string
	target      string // the resolved /proc target (G5), NOT Finding.Path
	dst         string
	dedupKey    string
	gates       []string // human gate outcomes for the Detail/Related
}

// decide runs gates G1–G8 EXACTLY per §3.1 and selects the §3.4 action. A nil
// return means "emit nothing" (a finding that is not even a correlated
// candidate). A non-eligible decision is currently emitted as nothing (quiet, to
// avoid soak noise — see emit()); the gate outcome is still recorded for tests.
func (b *Bridge) decide(f report.Finding) *decision {
	// G1 Corroboration — the LOAD-BEARING gate. NEVER reduced to a confidence
	// check: realtime.correlated is the only auto-eligible Check.
	if f.Check != "realtime.correlated" {
		return nil
	}
	d := &decision{finding: f}

	// G2 Confidence + G3 Severity: the SAME code-enforced bit as G1 (asserted
	// defensively, not counted as independent selectivity).
	if f.Confidence != "high" {
		d.gates = append(d.gates, "G2 confidence!=high (fail)")
		return d
	}
	if f.Severity != report.SeverityCritical {
		d.gates = append(d.gates, "G3 severity!=critical (fail)")
		return d
	}
	d.gates = append(d.gates, "G1-G3 corroborated/high/critical")

	// G4 exec_id-resolved: refuse a pid-only / absent attribution.
	if !relatedHas(f.Related, "resolved=exec_id") {
		d.gates = append(d.gates, "G4 not resolved by exec_id (fail → alert-only)")
		return d
	}
	d.gates = append(d.gates, "G4 resolved=exec_id")

	// AutoMeta is the typed identity snapshot. Absent → cannot identity-bind.
	if f.AutoMeta == nil {
		d.gates = append(d.gates, "G5 no identity metadata (fail → alert-only)")
		return d
	}

	// G6 freshness (event-time, best-effort): the Tetragon event time must be
	// within StaleTTL of the clock. A zero/absent event time fails closed.
	now := b.now()
	det := f.AutoMeta.DetectedAt
	if det.IsZero() || now.Sub(det) > b.cfg.StaleTTL || det.Sub(now) > b.cfg.StaleTTL {
		d.gates = append(d.gates, "G6 stale or no event time (fail → alert-only)")
		return d
	}
	d.gates = append(d.gates, "G6 fresh")

	// G7 destination class: dst must be routable + external. We read the dst from
	// AutoMeta first, falling back to the dst= Related marker.
	dst := f.AutoMeta.Dst
	if dst == "" {
		dst = relatedValue(f.Related, "dst=")
	}
	d.dst = dst
	if !b.dstIsExternal(dst) {
		d.gates = append(d.gates, "G7 non-external/unparseable dst (fail → alert-only)")
		return d
	}
	d.gates = append(d.gates, "G7 external dst")

	// G5 live, staging-resident, identity-bound, same-UID, non-protected target.
	// Computed READ-ONLY from /proc — no acting. The connecting process's own
	// exe is the target source; Finding.Path is NEVER trusted.
	target := b.proc.resolve(f.AutoMeta.Pid)
	connecting := target // for Increment 1 the connecting proc IS the candidate
	if !target.Live {
		d.gates = append(d.gates, "G5 process not live (fail → alert-only)")
		return d
	}
	if !underStagingDir(target.Exe, b.cfg.StagingDirs) {
		d.gates = append(d.gates, "G5 exe not under a staging dir (fail → alert-only)")
		return d
	}
	if target.UID != connecting.UID {
		d.gates = append(d.gates, "G5 UID mismatch (fail → alert-only)")
		return d
	}
	if isProtectedExe(target, b.cfg.NeverQuarantine) {
		d.gates = append(d.gates, "G5 protected process (fail → alert-only)")
		return d
	}
	d.gates = append(d.gates, "G5 live/staging/same-UID/non-protected target")
	d.target = target.Exe

	// G8 + §3.4 action selection over the FULL set of base techniques. Inspect
	// EVERY "base technique=" line.
	techs := relatedValues(f.Related, "base technique=")
	d.wouldAction = selectAction(techs)
	switch d.wouldAction {
	case actionWouldQuarantine:
		d.gates = append(d.gates, "G8 fileless/external base → quarantine")
		d.eligible = true
	default:
		// bare staging T1059 (G8) or bpf-load present (§3.4 precedence): alert-only.
		d.gates = append(d.gates, "G8/§3.4 base technique → alert-only")
	}

	// Stable dedup key (§4.5 #29): resolved target + dst + lineage-root, NOT the
	// fresh /tmp name.
	d.dedupKey = d.target + "|" + d.dst + "|" + lineageRoot(f.Related)
	return d
}

// selectAction implements §3.4 precedence over the full technique set:
//   - any bpf-load (T1014) present → force alert-only (quarantining the loader is
//     theatre; the resident eBPF program keeps running).
//   - else if fileless (T1620) present → quarantine (the would-action).
//   - else (bare staging T1059 only, or no recognized technique) → alert-only (G8
//     excludes the cheapest-to-forge bare staging exec).
func selectAction(techniques []string) string {
	hasBPF, hasFileless := false, false
	for _, t := range techniques {
		switch strings.TrimSpace(t) {
		case "T1014":
			hasBPF = true
		case "T1620":
			hasFileless = true
		}
	}
	if hasBPF {
		return actionAlertOnly // precedence: loader quarantine is theatre
	}
	if hasFileless {
		return actionWouldQuarantine
	}
	return actionAlertOnly // bare staging T1059-only is G8-excluded
}

// emit turns a decision into the finding(s) it should produce, applying the
// auto-only disarm latch + auto-rate budget (§4.5). It returns nil when the
// decision yields no would-finding (off/non-eligible/already-deduped). The
// Bridge NEVER executes — this only constructs report.Finding values.
func (b *Bridge) emit(d decision) *report.Finding {
	if !d.eligible {
		// A failed-gate finding is kept QUIET to avoid soak noise (documented
		// choice): emit nothing. The gate outcomes are still available to tests via
		// decide(). (A future increment may emit a low-severity skipped finding.)
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()

	// Action-dedup on the STABLE key: a rename-per-exec storm to the same target+
	// dst+lineage-root collapses to one decision.
	if b.actionDedup[d.dedupKey] {
		return nil
	}

	// Auto-only disarm: the latch FILE exists, OR the auto-rate budget is
	// exhausted → THROTTLE. Emit ONE throttled finding per window (rate-limited),
	// no would-act. NEVER touch the shared manual kill-switch.
	latched := b.cfg.DisablePath != "" && b.existsFn != nil && b.existsFn(b.cfg.DisablePath)
	overBudget := b.overRateLocked(now)
	if latched || overBudget {
		return b.throttleLocked(now, latched)
	}

	// Within budget and not latched: record the rate event + dedup, then emit the
	// shadow WOULD-finding. (We consume budget only for an actually-emitted
	// decision.)
	b.rate = append(b.rate, now)
	b.actionDedup[d.dedupKey] = true
	b.throttled = false // a successful emit reopens the throttle for the next storm

	target := d.target
	mode := b.cfg.Mode.String()
	related := []string{
		"mode=" + mode,
		"would_action=" + d.wouldAction,
		"resolved_target=" + target,
		"dst=" + d.dst,
	}
	related = append(related, d.gates...)
	f := report.Finding{
		Check:      checkShadow,
		Severity:   report.SeverityHigh,
		Confidence: "high",
		Title:      fmt.Sprintf("WOULD %s %s", d.wouldAction, target),
		Detail: fmt.Sprintf(
			"auto-response %s decision (NOT executed): would %s live /proc target %q (dst %s); gates passed: %s",
			mode, d.wouldAction, target, d.dst, strings.Join(d.gates, "; ")),
		Technique: d.finding.Technique,
		Related:   related,
	}
	return &f
}

// overRateLocked reports whether the auto-rate budget is exhausted at now,
// pruning the sliding window first. mu must be held.
func (b *Bridge) overRateLocked(now time.Time) bool {
	if b.cfg.RateMax <= 0 || b.cfg.RateWindow <= 0 {
		return false // no budget configured → never over budget
	}
	cutoff := now.Add(-b.cfg.RateWindow)
	kept := b.rate[:0]
	for _, t := range b.rate {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.rate = kept
	return len(b.rate) >= b.cfg.RateMax
}

// throttleLocked emits AT MOST one throttled finding per window. mu must be held.
// It NEVER touches the shared manual kill-switch — throttling is auto-only.
func (b *Bridge) throttleLocked(now time.Time, latched bool) *report.Finding {
	if b.throttled && now.Sub(b.lastThrottle) < b.cfg.RateWindow {
		return nil // already alerted this window
	}
	b.throttled = true
	b.lastThrottle = now
	reason := "auto-rate budget exhausted"
	if latched {
		reason = "auto-only disarm latch present"
	}
	return &report.Finding{
		Check:      checkThrottled,
		Severity:   report.SeverityHigh,
		Confidence: "high",
		Title:      "auto-response throttled",
		Detail: fmt.Sprintf(
			"auto-response decision throttled (%s); manual response is UNAFFECTED (shared kill-switch not touched)",
			reason),
		Related: []string{"mode=" + b.cfg.Mode.String(), "throttle_reason=" + reason},
	}
}

// dstIsExternal implements G7: dst must be routable, non-loopback,
// non-RFC1918/CGNAT/link-local, non-collector, non-mgmt-subnet. An empty /
// unparseable / non-IP dst is NOT external (→ alert-only). dst may be "ip",
// "ip:port", or the generic fallback phrase.
func (b *Bridge) dstIsExternal(dst string) bool {
	dst = strings.TrimSpace(dst)
	if dst == "" || dst == "an external endpoint" {
		return false // empty/unparseable → alert-only
	}
	host := dst
	if h, _, err := net.SplitHostPort(dst); err == nil {
		host = h
	} else if i := strings.LastIndexByte(dst, ':'); i >= 0 && strings.Count(dst, ":") == 1 {
		// "ip:port" that SplitHostPort rejected (rare); strip a trailing :port.
		host = dst[:i]
	}
	host = strings.TrimSpace(host)
	if b.cfg.CollectorHost != "" && strings.EqualFold(host, b.cfg.CollectorHost) {
		return false // the collector is never an external C2 dst
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // not an IP literal → unparseable → alert-only
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if isPrivateOrCGNAT(ip) {
		return false
	}
	for _, n := range b.mgmtNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// isPrivateOrCGNAT reports whether ip is RFC1918 (10/8, 172.16/12, 192.168/16)
// or CGNAT (100.64/10). IPv4-mapped IPv6 is normalized first. (ip.IsPrivate in
// the stdlib covers RFC1918 + fc00::/7 but NOT CGNAT, so we add 100.64/10.)
func isPrivateOrCGNAT(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}

// --- Related-line helpers (parse, never trust as a target) ---

// relatedHas reports whether any Related line equals s exactly.
func relatedHas(related []string, s string) bool {
	for _, r := range related {
		if r == s {
			return true
		}
	}
	return false
}

// relatedValue returns the value after the first Related line with the given
// prefix (e.g. "dst="), or "".
func relatedValue(related []string, prefix string) string {
	for _, r := range related {
		if strings.HasPrefix(r, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(r, prefix))
		}
	}
	return ""
}

// relatedValues returns the values after EVERY Related line with the given
// prefix (e.g. all "base technique=" lines for §3.4 precedence).
func relatedValues(related []string, prefix string) []string {
	var out []string
	for _, r := range related {
		if strings.HasPrefix(r, prefix) {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(r, prefix)))
		}
	}
	return out
}

// lineageRoot returns a stable lineage-root token from the "lineage:" Related
// line (the ROOT-most "binary[exectail]" segment, which is the last element of
// the youngest-first " ← "-joined chain), for dedup keying. "" when absent.
func lineageRoot(related []string) string {
	line := relatedValue(related, "lineage:")
	if line == "" {
		return ""
	}
	parts := strings.Split(line, "←")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}
