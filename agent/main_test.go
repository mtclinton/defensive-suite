package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/config"
	"github.com/mtclinton/defensive-suite/agent/internal/respond"
)

// runCfg builds a config rooted under a temp dir so buildResponder's audit log
// and quarantine dir land in a writable, isolated place.
func runCfg(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.QuarantineDir = filepath.Join(dir, "quarantine")
	cfg.ResponseSocket = filepath.Join(dir, "response.sock")
	cfg.ResponseToken = "test-token"
	cfg.ResponseKillSwitch = filepath.Join(dir, "response.disabled")
	return cfg
}

// auditPathFor mirrors buildResponder's audit-log location so the test can read
// what was written.
func auditPathFor(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.QuarantineDir), "response-audit.jsonl")
}

// --- §4.0: buildResponder is dry-run by default (manual behaviour identical) ---

func TestBuildResponderDryRunByDefault(t *testing.T) {
	cfg := runCfg(t) // ResponseEnabled defaults false
	r, closer, err := buildResponder(cfg)
	if err != nil {
		t.Fatalf("buildResponder: %v", err)
	}
	defer closer.Close()
	if !r.DryRun {
		t.Fatal("a responder built with ResponseEnabled=false must be dry-run")
	}
	// A manual request returns a dry-run result and never executes (FakeExecutor).
	res := r.Respond(respond.Request{Action: respond.ActionQuarantine, Target: "/tmp/evil"})
	if !res.DryRun || !res.OK {
		t.Errorf("dry-run manual result=%+v", res)
	}
}

// buildResponder fails CLOSED with no token (a privileged socket with no auth
// must not start) — same as the old startResponse.
func TestBuildResponderRefusesWithoutToken(t *testing.T) {
	cfg := runCfg(t)
	cfg.ResponseToken = ""
	if _, _, err := buildResponder(cfg); err == nil {
		t.Fatal("buildResponder must refuse to build without a response token")
	}
}

// FAIL CLOSED on an unopenable audit log: when the audit dir cannot be created,
// buildResponder returns an error so cmdRun refuses to serve a live, unaudited
// surface.
func TestBuildResponderFailsClosedOnAuditError(t *testing.T) {
	cfg := runCfg(t)
	// Make the audit's parent dir a FILE so MkdirAll(filepath.Dir(auditPath)) fails.
	// auditPath = <dir>/response-audit.jsonl, its dir is filepath.Dir(QuarantineDir)
	// = <tmp>. Point QuarantineDir under a regular file so the audit dir is invalid.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.QuarantineDir = filepath.Join(blocker, "quarantine")
	if _, _, err := buildResponder(cfg); err == nil {
		t.Fatal("buildResponder must fail closed when the audit log cannot be opened")
	}
}

// --- §4.0: the HOISTED responder serves manual response identically, and the
// audit file is closed at the top level on ctx.Done (decoupled from serve). ---

func TestServeResponseManualRoundTripAndAuditCloseOnCtxDone(t *testing.T) {
	cfg := runCfg(t)
	// Unix socket paths are limited (sun_path ~104 bytes on darwin); long temp
	// paths overflow it. Use a short socket path under the OS temp root and clean
	// it up ourselves.
	short, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	cfg.ResponseSocket = filepath.Join(short, "r.sock")

	r, closer, err := buildResponder(cfg)
	if err != nil {
		t.Fatalf("buildResponder: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var serveWG sync.WaitGroup
	if err := serveResponse(ctx, cfg, r, &serveWG); err != nil {
		t.Fatalf("serveResponse: %v", err)
	}

	// A unix-socket HTTP client targeting the served socket.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", cfg.ResponseSocket)
			},
		},
		Timeout: 5 * time.Second,
	}

	// Manual request behaves EXACTLY as before: dry-run (response not enabled).
	body, _ := json.Marshal(respond.Request{Action: respond.ActionKill, Target: "1234"})
	req, _ := http.NewRequest(http.MethodPost, "http://unix/respond", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.ResponseToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("manual /respond round-trip failed: %v", err)
	}
	var result respond.Result
	_ = json.NewDecoder(resp.Body).Decode(&result)
	_ = resp.Body.Close()
	if !result.OK || !result.DryRun {
		t.Errorf("hoisted responder manual result should be a dry-run OK: %+v", result)
	}

	// The audit log recorded the request (intent + result), proving the hoisted
	// responder + audit log are wired identically to the old in-startResponse pair.
	auditData, err := os.ReadFile(auditPathFor(cfg))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(auditData)), "\n") + 1; n < 2 {
		t.Errorf("expected intent+result audit lines, got %d: %q", n, auditData)
	}

	// ctx.Done decouples the audit close: cmdRun closes the audit file at the top
	// level after both consumers stop. Here we emulate that: cancel ctx (stops the
	// serve goroutine), JOIN the serve goroutine (FIX 3: serveWG.Wait, exactly as
	// cmdRun does), then close the audit file via the returned closer — it must
	// close cleanly (no double-close / no panic).
	cancel()
	serveWG.Wait() // FIX 3: join the serve goroutine BEFORE closing the audit file.
	if err := closer.Close(); err != nil {
		t.Errorf("top-level audit close on ctx.Done should succeed: %v", err)
	}
}

// TestServeResponseAuditsInFlightResponseDuringShutdown is the FIX 3 abuse-path
// test: a response that begins executing as ctx cancels must be FULLY audited —
// its audit line must land BEFORE the audit file is closed (no
// close-before-last-write, the §4.0 hazard). It drives a request whose audit write
// is deliberately SLOW (a blocking io.Writer released only after ctx is cancelled),
// then asserts cmdRun's ordering — serveWG.Wait() (join) THEN Close — captures that
// write. Run under -race, a close-racing-the-write would also surface as a data
// race / use-after-close.
func TestServeResponseAuditsInFlightResponseDuringShutdown(t *testing.T) {
	cfg := runCfg(t)
	short, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	cfg.ResponseSocket = filepath.Join(short, "r.sock")
	if cfg.ResponseToken == "" {
		cfg.ResponseToken = "tok"
	}

	// A gate-able audit sink: the second audit write (the in-flight response's
	// RESULT line) blocks until we cancel ctx, modelling a response whose audit
	// write is still pending exactly as shutdown begins. The bytes must still be in
	// the file after the (post-join) close.
	gate := make(chan struct{})
	sink := &gatedAuditSink{gateAfter: 2, gate: gate, writeDone: make(chan struct{}), blocked: make(chan struct{})}
	guards := respond.DefaultGuards()
	guards.QuarantineDir = cfg.QuarantineDir
	r := respond.NewResponder(&respond.FakeExecutor{}, respond.NewAuditLog(sink), true, guards, time.Now)

	ctx, cancel := context.WithCancel(context.Background())
	var serveWG sync.WaitGroup
	if err := serveResponse(ctx, cfg, r, &serveWG); err != nil {
		t.Fatalf("serveResponse: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", cfg.ResponseSocket)
		},
	}, Timeout: 5 * time.Second}

	// Fire the in-flight request in a goroutine — its RESULT audit write blocks in
	// the handler (gatedAuditSink) until the gate releases. We deliberately do NOT
	// synchronize on the request completing before Close: the JOIN (serveWG.Wait)
	// must be the SOLE thing that guarantees the write lands before Close.
	go func() {
		body, _ := json.Marshal(respond.Request{Action: respond.ActionKill, Target: "4321"})
		req, _ := http.NewRequest(http.MethodPost, "http://unix/respond", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cfg.ResponseToken)
		if resp, derr := client.Do(req); derr == nil {
			_ = resp.Body.Close()
		}
	}()

	// Wait until the handler is BLOCKED inside its final audit write, then begin
	// shutdown — the classic close-before-last-write window. The handler is now
	// stuck mid-Respond; srv.Shutdown (inside respond.Serve) must drain it.
	sink.waitBlocked(t)
	cancel()
	// Release the blocked write a beat later, modelling the in-flight audit write
	// completing WHILE srv.Shutdown drains. Until this fires, respond.Serve cannot
	// return, so serveWG.Wait() below cannot return either.
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(gate)
	}()

	// cmdRun's ordering (FIX 3): JOIN the serve goroutine — serveWG.Wait blocks
	// until respond.Serve returns, which blocks until srv.Shutdown has drained the
	// (still-blocked) handler, which only finishes after the gate releases its audit
	// write. THEN close. So the in-flight write is captured BEFORE close. Without the
	// join, Close would race the still-draining write → writes-after-close.
	serveWG.Wait()
	if err := sink.Close(); err != nil {
		t.Errorf("audit close should succeed: %v", err)
	}
	// Settle: deterministically wait until the gated in-flight write has actually
	// RETURNED before asserting, so a close-before-write (buggy ordering) is
	// OBSERVABLE rather than racily missed. With the correct ordering this returns
	// immediately (the write already completed before Close).
	sink.waitWriteDone(t)
	if sink.WritesAfterClose() != 0 {
		t.Fatalf("UNAUDITED-ACTION HAZARD: %d audit writes landed AFTER close", sink.WritesAfterClose())
	}
	if sink.Writes() < 2 {
		t.Fatalf("in-flight response should be fully audited (intent+result): got %d writes", sink.Writes())
	}
	if sink.Closes() != 1 {
		t.Errorf("audit file must be closed EXACTLY once, got %d", sink.Closes())
	}
}

// gatedAuditSink is an io.WriteCloser audit sink that BLOCKS its Nth write until a
// gate channel closes (modelling an in-flight audit write during shutdown), and
// records whether any write arrives AFTER Close (the close-before-last-write
// hazard). It is concurrency-safe.
type gatedAuditSink struct {
	mu              sync.Mutex
	buf             bytes.Buffer
	writes          int
	closes          int
	closed          bool
	writesAfter     int
	gateAfter       int
	gate            chan struct{}
	blockedSignaled bool
	blocked         chan struct{}
	writeDone       chan struct{}
	writeDoneOnce   sync.Once
}

func (g *gatedAuditSink) Write(p []byte) (int, error) {
	g.mu.Lock()
	g.writes++
	n := g.writes
	if g.blocked == nil {
		g.blocked = make(chan struct{})
	}
	shouldBlock := n == g.gateAfter && g.gate != nil
	if shouldBlock && !g.blockedSignaled {
		g.blockedSignaled = true
		close(g.blocked)
	}
	g.mu.Unlock()

	if shouldBlock {
		<-g.gate // block until shutdown releases us (the in-flight window)
	}

	// COMMIT the bytes only now. For the gated write this is AFTER the gate
	// released, so if Close ran while we were blocked, closed==true here and the
	// write is correctly counted as landing AFTER close (the hazard).
	g.mu.Lock()
	if g.closed {
		g.writesAfter++
	}
	g.buf.Write(p)
	g.mu.Unlock()

	if shouldBlock {
		g.signalWriteDone()
	}
	return len(p), nil
}

func (g *gatedAuditSink) signalWriteDone() {
	g.writeDoneOnce.Do(func() { close(g.writeDone) })
}

func (g *gatedAuditSink) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closes++
	g.closed = true
	return nil
}

func (g *gatedAuditSink) waitBlocked(t *testing.T) {
	t.Helper()
	select {
	case <-g.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the in-flight audit write to block")
	}
}

func (g *gatedAuditSink) waitWriteDone(t *testing.T) {
	t.Helper()
	select {
	case <-g.writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the in-flight audit write to complete")
	}
}

func (g *gatedAuditSink) Writes() int { g.mu.Lock(); defer g.mu.Unlock(); return g.writes }
func (g *gatedAuditSink) Closes() int { g.mu.Lock(); defer g.mu.Unlock(); return g.closes }
func (g *gatedAuditSink) WritesAfterClose() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.writesAfter
}

// --- §E: cmdRun / cmdPreflight REFUSE canary/armed with the precondition list,
// and leave off/dry-run/shadow unaffected. ---

func TestCheckArmingGate(t *testing.T) {
	mkCfg := func(mode string) config.Config {
		c := config.Defaults()
		c.AutoResponseMode = mode
		return c
	}
	// Safe modes: no arming gate.
	for _, m := range []string{"off", "dry-run", "shadow", ""} {
		if err := checkArmingGate(mkCfg(m)); err != nil {
			t.Errorf("mode %q must pass the arming gate, got %v", m, err)
		}
	}
	// canary/armed: refused, with the precise precondition list.
	for _, m := range []string{"canary", "armed", "armed:quarantine"} {
		err := checkArmingGate(mkCfg(m))
		if err == nil {
			t.Fatalf("mode %q must be REFUSED by the arming gate", m)
		}
		msg := err.Error()
		if !strings.Contains(msg, "REFUSED") {
			t.Errorf("mode %q refusal should say REFUSED: %q", m, msg)
		}
		// The bridge→Respond wire, grace queue, and watchdog are BUILT this increment
		// and no longer deferred. The refusal must instead name a genuinely-unbuilt
		// rail (the authenticated Tetragon export). canary/armed stay refused.
		if !strings.Contains(msg, "authenticated gRPC/socket Tetragon export") {
			t.Errorf("mode %q refusal should name the unbuilt authenticated-export rail: %q", m, msg)
		}
	}
}

// Even with BOTH config gates satisfied (soak attestation present + grpc source),
// canary is STILL refused — the deferred safety mechanisms are unmet.
func TestCheckArmingGateStillRefusesWithConfigGatesSatisfied(t *testing.T) {
	dir := t.TempDir()
	attest := filepath.Join(dir, "soak.json")
	if err := os.WriteFile(attest, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := config.Defaults()
	c.AutoResponseMode = "canary"
	c.AutoResponseSoakAttested = attest
	c.TetragonSource = "grpc"
	err := checkArmingGate(c)
	if err == nil {
		t.Fatal("canary must STILL be refused even with config gates satisfied (deferred mechanisms unmet)")
	}
	msg := err.Error()
	// The satisfied gates must NOT be in the list; the unbuilt rails must be.
	if strings.Contains(msg, "AGENT_AUTORESPONSE_SOAK_ATTESTED") || strings.Contains(msg, "AGENT_TETRAGON_SOURCE") {
		t.Errorf("satisfied config gates should not be listed as missing: %q", msg)
	}
	// The two genuinely-unbuilt rails (console push + authenticated export) keep
	// canary refused after this increment (the bridge wire / grace / watchdog are
	// built and no longer deferred).
	if !strings.Contains(msg, "console push") {
		t.Errorf("the unbuilt console-push rail must still be listed: %q", msg)
	}
	if !strings.Contains(msg, "authenticated gRPC/socket Tetragon export") {
		t.Errorf("the unbuilt authenticated-export rail must still be listed: %q", msg)
	}
}

// TestCheckArmingGateRunsRealSoakValidator (M6) is the integration assertion that
// the §3 validator is WIRED into the runtime arm gate — not degraded to file-exists.
// A malformed / short / stale attestation must surface the §3 soak refusal REASON
// in checkArmingGate's output (proving the validator ran), while the two deferred
// rails keep canary refused (this does NOT un-gate).
func TestCheckArmingGateRunsRealSoakValidator(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "soak.json")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gen := func(d time.Duration) string { return time.Now().Add(d).Format(time.RFC3339) }
	valid := func() string {
		return `{"schema":"dsuite.soak.attestation/v1","duration_days":21,` +
			`"distinct_would_quarantine":0,"unexplained_fp":0,` +
			`"generated_at":"` + gen(-3*24*time.Hour) + `","host_class":"workstation"}`
	}

	cases := []struct {
		name    string
		content string
		want    string // a substring that proves the §3 validator (not file-exists) ran
	}{
		{"empty-object (all fields missing)", `{}`, "missing the required"},
		{"malformed json", `{not json`, "unparseable"},
		{"short duration", `{"schema":"dsuite.soak.attestation/v1","duration_days":3,` +
			`"distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen(-3*24*time.Hour) +
			`","host_class":"workstation"}`, "too short"},
		{"stale", `{"schema":"dsuite.soak.attestation/v1","duration_days":21,` +
			`"distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen(-90*24*time.Hour) +
			`","host_class":"workstation"}`, "stale"},
		{"future-dated", `{"schema":"dsuite.soak.attestation/v1","duration_days":21,` +
			`"distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen(72*time.Hour) +
			`","host_class":"workstation"}`, "FUTURE"},
		{"trailing decoy object", valid() + "\n" + valid(), "trailing data"},
		{"host-class mismatch", `{"schema":"dsuite.soak.attestation/v1","duration_days":21,` +
			`"distinct_would_quarantine":0,"unexplained_fp":0,"generated_at":"` + gen(-3*24*time.Hour) +
			`","host_class":"server"}`, "host_class"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Defaults()
			c.AutoResponseMode = "canary"
			c.AutoResponseSoakAttested = write(t, tc.content)
			c.AutoResponseHostClass = "workstation"
			c.TetragonSource = "grpc" // authenticated export satisfied, isolating the soak gate
			err := checkArmingGate(c)
			if err == nil {
				t.Fatal("canary must be REFUSED")
			}
			msg := err.Error()
			// The §3 validator REASON must appear (proving it ran, not file-exists).
			if !strings.Contains(msg, tc.want) {
				t.Errorf("the §3 soak refusal reason %q must appear in the arming output:\n%s", tc.want, msg)
			}
			// And this does NOT un-gate: the deferred rails still keep canary refused.
			if !strings.Contains(msg, "console push") || !strings.Contains(msg, "authenticated gRPC/socket Tetragon export") {
				t.Errorf("the two deferred rails must STILL keep canary refused:\n%s", msg)
			}
		})
	}

	// A FULLY-VALID attestation makes the soak reason DISAPPEAR (the validator passed),
	// yet canary is STILL refused by the two deferred rails — the gating invariant.
	t.Run("valid attestation: soak passes but rails still refuse", func(t *testing.T) {
		c := config.Defaults()
		c.AutoResponseMode = "canary"
		c.AutoResponseSoakAttested = write(t, valid())
		c.AutoResponseHostClass = "workstation"
		c.TetragonSource = "grpc"
		err := checkArmingGate(c)
		if err == nil {
			t.Fatal("canary must STILL be refused even with a valid soak (gating invariant)")
		}
		msg := err.Error()
		if strings.Contains(msg, "FP-soak") {
			t.Errorf("a VALID soak must not surface a soak refusal:\n%s", msg)
		}
		if !strings.Contains(msg, "console push") || !strings.Contains(msg, "authenticated gRPC/socket Tetragon export") {
			t.Errorf("the deferred rails must keep canary refused:\n%s", msg)
		}
	})
}

// cmdPreflight returns non-zero for canary/armed (the arming gate), 0-or-2 for a
// safe mode depending on host readiness — but never blocked by the auto gate.
func TestCmdPreflightRefusesCanary(t *testing.T) {
	t.Setenv("AGENT_AUTORESPONSE_MODE", "canary")
	if code := cmdPreflight([]string{"-format", "json"}); code == 0 {
		t.Fatal("cmdPreflight must return non-zero for a canary mode (arming gate)")
	}
}
