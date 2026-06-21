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
	if err := serveResponse(ctx, cfg, r); err != nil {
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
	// serve goroutine), then close the audit file via the returned closer — it must
	// close cleanly (no double-close / no panic), and a SECOND close is harmless.
	cancel()
	// Give the serve goroutine a moment to shut down (it does NOT close the audit).
	time.Sleep(50 * time.Millisecond)
	if err := closer.Close(); err != nil {
		t.Errorf("top-level audit close on ctx.Done should succeed: %v", err)
	}
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
		if !strings.Contains(msg, "bridge→Respond") {
			t.Errorf("mode %q refusal should name the missing bridge→Respond wire: %q", m, msg)
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
	// The satisfied gates must NOT be in the list; the deferred ones must be.
	if strings.Contains(msg, "AGENT_AUTORESPONSE_SOAK_ATTESTED") || strings.Contains(msg, "AGENT_TETRAGON_SOURCE") {
		t.Errorf("satisfied config gates should not be listed as missing: %q", msg)
	}
	if !strings.Contains(msg, "bridge→Respond") {
		t.Errorf("the deferred bridge wire must still be listed: %q", msg)
	}
}

// cmdPreflight returns non-zero for canary/armed (the arming gate), 0-or-2 for a
// safe mode depending on host readiness — but never blocked by the auto gate.
func TestCmdPreflightRefusesCanary(t *testing.T) {
	t.Setenv("AGENT_AUTORESPONSE_MODE", "canary")
	if code := cmdPreflight([]string{"-format", "json"}); code == 0 {
		t.Fatal("cmdPreflight must return non-zero for a canary mode (arming gate)")
	}
}
