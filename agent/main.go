// Command agentd is the defensive-suite real-time agent (Phase 1, M1). It tails
// Tetragon's JSON event export, evaluates each event against observe-mode rules,
// and forwards the resulting findings to the collector. Detection only — no
// enforcement (that lives in Tetragon TracingPolicies, a later milestone).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/config"
	"github.com/mtclinton/defensive-suite/agent/internal/pipeline"
	"github.com/mtclinton/defensive-suite/agent/internal/preflight"
	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/respond"
	"github.com/mtclinton/defensive-suite/agent/internal/spool"
)

var version = "0.1.0"

func main() {
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch {
	case cmd == "version" || cmd == "-v" || cmd == "--version":
		fmt.Println("agentd", version)
	case cmd == "help" || cmd == "-h" || cmd == "--help":
		usage(os.Stdout)
	case cmd == "scan":
		os.Exit(cmdScan(args[1:]))
	case cmd == "preflight":
		os.Exit(cmdPreflight(args[1:]))
	case cmd == "run":
		os.Exit(cmdRun(args[1:]))
	case cmd == "" || strings.HasPrefix(cmd, "-"):
		os.Exit(cmdRun(args)) // bare flags → run
	default:
		fmt.Fprintf(os.Stderr, "agentd: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `agentd — defensive-suite real-time agent (observe mode)

usage:
  agentd run        [flags]   tail Tetragon's JSON export → findings → collector
  agentd scan       [flags]   evaluate a Tetragon JSON file once (for testing)
  agentd preflight  [flags]   READ-ONLY host-readiness check for arming enforcement
  agentd version

flags (env AGENT_* also apply):
  run:  -tetragon-log PATH   -collector URL
        -response-socket PATH   serve the manual-response API on a unix socket
        -enable-response        ACTUALLY perform actions (default OFF → dry-run)
  scan: -file PATH (- = stdin)  -collector URL  -no-post  -format text|json
  preflight: -post   also POST the readiness report to the collector
             -format text|json   (default text)
        Inspects host state (BTF, kernel config, nftables, fapolicyd, Tetragon,
        sockets, loaded policies) and reports whether enforcement can be armed.
        STRICTLY READ-ONLY: it loads no policy, enables no enforcement, and
        writes no rule. Arming is a documented, human-run step — see
        deploy/ENFORCE.md. Exit: 0 ready · 2 not-ready · 1 verifier error.

env: AGENT_TETRAGON_LOG, AGENT_COLLECTOR_URL, AGENT_COLLECTOR_AUTH (e.g. "Bearer …"),
     AGENT_HOST, AGENT_BPF_ALLOWLIST, AGENT_FLUSH_SECONDS,
     AGENT_RESPONSE_SOCKET, AGENT_RESPONSE_TOKEN, AGENT_ENABLE_RESPONSE,
     AGENT_MGMT_IFACES, AGENT_QUARANTINE_DIR

Manual response is OFF by default: without --enable-response (or
AGENT_ENABLE_RESPONSE) the responder stays in DRY-RUN and never touches the
system — it returns what it WOULD do, audited. Enabling it requires root and is
reviewed in deploy/RESPONSE.md before running on a real host.
`)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	file := fs.String("file", "-", "Tetragon JSON export to evaluate (- = stdin)")
	collector := fs.String("collector", "", "override collector URL")
	noPost := fs.Bool("no-post", false, "do not POST to the collector")
	format := fs.String("format", "text", "output format: text|json")
	_ = fs.Parse(args)

	cfg := config.Load(os.Getenv)
	if *collector != "" {
		cfg.CollectorURL = *collector
	}

	var r io.Reader = os.Stdin
	if *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "agentd:", err)
			return 1
		}
		defer f.Close()
		r = f
	}

	findings := pipeline.ProcessReader(r, cfg)
	rep := report.New("agent", cfg.Host, "", time.Now(), findings)

	if !*noPost && cfg.CollectorURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.CollectorURL, cfg.CollectorAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "agentd: collector:", err)
		}
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printText(os.Stdout, rep)
	}
	return rep.ExitCode()
}

// cmdPreflight runs the READ-ONLY host-readiness checks for arming enforcement
// and sets the exit code (0 ready / 2 not-ready / 1 error). It NEVER mutates the
// host: it builds the real (read-only) Runner/FS, probes state, prints a table
// (or JSON), and optionally POSTs the readiness report to the collector via the
// same EmitWebhook path scan/run use. No policy is loaded, no enforcement
// enabled, no rule written — arming is documented in deploy/ENFORCE.md.
func cmdPreflight(args []string) int {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	post := fs.Bool("post", false, "also POST the readiness report to the collector")
	collector := fs.String("collector", "", "override collector URL")
	format := fs.String("format", "text", "output format: text|json")
	_ = fs.Parse(args)

	cfg := config.Load(os.Getenv)
	if *collector != "" {
		cfg.CollectorURL = *collector
	}

	// Real, read-only implementations. Inputs with nil fields would also resolve
	// to these; we pass them explicitly for clarity.
	checks := preflight.Run(preflight.Inputs{
		Runner: preflight.RealRunner{},
		FS:     preflight.RealFS{},
		Getenv: os.Getenv,
	})
	rep := preflight.ToReport(cfg.Host, time.Now(), checks)

	if *post && cfg.CollectorURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.CollectorURL, cfg.CollectorAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "agentd: collector:", err)
		}
		cancel()
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	default:
		preflight.WriteTable(os.Stdout, checks)
	}
	return preflight.ExitCode(checks)
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	logPath := fs.String("tetragon-log", "", "override the Tetragon JSON export path")
	collector := fs.String("collector", "", "override collector URL")
	respSocket := fs.String("response-socket", "", "serve the manual-response API on this unix socket")
	enableResp := fs.Bool("enable-response", false, "ACTUALLY perform response actions (default off → dry-run)")
	_ = fs.Parse(args)

	cfg := config.Load(os.Getenv)
	if *logPath != "" {
		cfg.TetragonLog = *logPath
	}
	if *collector != "" {
		cfg.CollectorURL = *collector
	}
	if *respSocket != "" {
		cfg.ResponseSocket = *respSocket
	}
	// The flag can only ENABLE; it never disables what the env enabled. Either
	// source turning it on is sufficient (and still requires a token + root).
	if *enableResp {
		cfg.ResponseEnabled = true
	}

	buf := pipeline.NewBuffer(cfg.BufferMax)
	// The HTTP client timeout (15s) is deliberately BELOW the collector's 20s
	// WriteTimeout so a slow-but-alive collector isn't misread as a failed POST
	// (which would needlessly spool a report that actually got through).
	client := &http.Client{Timeout: 15 * time.Second}

	// Delivery spool: a failed POST persists the report under <state-dir>/spool/
	// instead of dropping it, and every flush replays the backlog oldest-first. A
	// nil spool (open failed) degrades to the old log-and-drop behaviour rather
	// than killing detection.
	var sp *spool.Spool
	spoolDir := filepath.Join(cfg.StateDir, "spool")
	if s, err := spool.New(spoolDir, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "<3>agentd: delivery spool NOT available: %v (failed POSTs will be dropped)\n", err)
	} else {
		sp = s
	}

	// postReport delivers one report to the collector with the spool-friendly POST
	// signature. A blank CollectorURL is treated as success (forwarding disabled —
	// nothing to spool/replay).
	postReport := func(data []byte) error {
		if cfg.CollectorURL == "" {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return report.EmitWebhookBytes(ctx, client, cfg.CollectorURL, cfg.CollectorAuth, data)
	}

	// run mode emits an event STREAM: each flush posts the findings drained since
	// the last flush, as an Append delta. The collector accumulates these, so
	// deltas the bounded buffer would later trim are not lost. agentd ALSO posts a
	// HEARTBEAT every flush even with zero new findings (an empty Append report) so
	// the collector's last-seen advances and a crash-looping/dead agent becomes
	// visible — a quiet healthy agent must not look the same as a dead one. If the
	// cap was hit within a window, some findings were trimmed before this flush —
	// warn (loudly, not silently) so the operator can raise the buffer/flush rate.
	flush := func() {
		if dropped := buf.Dropped(); dropped > 0 {
			fmt.Fprintf(os.Stderr,
				"<%d>agent[buffer] WARNING: dropped %d findings this window (buffer cap %d hit); raise BufferMax or flush more often\n",
				4, dropped, cfg.BufferMax)
		}
		pending := buf.Drain()
		rep := report.New("agent", cfg.Host, "", time.Now(), pending)
		rep.Append = true // always a delta; empty == heartbeat (no-op for findings)
		if len(pending) > 0 {
			_ = report.EmitJournal(os.Stderr, rep)
		}
		if cfg.CollectorURL == "" {
			return
		}
		// Replay any spooled backlog FIRST (oldest-first) so order is preserved: a
		// report spooled during an outage must reach the collector before this
		// fresh one. If replay fails the collector is still down — spool this report
		// too rather than attempting (and failing) a live POST.
		data, err := spool.MarshalReport(rep)
		if err != nil {
			fmt.Fprintln(os.Stderr, "agentd: marshal report:", err)
			return
		}
		if sp != nil {
			if _, rerr := sp.Replay(postReport); rerr != nil {
				fmt.Fprintln(os.Stderr, "agentd: collector (replay):", rerr)
				if werr := sp.Write(data); werr != nil {
					fmt.Fprintln(os.Stderr, "agentd: spool write:", werr)
				}
				return
			}
		}
		if err := postReport(data); err != nil {
			fmt.Fprintln(os.Stderr, "agentd: collector:", err)
			if sp != nil {
				if werr := sp.Write(data); werr != nil {
					fmt.Fprintln(os.Stderr, "agentd: spool write:", werr)
				}
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		t := time.NewTicker(cfg.FlushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				flush()
			}
		}
	}()

	if cfg.ResponseSocket != "" {
		if err := startResponse(ctx, cfg); err != nil {
			// A response-config problem must NEVER kill detection. Log loudly and
			// carry on tailing — previously this returned, so a misconfigured (or
			// defaulted) response socket silently aborted the whole detector.
			fmt.Fprintf(os.Stderr, "<3>agentd: response socket NOT served: %v (detection continues)\n", err)
		}
	}

	// Checkpoint the tail position under the state dir so a crash/restart resumes
	// where it left off (catch up on events written during downtime) instead of
	// jumping to EOF and skipping them — closing the blind window an attacker who
	// can OOM/crash agentd would otherwise get for free.
	statePath := filepath.Join(cfg.StateDir, "tail.state")
	fmt.Fprintf(os.Stderr, "agentd %s: tailing %s → %s (observe mode)\n",
		version, cfg.TetragonLog, orNone(cfg.CollectorURL))
	_ = pipeline.TailWithState(ctx, cfg.TetragonLog, statePath, time.Second, func(line string) {
		buf.Add(pipeline.EvalLine(line, cfg)...)
	})
	flush()
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "(no collector configured)"
	}
	return s
}

// startResponse stands up the manual-response unix socket and serves it for the
// lifetime of ctx. The Responder is built DRY-RUN unless cfg.ResponseEnabled is
// true, so by default it never touches the system. A missing response token is
// fatal: a privileged socket with no auth must not start.
func startResponse(ctx context.Context, cfg config.Config) error {
	if cfg.ResponseToken == "" {
		return fmt.Errorf("refusing to serve %s without AGENT_RESPONSE_TOKEN set", cfg.ResponseSocket)
	}

	// Append-only audit log next to the socket-owner's state dir.
	auditPath := filepath.Join(filepath.Dir(cfg.QuarantineDir), "response-audit.jsonl")
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		return fmt.Errorf("audit dir: %w", err)
	}
	auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}

	guards := respond.DefaultGuards()
	guards.MgmtIfaces = cfg.MgmtIfaces
	guards.QuarantineDir = cfg.QuarantineDir
	guards.SelfPID = os.Getpid()

	// The single safety gate: DryRun is the NEGATION of ResponseEnabled. With
	// ResponseEnabled=false (the default), DryRun=true → executor never runs.
	dryRun := !cfg.ResponseEnabled
	var exec respond.Executor
	if dryRun {
		// Dry-run never executes, but the interface needs a value; use the inert
		// fake so even a coding error can't reach the real one.
		exec = &respond.FakeExecutor{}
	} else {
		exec = respond.NewRealExecutor(guards)
	}

	r := respond.NewResponder(exec, respond.NewAuditLog(auditFile), dryRun, guards, time.Now)
	h := respond.NewHandler(r, cfg.ResponseToken, cfg.ResponseMaxBody)

	ln, err := respond.Listen(cfg.ResponseSocket)
	if err != nil {
		return err
	}

	mode := "DRY-RUN (no destructive action)"
	if !dryRun {
		mode = "ENABLED — actions are LIVE"
	}
	fmt.Fprintf(os.Stderr, "agentd: response socket %s serving (%s)\n", cfg.ResponseSocket, mode)

	go func() {
		if err := respond.Serve(ctx, ln, h, cfg.ResponseSocket); err != nil {
			fmt.Fprintln(os.Stderr, "agentd: response serve:", err)
		}
		_ = auditFile.Close()
	}()
	return nil
}

func printText(w io.Writer, rep report.Report) {
	fmt.Fprintf(w, "agent report  host=%s  time=%s\n", rep.Host, rep.Time.Format(time.RFC3339))
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "  (no findings)")
	} else {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, f := range rep.Findings {
			path := f.Path
			if path == "" {
				path = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", strings.ToUpper(f.Severity.String()), f.Check, f.Title, path)
		}
		_ = tw.Flush()
	}
	fmt.Fprintf(w, "summary: %d findings, worst=%s, clean=%t\n", rep.Summary.Total, rep.Summary.Worst, rep.Summary.Clean)
}
