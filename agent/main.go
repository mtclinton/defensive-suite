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
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/config"
	"github.com/mtclinton/defensive-suite/agent/internal/pipeline"
	"github.com/mtclinton/defensive-suite/agent/internal/report"
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
  agentd run   [flags]   tail Tetragon's JSON export → findings → collector
  agentd scan  [flags]   evaluate a Tetragon JSON file once (for testing)
  agentd version

flags (env AGENT_* also apply):
  run:  -tetragon-log PATH   -collector URL
  scan: -file PATH (- = stdin)  -collector URL  -no-post  -format text|json

env: AGENT_TETRAGON_LOG, AGENT_COLLECTOR_URL, AGENT_COLLECTOR_AUTH (e.g. "Bearer …"),
     AGENT_HOST, AGENT_BPF_ALLOWLIST, AGENT_FLUSH_SECONDS
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

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	logPath := fs.String("tetragon-log", "", "override the Tetragon JSON export path")
	collector := fs.String("collector", "", "override collector URL")
	_ = fs.Parse(args)

	cfg := config.Load(os.Getenv)
	if *logPath != "" {
		cfg.TetragonLog = *logPath
	}
	if *collector != "" {
		cfg.CollectorURL = *collector
	}

	buf := pipeline.NewBuffer(cfg.BufferMax)
	client := &http.Client{Timeout: 15 * time.Second}
	flush := func() {
		rep := report.New("agent", cfg.Host, "", time.Now(), buf.Snapshot())
		_ = report.EmitJournal(os.Stderr, rep)
		if cfg.CollectorURL != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := report.EmitWebhook(ctx, client, cfg.CollectorURL, cfg.CollectorAuth, rep); err != nil {
				fmt.Fprintln(os.Stderr, "agentd: collector:", err)
			}
			cancel()
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

	fmt.Fprintf(os.Stderr, "agentd %s: tailing %s → %s (observe mode)\n",
		version, cfg.TetragonLog, orNone(cfg.CollectorURL))
	_ = pipeline.Tail(ctx, cfg.TetragonLog, time.Second, func(line string) {
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
