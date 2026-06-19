// Command authwatch is a scheduled integrity-and-anomaly checker for the Linux
// trust path: PAM modules, OpenSSH, authorized_keys, ld.so.preload, and the
// QLNX fake-X11-lockfile pattern. It verifies auth binaries against package
// checksums, diffs them against an off-host baseline, and emits findings to
// journald and an optional webhook. See DESIGN.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mtclinton/defensive-suite/authwatch/internal/baseline"
	"github.com/mtclinton/defensive-suite/authwatch/internal/check"
	"github.com/mtclinton/defensive-suite/authwatch/internal/config"
	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		os.Exit(cmdCheck(os.Args[2:]))
	case "baseline":
		os.Exit(cmdBaseline(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("authwatch", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "authwatch: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `authwatch — Linux trust-path integrity checker

usage:
  authwatch check     [flags]   run all checks, emit to journald + webhook
  authwatch baseline  [flags]   capture an off-host hash baseline of auth files
  authwatch version             print version

check flags:
  -config PATH       JSON config file (env AUTHWATCH_* overrides it)
  -webhook URL       override webhook URL
  -baseline PATH     override off-host baseline path
  -allowlist PATH    override authorized_keys allowlist path
  -format text|json  output format (default text)
  -no-webhook        do not POST to the webhook
  -aide              also run `+"`aide --check`"+`
  -timeout DUR       overall timeout (default 60s)

exit codes: 0 clean, 2 findings at medium or above, 1 operational error
`)
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	webhook := fs.String("webhook", "", "override webhook URL")
	baselinePath := fs.String("baseline", "", "override off-host baseline path")
	allowlist := fs.String("allowlist", "", "override authorized_keys allowlist path")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	runAIDE := fs.Bool("aide", false, "also run aide --check")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "authwatch: config:", err)
		return 1
	}
	if *webhook != "" {
		cfg.WebhookURL = *webhook
	}
	if *baselinePath != "" {
		cfg.BaselinePath = *baselinePath
	}
	if *allowlist != "" {
		cfg.AllowlistPath = *allowlist
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := check.Run(ctx, cfg, runner.Exec{}, check.Options{RunAIDE: *runAIDE})

	// Always emit to journald (stderr under systemd reads the priority prefix).
	_ = report.EmitJournal(os.Stderr, rep)

	if !*noWebhook {
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "authwatch: webhook:", err)
		}
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	default:
		printText(os.Stdout, rep)
	}
	return rep.ExitCode()
}

func cmdBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	out := fs.String("o", "", "output path (default: config baseline_path, else stdout)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "authwatch: config:", err)
		return 1
	}
	host, _ := os.Hostname()
	b := baseline.Capture(host, time.Now(), check.AuthCriticalPaths(cfg))

	target := *out
	if target == "" {
		target = cfg.BaselinePath
	}
	if target == "" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(b)
		return 0
	}
	if err := b.Save(target); err != nil {
		fmt.Fprintln(os.Stderr, "authwatch: save:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "authwatch: wrote baseline of %d files to %s\n", len(b.Entries), target)
	fmt.Fprintln(os.Stderr, "authwatch: store this on read-only/off-host media — it is the trust anchor")
	return 0
}

func printText(w io.Writer, rep report.Report) {
	fmt.Fprintf(w, "authwatch report  host=%s  distro=%s  time=%s\n",
		rep.Host, rep.Distro, rep.Time.Format(time.RFC3339))
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "  (no findings)")
	} else {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, f := range rep.Findings {
			path := f.Path
			if path == "" {
				path = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
				strings.ToUpper(f.Severity.String()), f.Check, f.Title, path)
		}
		_ = tw.Flush()
	}
	fmt.Fprintf(w, "summary: %d findings, worst=%s, clean=%t\n",
		rep.Summary.Total, rep.Summary.Worst, rep.Summary.Clean)
}
