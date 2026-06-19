// Command instguard is a supply-chain install-time guard for npm/AUR projects.
// It runs before `npm install` / an AUR build to catch the moment of maximum
// risk — code that executes at install time, before any import:
//
//   - lockfile drift between package.json and package-lock.json,
//   - dangerous install hooks (curl|sh, node -e, eval, base64/atob, TLS-off),
//   - OSV.dev MAL- (malicious-package) advisories on pinned versions,
//   - a release-age cooldown on too-fresh versions,
//   - unexpected/obfuscated npm/bun invocations in AUR PKGBUILD/.install/.hook.
//
// It emits a per-package SAFE/REVIEW/BLOCK verdict and findings to journald and
// an optional webhook. `instguard check` exits 1 on any BLOCK (a CI gate);
// `instguard audit` is a post-install pass over ~/.npm/_logs for hooks that ran.
// See DESIGN.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/mtclinton/defensive-suite/instguard/internal/auditlog"
	"github.com/mtclinton/defensive-suite/instguard/internal/check"
	"github.com/mtclinton/defensive-suite/instguard/internal/config"
	"github.com/mtclinton/defensive-suite/instguard/internal/report"
	"github.com/mtclinton/defensive-suite/instguard/internal/runner"
	"github.com/mtclinton/defensive-suite/instguard/internal/verdict"
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
	case "audit":
		os.Exit(cmdAudit(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("instguard", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "instguard: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `instguard — supply-chain install-time guard (npm / AUR)

usage:
  instguard check  [flags]   vet a project before install, emit verdicts
  instguard audit  [flags]   post-install pass over ~/.npm/_logs for hooks that ran
  instguard version          print version

check flags:
  -config PATH        JSON config file (env INSTGUARD_* overrides it)
  -project DIR        project directory to scan (default ".")
  -webhook URL        override webhook URL
  -osv-url URL        override the OSV.dev query endpoint
  -cooldown N         release-age cooldown in days (default 3)
  -release-meta PATH  JSON {"name@version":"RFC3339 publish date"} for the cooldown
  -format text|json   output format (default text)
  -no-webhook         do not POST to the webhook
  -offline            skip the OSV network query
  -timeout DUR        overall timeout (default 60s)

audit flags:
  -config PATH        JSON config file
  -logs DIR           npm logs dir (default $HOME/.npm/_logs)
  -format text|json   output format (default text)
  -no-webhook         do not POST to the webhook

exit codes:
  0  clean / SAFE
  1  operational error, OR (check only) one or more BLOCK verdicts — the CI gate
  2  a finding at medium or above (REVIEW-level supply-chain risk)
`)
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	project := fs.String("project", "", "project directory to scan")
	webhook := fs.String("webhook", "", "override webhook URL")
	osvURL := fs.String("osv-url", "", "override OSV.dev query endpoint")
	cooldown := fs.Int("cooldown", -1, "release-age cooldown in days")
	releaseMeta := fs.String("release-meta", "", "JSON map name@version -> publish date")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	offline := fs.Bool("offline", false, "skip the OSV network query")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instguard: config:", err)
		return 1
	}
	if *project != "" {
		cfg.ProjectDir = *project
	}
	if *webhook != "" {
		cfg.WebhookURL = *webhook
	}
	if *osvURL != "" {
		cfg.OSVQueryURL = *osvURL
	}
	if *cooldown >= 0 {
		cfg.CooldownDays = *cooldown
	}
	if *offline {
		cfg.OfflineOSV = true
	}

	releaseDates, err := loadReleaseMeta(*releaseMeta)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instguard: release-meta:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := check.Options{ReleaseDates: releaseDates}
	if !cfg.OfflineOSV {
		opts.HTTP = check.DefaultHTTPClient()
	}

	rep := check.Run(ctx, cfg, runner.Exec{}, opts)

	_ = report.EmitJournal(os.Stderr, rep)
	if !*noWebhook {
		client := check.DefaultHTTPClient()
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "instguard: webhook:", err)
		}
	}

	emit(os.Stdout, *format, rep)

	// CI gate: any BLOCK verdict fails the build with exit 1, taking precedence
	// over the medium-severity exit 2 so a hard block is unambiguous to CI.
	if verdict.AnyBlocked(rep.Verdicts) {
		return 1
	}
	return rep.ExitCode()
}

func cmdAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	logsDir := fs.String("logs", "", "npm logs directory")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instguard: config:", err)
		return 1
	}
	dir := auditlog.DefaultLogsDir(firstNonEmpty(*logsDir, cfg.NPMLogsDir))

	findings, err := auditlog.Scan(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "instguard: audit:", err)
		return 1
	}
	host, _ := os.Hostname()
	rep := report.New("instguard", host, "", time.Now(), findings, nil)

	_ = report.EmitJournal(os.Stderr, rep)
	if !*noWebhook {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		client := check.DefaultHTTPClient()
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "instguard: webhook:", err)
		}
	}

	emit(os.Stdout, *format, rep)
	return rep.ExitCode()
}

// loadReleaseMeta reads the optional release-metadata file: a JSON object mapping
// "name@version" to an RFC3339 publish timestamp. It is input to the pure
// cooldown comparison so instguard needs no registry network access to enforce
// the cooldown. A blank path yields a nil map (cooldown then skipped).
func loadReleaseMeta(path string) (map[string]time.Time, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(raw))
	for k, v := range raw {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("release-meta %q: %w", k, err)
		}
		out[k] = ts
	}
	return out, nil
}

func emit(w io.Writer, format string, rep report.Report) {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	default:
		printText(w, rep)
	}
}

func printText(w io.Writer, rep report.Report) {
	fmt.Fprintf(w, "instguard report  host=%s  time=%s\n", rep.Host, rep.Time.Format(time.RFC3339))

	if len(rep.Verdicts) > 0 {
		fmt.Fprintln(w, "verdicts:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, v := range rep.Verdicts {
			reason := "-"
			if len(v.Reasons) > 0 {
				reason = v.Reasons[0]
				if len(v.Reasons) > 1 {
					reason = fmt.Sprintf("%s (+%d more)", reason, len(v.Reasons)-1)
				}
			}
			ver := v.Version
			if ver == "" {
				ver = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", v.Decision, v.Package, ver, reason)
		}
		_ = tw.Flush()
	}

	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "  (no findings)")
	} else {
		fmt.Fprintln(w, "findings:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, f := range rep.Findings {
			ctx := f.Package
			if ctx == "" {
				ctx = f.Path
			}
			if ctx == "" {
				ctx = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", upper(f.Severity.String()), f.Check, f.Title, ctx)
		}
		_ = tw.Flush()
	}
	fmt.Fprintf(w, "summary: %d findings, worst=%s, blocked=%d, clean=%t\n",
		rep.Summary.Total, rep.Summary.Worst, rep.Summary.Blocked, rep.Summary.Clean)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}
