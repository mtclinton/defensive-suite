// Command credsentinel is a secret-exposure scanner and honeytoken tripwire for
// a Linux developer workstation. It has two halves (see DESIGN.md):
//
//   - scan: orchestrates gitleaks + TruffleHog (and a built-in stdlib fallback)
//     over repos, the home directory, and the exact files credential stealers
//     walk (.npmrc, .aws/credentials, .kube/config, SSH keys, Vault tokens, …).
//     A TruffleHog verified-live hit is a Critical "rotate now".
//
//   - deploy / watch: plants from-scratch honeytokens (a fake AWS key in
//     ~/.aws/credentials.bak, a decoy kubeconfig, a fake .env with a DNS-token
//     hostname), records each decoy's fingerprint + stat baseline, and detects a
//     decoy being read or modified — a near-zero-false-positive breach indicator.
//
// Findings go to journald (sd-daemon priority prefixes) and an optional webhook.
// Exit codes: 0 clean, 2 a finding at medium or above, 1 operational error.
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

	"github.com/mtclinton/defensive-suite/credsentinel/internal/config"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/honeytoken"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/report"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/runner"
	"github.com/mtclinton/defensive-suite/credsentinel/internal/scan"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "deploy":
		os.Exit(cmdDeploy(os.Args[2:]))
	case "watch", "check":
		os.Exit(cmdWatch(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("credsentinel", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "credsentinel: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `credsentinel — secret-exposure scanner + honeytoken tripwires

usage:
  credsentinel scan    [flags]   scan repos/home/stealer-targets for exposed creds
  credsentinel deploy  [flags]   plant honeytoken decoys and record their baseline
  credsentinel watch   [flags]   check deployed honeytokens for a trip (alias: check)
  credsentinel version           print version

scan flags:
  -config PATH       JSON config file (env CREDSENTINEL_* overrides it)
  -webhook URL       override webhook URL
  -roots LIST        comma-separated scan roots (repos/home), overrides config
  -home PATH         home dir the stealer-target list resolves against
  -no-targets        do not scan the exact stealer-target credential files
  -with-honeytokens  also fold the honeytoken watch into the scan report
  -format text|json  output format (default text)
  -no-webhook        do not POST to the webhook
  -timeout DUR       overall timeout (default 120s)

deploy flags:
  -config PATH       JSON config file
  -dir PATH          directory to plant decoys under (default: home)
  -manifest PATH     where to record the decoy manifest

watch flags:
  -config PATH       JSON config file
  -manifest PATH     decoy manifest to check against
  -webhook URL       override webhook URL
  -format text|json  output format (default text)
  -no-webhook        do not POST to the webhook

exit codes: 0 clean, 2 findings at medium or above, 1 operational error

env: CREDSENTINEL_WEBHOOK_URL, CREDSENTINEL_WEBHOOK_AUTH (token, env-only),
     CREDSENTINEL_SCAN_ROOTS, CREDSENTINEL_HOME, CREDSENTINEL_HONEYTOKEN_DIR,
     CREDSENTINEL_MANIFEST, CREDSENTINEL_CANARY_HOST (DNS-token host, env-only)
`)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	webhook := fs.String("webhook", "", "override webhook URL")
	roots := fs.String("roots", "", "comma-separated scan roots")
	home := fs.String("home", "", "home dir for stealer-target resolution")
	noTargets := fs.Bool("no-targets", false, "do not scan stealer-target files")
	withHoney := fs.Bool("with-honeytokens", false, "fold the honeytoken watch into the report")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	timeout := fs.Duration("timeout", 120*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credsentinel: config:", err)
		return 1
	}
	if *webhook != "" {
		cfg.WebhookURL = *webhook
	}
	if *roots != "" {
		cfg.ScanRoots = splitList(*roots)
	}
	if *home != "" {
		cfg.HomeDir = *home
	}
	if *noTargets {
		cfg.ScanTargets = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := scan.Run(ctx, cfg, runner.Exec{}, scan.Options{IncludeHoneytokenWatch: *withHoney})

	emit(ctx, cfg, rep, *noWebhook, *format)
	return rep.ExitCode()
}

func cmdDeploy(args []string) int {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	dir := fs.String("dir", "", "directory to plant decoys under (default: home)")
	manifest := fs.String("manifest", "", "where to record the decoy manifest")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credsentinel: config:", err)
		return 1
	}
	if *dir != "" {
		cfg.HoneytokenDir = *dir
	}
	if *manifest != "" {
		cfg.ManifestPath = *manifest
	}

	deployDir := cfg.ExpandHome(cfg.HoneytokenDir)
	manifestPath := cfg.ExpandHome(cfg.ManifestPath)
	host, _ := os.Hostname()

	canaryWoven := cfg.CanaryHost != ""
	decoys := honeytoken.Decoys(cfg.CanaryHost)
	m, errs := honeytoken.Deploy(deployDir, host, time.Now(), decoys, canaryWoven)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "credsentinel: deploy:", e)
	}
	if len(m.Decoys) == 0 {
		fmt.Fprintln(os.Stderr, "credsentinel: no decoys deployed")
		return 1
	}
	if err := honeytoken.SaveManifest(manifestPath, m); err != nil {
		fmt.Fprintln(os.Stderr, "credsentinel: save manifest:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "credsentinel: planted %d honeytokens under %s\n", len(m.Decoys), deployDir)
	for _, rec := range m.Decoys {
		fmt.Fprintf(os.Stderr, "  %-22s %s  sha256=%s\n", rec.Name, rec.Path, short(rec.SHA256))
	}
	fmt.Fprintf(os.Stderr, "credsentinel: manifest at %s — back it up off-host\n", manifestPath)
	if !canaryWoven {
		fmt.Fprintln(os.Stderr, "credsentinel: set CREDSENTINEL_CANARY_HOST to weave a self-hosted DNS token into the .env decoy")
	}
	fmt.Fprintln(os.Stderr, "credsentinel: ship deploy/audit/credsentinel-honeytokens.rules to add a kernel-level (auditd) trip — review before loading")
	return 0
}

func cmdWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	manifest := fs.String("manifest", "", "decoy manifest to check against")
	webhook := fs.String("webhook", "", "override webhook URL")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credsentinel: config:", err)
		return 1
	}
	if *manifest != "" {
		cfg.ManifestPath = *manifest
	}
	if *webhook != "" {
		cfg.WebhookURL = *webhook
	}

	manifestPath := cfg.ExpandHome(cfg.ManifestPath)
	host, _ := os.Hostname()

	m, err := honeytoken.LoadManifest(manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credsentinel: no honeytoken manifest at", manifestPath, "— run `credsentinel deploy` first")
		rep := report.New("credsentinel", host, "", time.Now(), []report.Finding{{
			Check: "honeytoken", Severity: report.SeverityInfo, Path: manifestPath,
			Title: "no honeytoken manifest; nothing to watch",
		}})
		ctx := context.Background()
		emit(ctx, cfg, rep, *noWebhook, *format)
		return rep.ExitCode()
	}

	findings := honeytoken.Watch(m)
	findings = append(findings, honeytoken.SummaryFinding(m, findings))
	rep := report.New("credsentinel", host, "", time.Now(), findings)

	ctx := context.Background()
	emit(ctx, cfg, rep, *noWebhook, *format)
	return rep.ExitCode()
}

// emit sends the report to journald, the optional webhook, and stdout.
func emit(ctx context.Context, cfg config.Config, rep report.Report, noWebhook bool, format string) {
	_ = report.EmitJournal(os.Stderr, rep)
	if !noWebhook {
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "credsentinel: webhook:", err)
		}
	}
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	default:
		printText(os.Stdout, rep)
	}
}

func printText(w io.Writer, rep report.Report) {
	fmt.Fprintf(w, "credsentinel report  host=%s  time=%s\n",
		rep.Host, rep.Time.Format(time.RFC3339))
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

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
