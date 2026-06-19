// Command bpfsentry is an offline eBPF-program enumerator and out-of-band memory
// forensics differ — the flagship of the defensive-suite. Its thesis: build at
// least one detection path that does NOT run on the (possibly compromised) live
// kernel, because an eBPF rootkit that hooks sys_bpf hides from every on-box
// tool including bpftool and eBPF EDR.
//
// Subcommands:
//
//	baseline  capture the early-boot allowlist of BPF programs to an off-host path
//	diff      enumerate live (bpftool) and diff vs the allowlist; optionally
//	          ingest an out-of-band enumeration (Volatility prog_idr walk) and
//	          report any program hidden from the live kernel — proof of an implant
//	status    report detection-coverage posture (agent/visibility status)
//	version   print version
//
// The default build is stdlib-only: the portable path shells out to
// `bpftool ... -j`. The deeper cilium/ebpf direct path is an artifact behind the
// `linux && ebpf` build tag. See DESIGN.md.
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

	"github.com/mtclinton/defensive-suite/bpfsentry/internal/baseline"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/config"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/enumerate"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/report"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/runner"
	"github.com/mtclinton/defensive-suite/bpfsentry/internal/status"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "baseline":
		os.Exit(cmdBaseline(os.Args[2:]))
	case "diff":
		os.Exit(cmdDiff(os.Args[2:]))
	case "status", "agent":
		os.Exit(cmdStatus(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("bpfsentry", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "bpfsentry: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `bpfsentry — offline eBPF-program enumerator + out-of-band memory differ

usage:
  bpfsentry baseline [flags]   capture the early-boot allowlist to an off-host path
  bpfsentry diff     [flags]   enumerate live + diff vs allowlist (and optional out-of-band view)
  bpfsentry status   [flags]   report detection-coverage / visibility posture
  bpfsentry version            print version

baseline flags:
  -config PATH       JSON config file (env BPFSENTRY_* overrides it)
  -bpftool PATH      bpftool executable (default: PATH lookup)
  -o PATH            output path (default: config baseline_path, else stdout)

diff flags:
  -config PATH       JSON config file
  -bpftool PATH      bpftool executable
  -baseline PATH     early-boot allowlist to diff against
  -oob PATH          out-of-band enumeration JSON (Volatility prog_idr walk) to
                     diverge the live view against; "-" reads stdin
  -webhook URL       override webhook URL
  -no-webhook        do not POST to the webhook
  -format text|json  output format (default text)
  -timeout DUR       overall timeout (default 60s)

status flags:
  -config PATH       JSON config file
  -bpftool PATH      bpftool executable
  -baseline PATH     early-boot allowlist path to probe
  -format text|json  output format (default text)

exit codes: 0 clean, 2 findings at medium or above, 1 operational error
`)
}

// loadConfig loads config and applies the common -bpftool / -baseline overrides.
func loadConfig(path, bpftool, baselinePath string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, err
	}
	if bpftool != "" {
		cfg.BPFToolPath = bpftool
	}
	if baselinePath != "" {
		cfg.BaselinePath = baselinePath
	}
	return cfg, nil
}

func cmdBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	bpftool := fs.String("bpftool", "", "bpftool executable")
	out := fs.String("o", "", "output path (default: config baseline_path, else stdout)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath, *bpftool, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "bpfsentry: config:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	inv, err := enumerate.Enumerate(ctx, runner.Exec{}, cfg.BPFToolPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bpfsentry: enumerate:", err)
		fmt.Fprintln(os.Stderr, "bpfsentry: the early-boot baseline must be captured on a live host with bpftool")
		return 1
	}

	host, _ := os.Hostname()
	b := baseline.Capture(host, time.Now(), inv)

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
		fmt.Fprintln(os.Stderr, "bpfsentry: save:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "bpfsentry: wrote early-boot allowlist of %d programs to %s\n", len(b.Entries), target)
	fmt.Fprintln(os.Stderr, "bpfsentry: store this on read-only/off-host media — it is the trust anchor")
	return 0
}

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	bpftool := fs.String("bpftool", "", "bpftool executable")
	baselinePath := fs.String("baseline", "", "early-boot allowlist path")
	oobPath := fs.String("oob", "", "out-of-band enumeration JSON ('-' for stdin)")
	webhook := fs.String("webhook", "", "override webhook URL")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	format := fs.String("format", "text", "output format: text|json")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath, *bpftool, *baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bpfsentry: config:", err)
		return 1
	}
	if *webhook != "" {
		cfg.WebhookURL = *webhook
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	host, _ := os.Hostname()
	var findings []report.Finding

	// Live enumeration via the portable path.
	live, enumErr := enumerate.Enumerate(ctx, runner.Exec{}, cfg.BPFToolPath)
	if enumErr != nil {
		findings = append(findings, report.Finding{
			Check: "enumerate", Severity: report.SeverityLow,
			Title:  "live BPF enumeration unavailable; cannot diff the live view",
			Detail: enumErr.Error(), Technique: "T1562.001",
		})
	}

	// Allowlist diff.
	if cfg.BaselinePath == "" {
		findings = append(findings, report.Finding{
			Check: "baseline", Severity: report.SeverityInfo,
			Title: "no early-boot allowlist configured; allowlist diff skipped",
		})
	} else if base, err := baseline.Load(cfg.BaselinePath); err != nil {
		findings = append(findings, report.Finding{
			Check: "baseline", Severity: report.SeverityLow,
			Title: "could not load early-boot allowlist", Detail: err.Error(),
		})
	} else if enumErr == nil {
		findings = append(findings, baseline.Diff(base, live, cfg.SuspiciousHelpers)...)
	}

	// Out-of-band divergence — the key thesis path.
	if *oobPath != "" {
		oob, err := loadOOB(*oobPath)
		if err != nil {
			findings = append(findings, report.Finding{
				Check: "divergence", Severity: report.SeverityLow,
				Title: "could not load out-of-band enumeration", Detail: err.Error(),
			})
		} else {
			// Run the DESIGN-mandated suspicious-helper scan against the
			// OUT-OF-BAND inventory itself — the can't-be-lied-to path. Divergence
			// only compares program-set membership, so without this an allowlisted,
			// live-visible program carrying a rootkit-primitive helper
			// (bpf_probe_write_user / bpf_override_return / bpf_send_signal) is
			// reported clean offline. forensics/oob_parser.py carries the helper
			// metadata through, so this mirrors the live helper scan in baseline.Diff.
			findings = append(findings, baseline.ScanHelpers(oob, cfg.SuspiciousHelpers)...)
			if enumErr != nil {
				findings = append(findings, report.Finding{
					Check: "divergence", Severity: report.SeverityLow,
					Title: "out-of-band view loaded but the live view is unavailable; cannot compute divergence",
				})
			} else {
				findings = append(findings, enumerate.DivergenceFromOOB(live, oob).Findings()...)
			}
		}
	}

	rep := report.New("bpfsentry", host, "", time.Now(), findings)

	_ = report.EmitJournal(os.Stderr, rep)
	if !*noWebhook {
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "bpfsentry: webhook:", err)
		}
	}
	emit(rep, *format)
	return rep.ExitCode()
}

func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	bpftool := fs.String("bpftool", "", "bpftool executable")
	baselinePath := fs.String("baseline", "", "early-boot allowlist path")
	format := fs.String("format", "text", "output format: text|json")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath, *bpftool, *baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bpfsentry: config:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	host, _ := os.Hostname()
	findings := status.Check(ctx, runner.Exec{}, status.Options{
		BPFToolPath:  cfg.BPFToolPath,
		BaselinePath: cfg.BaselinePath,
	})
	rep := report.New("bpfsentry", host, "", time.Now(), findings)
	_ = report.EmitJournal(os.Stderr, rep)
	emit(rep, *format)
	return rep.ExitCode()
}

// loadOOB reads an out-of-band enumeration JSON (the shape the forensics parser
// emits, identical to an Inventory) from a path or stdin ("-").
func loadOOB(path string) (enumerate.Inventory, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<24))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return enumerate.Inventory{}, err
	}
	var inv enumerate.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return enumerate.Inventory{}, err
	}
	if inv.Source == "" {
		inv.Source = "oob"
	}
	inv.Sort()
	return inv, nil
}

func emit(rep report.Report, format string) {
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
	fmt.Fprintf(w, "bpfsentry report  host=%s  time=%s\n",
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
