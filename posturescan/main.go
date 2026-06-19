// Command posturescan measures (and dry-run remediates) the kernel and
// container hardening posture the defensive-suite threat cluster turns on:
// kernel.unprivileged_bpf_disabled, kernel.yama.ptrace_scope (the
// ssh-keysign-pwn fix), kernel lockdown, kptr/dmesg restrict, module signing;
// plus a capabilities audit (stray CAP_BPF/CAP_SYS_ADMIN), a rootless-Podman
// posture score, and wrappers for Lynis / OpenSCAP / `systemd-analyze
// security`. It emits findings to journald and an optional webhook, and prints a
// before/after hardening index and the per-sysctl OK/DIFFERENT table.
//
// `posturescan remediate` is strictly DRY-RUN: it generates and PRINTS the
// /etc/sysctl.d drop-in and the `sysctl --system` command. It never writes to
// /etc, runs sysctl, or modifies the system. See DESIGN.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/mtclinton/defensive-suite/posturescan/internal/check"
	"github.com/mtclinton/defensive-suite/posturescan/internal/config"
	"github.com/mtclinton/defensive-suite/posturescan/internal/remediate"
	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/runner"
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
	case "remediate":
		os.Exit(cmdRemediate(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("posturescan", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "posturescan: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `posturescan — kernel & container hardening posture

usage:
  posturescan scan       [flags]   measure posture, emit to journald + webhook
  posturescan remediate  [flags]   DRY-RUN: print the sysctl.d drop-in + commands
  posturescan version              print version

scan flags:
  -config PATH       JSON config file (env POSTURESCAN_* overrides it)
  -webhook URL       override webhook URL
  -profile PATH      target sysctl profile (defaults to the built-in goal profile)
  -proc-sys PATH     /proc/sys-style root to read sysctls from (default /proc/sys)
  -spec PATH         container spec to audit/score (repeatable)
  -wrap-tools        also run lynis / oscap / systemd-analyze security
  -format text|json  output format (default text)
  -no-webhook        do not POST to the webhook
  -timeout DUR       overall timeout (default 60s)

remediate flags:
  -config PATH       JSON config file
  -profile PATH      target sysctl profile
  -proc-sys PATH     /proc/sys-style root to read current values from

remediate NEVER applies anything — it prints the drop-in and the commands to run.

exit codes: 0 clean, 2 drift at medium or above, 1 operational error
`)
}

// loadConfig applies the shared flags onto a loaded config.
func loadConfig(configPath, webhook, profile, procSys string, specs multiFlag) (config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return cfg, err
	}
	if webhook != "" {
		cfg.WebhookURL = webhook
	}
	if profile != "" {
		cfg.ProfilePath = profile
	}
	if procSys != "" {
		cfg.ProcSysRoot = procSys
	}
	if len(specs) > 0 {
		cfg.ContainerSpecs = append(cfg.ContainerSpecs, specs...)
	}
	return cfg, nil
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	webhook := fs.String("webhook", "", "override webhook URL")
	profile := fs.String("profile", "", "target sysctl profile path")
	procSys := fs.String("proc-sys", "", "/proc/sys-style root")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	wrapTools := fs.Bool("wrap-tools", false, "also run lynis / oscap / systemd-analyze")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	var specs multiFlag
	fs.Var(&specs, "spec", "container spec to audit/score (repeatable)")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath, *webhook, *profile, *procSys, specs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "posturescan: config:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := check.Run(ctx, cfg, runner.Exec{}, check.Options{WrapTools: *wrapTools})

	// Always emit to journald (stderr under systemd reads the priority prefix).
	_ = report.EmitJournal(os.Stderr, rep)

	if !*noWebhook {
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "posturescan: webhook:", err)
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

func cmdRemediate(args []string) int {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	profile := fs.String("profile", "", "target sysctl profile path")
	procSys := fs.String("proc-sys", "", "/proc/sys-style root")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath, "", *profile, *procSys, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "posturescan: config:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targets := check.Targets(cfg)
	rows, _ := check.SysctlRows(ctx, cfg, runner.Exec{}, targets)
	plan := remediate.BuildPlan(targets, rows, cfg.SysctlDropInPath, time.Now())

	// DRY RUN: print only. posturescan never writes the file or runs sysctl.
	fmt.Print(remediate.Render(plan))
	return 0
}

func printText(w io.Writer, rep report.Report) {
	fmt.Fprintf(w, "posturescan report  host=%s  distro=%s  time=%s\n",
		rep.Host, rep.Distro, rep.Time.Format(time.RFC3339))

	if rep.Posture != nil {
		fmt.Fprintf(w, "\nhardening index: %d/100 (before)  ->  %d/100 (target, after remediation)\n",
			rep.Posture.HardeningIndex, rep.Posture.TargetIndex)
		fmt.Fprintln(w, "\nsysctl posture table:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  STATUS\tKEY\tWANT\tGOT")
		for _, row := range rep.Posture.Sysctls {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", row.Status, row.Key, row.Want, row.Got)
		}
		_ = tw.Flush()
	}

	fmt.Fprintln(w, "\nfindings:")
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
				upper(f.Severity.String()), f.Check, f.Title, path)
		}
		_ = tw.Flush()
	}
	fmt.Fprintf(w, "\nsummary: %d findings, worst=%s, clean=%t\n",
		rep.Summary.Total, rep.Summary.Worst, rep.Summary.Clean)
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

// multiFlag collects a repeatable string flag (e.g. -spec a -spec b).
type multiFlag []string

func (m *multiFlag) String() string {
	if m == nil {
		return ""
	}
	return fmt.Sprint(strconv.Itoa(len(*m)) + " specs")
}

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
