// Command egresswatch gives per-process egress visibility and passive-backdoor
// detection for a Linux developer workstation. Its portable, stdlib-only core
// does two things: (1) a BPFDoor/Symbiote triage scan over /proc — flagging any
// process holding a raw/AF_PACKET (SOCK_RAW) socket, fileless executables,
// zero-byte mutex files, and threads blocked in packet_recvmsg, and escalating a
// raw socket to Critical only when corroborated by another marker; and (2) an
// expected-egress allowlist evaluation — flagging any observed outbound
// connection not on the allowlist (the OpenSnitch allow/deny model as data).
//
// /proc cannot reveal whether a BPF filter is actually attached to a socket;
// confirming that is the job of the eBPF magic-packet sensor (a kprobe on
// setsockopt+SO_ATTACH_FILTER). That sensor and the Falco/Suricata/Zeek rules
// ship under deploy/ and behind the `ebpf` build tag; the default build is
// stdlib-only. See DESIGN.md and deploy/README.md.
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

	"github.com/mtclinton/defensive-suite/egresswatch/internal/check"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/config"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/runner"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(cmdScan(os.Args[2:], check.Options{}))
	case "triage":
		os.Exit(cmdScan(os.Args[2:], check.Options{SkipEgress: true}))
	case "egress":
		os.Exit(cmdScan(os.Args[2:], check.Options{SkipTriage: true}))
	case "sensor":
		// Live eBPF magic-packet sensor. Real in `-tags ebpf` builds on Linux;
		// a stub explaining how to build it otherwise (see sensor_{ebpf,stub}.go).
		os.Exit(runSensor(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("egresswatch", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "egresswatch: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `egresswatch — per-process egress visibility + passive-backdoor detection

usage:
  egresswatch scan    [flags]   run both the BPFDoor triage and the egress check
  egresswatch triage  [flags]   run only the BPFDoor/Symbiote /proc triage scan
  egresswatch egress  [flags]   run only the egress-allowlist evaluation
  egresswatch sensor  [flags]   live eBPF magic-packet sensor (requires -tags ebpf, root)
  egresswatch version           print version

flags:
  -config PATH       JSON config file (env EGRESSWATCH_* overrides it)
  -webhook URL       override webhook URL
  -allowlist PATH    expected-egress allowlist JSON (CIDRs/hosts/ports)
  -proc PATH         /proc root to read (default /proc; for offline snapshots)
  -conn-source S     observed-conn source: proc | ss (default proc)
  -format text|json  output format (default text)
  -no-webhook        do not POST to the webhook
  -timeout DUR       overall timeout (default 60s)

exit codes: 0 clean, 2 findings at medium or above, 1 operational error
`)
}

func cmdScan(args []string, opts check.Options) int {
	name := "scan"
	switch {
	case opts.SkipEgress:
		name = "triage"
	case opts.SkipTriage:
		name = "egress"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	webhook := fs.String("webhook", "", "override webhook URL")
	allowlist := fs.String("allowlist", "", "expected-egress allowlist JSON")
	procDir := fs.String("proc", "", "/proc root to read")
	connSource := fs.String("conn-source", "", "observed-conn source: proc|ss")
	format := fs.String("format", "text", "output format: text|json")
	noWebhook := fs.Bool("no-webhook", false, "do not POST to the webhook")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "egresswatch: config:", err)
		return 1
	}
	if *webhook != "" {
		cfg.WebhookURL = *webhook
	}
	if *allowlist != "" {
		cfg.AllowlistPath = *allowlist
	}
	if *procDir != "" {
		cfg.ProcDir = *procDir
	}
	if *connSource != "" {
		cfg.ConnSource = strings.ToLower(*connSource)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := check.Run(ctx, cfg, runner.Exec{}, opts)

	// Always emit to journald (stderr under systemd reads the priority prefix).
	_ = report.EmitJournal(os.Stderr, rep)

	if !*noWebhook {
		client := &http.Client{Timeout: 15 * time.Second}
		if err := report.EmitWebhook(ctx, client, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
			fmt.Fprintln(os.Stderr, "egresswatch: webhook:", err)
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

func printText(w io.Writer, rep report.Report) {
	fmt.Fprintf(w, "egresswatch report  host=%s  time=%s\n",
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
