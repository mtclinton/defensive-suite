//go:build linux && ebpf

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mtclinton/defensive-suite/egresswatch/bpf"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/config"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
)

// runSensor loads the eBPF magic-packet sensor and streams an event to journald
// (and optionally the webhook) every time a process attaches a CBPF filter to a
// socket via setsockopt(SO_ATTACH_FILTER) — the BPFDoor/Symbiote signature. It
// is only compiled with `-tags ebpf` on Linux; the default build ships the stub.
func runSensor(args []string) int {
	fs := flag.NewFlagSet("sensor", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file")
	noWebhook := fs.Bool("no-webhook", false, "do not POST events to the webhook")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "egresswatch: config:", err)
		return 1
	}

	sensor, err := bpf.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "egresswatch: load sensor (need root + BTF kernel):", err)
		return 1
	}
	defer sensor.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	host, _ := os.Hostname()
	fmt.Fprintln(os.Stderr, "<6>egresswatch[sensor] magic-packet sensor active (setsockopt+SO_ATTACH_FILTER)")

	err = sensor.Run(ctx, func(e bpf.Event) {
		f := report.Finding{
			Check: "sensor", Severity: report.SeverityHigh,
			Title: "process attached a CBPF filter to a socket (BPFDoor signature)",
			Detail: fmt.Sprintf("pid=%d uid=%d comm=%q optname=%d family=%d",
				e.PID, e.UID, e.CommString(), e.Optname, e.Family),
			Technique: "T1205.002", Rule: "egresswatch-magic-packet",
		}
		rep := report.New("egresswatch", host, time.Now(), []report.Finding{f})
		_ = report.EmitJournal(os.Stderr, rep)
		if !*noWebhook {
			c := &http.Client{Timeout: 15 * time.Second}
			if err := report.EmitWebhook(ctx, c, cfg.WebhookURL, cfg.WebhookAuth, rep); err != nil {
				fmt.Fprintln(os.Stderr, "egresswatch: webhook:", err)
			}
		}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "egresswatch: sensor:", err)
		return 1
	}
	return 0
}
