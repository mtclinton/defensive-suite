// Command collector is the defensive-suite aggregator: the tools POST their
// Report JSON to /ingest (the collector contract the README describes), it
// stores them with retention, and serves the dashboard with live, local data.
// Bind it to a private interface (loopback by default, or Tailscale) — never to
// an untrusted network.
package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mtclinton/defensive-suite/collector/internal/config"
	"github.com/mtclinton/defensive-suite/collector/internal/server"
	"github.com/mtclinton/defensive-suite/collector/internal/store"
)

//go:embed web/index.html
var dashboardHTML []byte

var version = "0.1.0"

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "version", "-v", "--version":
			fmt.Println("collector", version)
			return
		case "serve":
			args = args[1:]
		}
	}

	cfg := config.Load(os.Getenv)
	fs := flag.NewFlagSet("collector", flag.ExitOnError)
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address — bind to a private/Tailscale interface")
	fs.StringVar(&cfg.DataDir, "data", cfg.DataDir, "directory for the persisted report snapshot")
	fs.IntVar(&cfg.RetentionDays, "retention-days", cfg.RetentionDays, "drop reports older than N days (0=keep all)")
	fs.IntVar(&cfg.MaxReports, "max-reports", cfg.MaxReports, "cap stored reports (0=unlimited)")
	tokenFile := fs.String("token-file", "", "read the ingest bearer token from this file (preferred over COLLECTOR_TOKEN)")
	_ = fs.Parse(args)

	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("collector: token-file: %v", err)
		}
		cfg.Token = strings.TrimSpace(string(b))
	}

	st, err := store.New(cfg.DataDir, time.Duration(cfg.RetentionDays)*24*time.Hour, cfg.MaxReports)
	if err != nil {
		log.Fatalf("collector: store: %v", err)
	}

	srv := server.New(st, cfg.Token, cfg.MaxBodyBytes, dashboardHTML)
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if cfg.Token == "" {
		log.Print("collector: WARNING — ingest is DISABLED; set COLLECTOR_TOKEN or --token-file to accept reports")
	}
	log.Printf("collector %s listening on http://%s  (dashboard /, ingest /ingest, api /api/*)", version, cfg.Addr)

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("collector: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Print("collector: shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
}
