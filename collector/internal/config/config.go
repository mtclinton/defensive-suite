// Package config holds the collector's runtime settings, from built-in defaults
// overlaid with COLLECTOR_* environment variables. The ingest token is a secret
// and is read from the environment or a token file — never a command-line flag
// (which would be visible in the process table).
package config

import "strconv"

// Config is the collector's settings.
type Config struct {
	// Addr is the listen address. Defaults to loopback — bind to a private
	// (e.g. Tailscale) interface deliberately, never 0.0.0.0 on an untrusted net.
	Addr string
	// Token is the bearer token required to POST to /ingest. Empty = ingest
	// disabled (fail closed).
	Token string
	// DataDir holds the persisted report snapshot.
	DataDir string
	// RetentionDays drops reports older than this (0 = keep all).
	RetentionDays int
	// MaxReports caps the stored report count (0 = unlimited).
	MaxReports int
	// MaxBodyBytes bounds an ingest request body.
	MaxBodyBytes int64

	// --- M3 manual response (optional; off unless both are set) ---

	// AgentSocket is the agentd response unix socket the collector forwards to.
	// Empty = /api/respond is not enabled.
	AgentSocket string
	// ResponseToken is the bearer token required to POST /api/respond; env-only.
	// Empty = /api/respond fails closed.
	ResponseToken string
}

// Defaults returns a safe baseline: loopback-bound, 30-day retention.
func Defaults() Config {
	return Config{
		Addr:          "127.0.0.1:8787",
		DataDir:       "data",
		RetentionDays: 30,
		MaxReports:    5000,
		MaxBodyBytes:  4 << 20,
	}
}

// Load overlays COLLECTOR_* env vars on the defaults. getenv is injected so the
// precedence is unit-testable.
func Load(getenv func(string) string) Config {
	c := Defaults()
	if v := getenv("COLLECTOR_ADDR"); v != "" {
		c.Addr = v
	}
	if v := getenv("COLLECTOR_TOKEN"); v != "" {
		c.Token = v
	}
	if v := getenv("COLLECTOR_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := getenv("COLLECTOR_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.RetentionDays = n
		}
	}
	if v := getenv("COLLECTOR_MAX_REPORTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxReports = n
		}
	}
	if v := getenv("COLLECTOR_AGENT_SOCKET"); v != "" {
		c.AgentSocket = v
	}
	if v := getenv("COLLECTOR_RESPONSE_TOKEN"); v != "" {
		c.ResponseToken = v
	}
	return c
}
