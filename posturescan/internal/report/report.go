// Package report defines the finding and report types shared by every
// posturescan check, plus the two emit paths the design mandates: journald and a
// webhook.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Severity ranks a finding. A run is considered "clean" when nothing reaches
// Medium; Info/Low cover skipped checks and benign observations.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// MarshalJSON renders the severity as its lowercase name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses a lowercase severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for sev, n := range severityNames {
		if n == name {
			*s = sev
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", name)
}

// syslogPriority maps a severity to an sd-daemon priority prefix value so that
// journald assigns the right level when posturescan runs as a systemd unit.
func (s Severity) syslogPriority() int {
	switch s {
	case SeverityCritical:
		return 2 // crit
	case SeverityHigh:
		return 3 // err
	case SeverityMedium:
		return 4 // warning
	case SeverityLow:
		return 5 // notice
	default:
		return 6 // info
	}
}

// Finding is a single observation from one check.
type Finding struct {
	Check     string   `json:"check"`
	Severity  Severity `json:"severity"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail,omitempty"`
	Path      string   `json:"path,omitempty"`
	Technique string   `json:"technique,omitempty"` // MITRE ATT&CK ID
	Sigma     string   `json:"sigma,omitempty"`     // matching shipped Sigma rule
}

// Report is the full output of one posturescan run.
type Report struct {
	Tool     string    `json:"tool"`
	Host     string    `json:"host"`
	Time     time.Time `json:"time"`
	Distro   string    `json:"distro,omitempty"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
	// Posture carries the per-sysctl table and hardening index for this run.
	// It is omitted from findings-only reports (e.g. a tool wrapper run).
	Posture *Posture `json:"posture,omitempty"`
}

// Posture is the structured hardening result attached to a scan report: the
// per-sysctl OK/DIFFERENT table plus the before/after hardening index the
// DESIGN doc calls for.
type Posture struct {
	// HardeningIndex is the 0-100 posture score for this run ("before").
	HardeningIndex int `json:"hardening_index"`
	// TargetIndex is the score the host would reach with the target profile
	// applied ("after") — always 100 for a fully matching profile.
	TargetIndex int `json:"target_index"`
	// Sysctls is the OK/DIFFERENT table, one row per checked key.
	Sysctls []SysctlRow `json:"sysctls"`
}

// SysctlRow is one row of the per-key OK/DIFFERENT table.
type SysctlRow struct {
	Key     string `json:"key"`
	Want    string `json:"want"`
	Got     string `json:"got"`
	Status  string `json:"status"` // OK | DIFFERENT | UNKNOWN
	Comment string `json:"comment,omitempty"`
}

// Summary is a roll-up of the findings, used for journald/webhook and exit code.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	Worst      Severity       `json:"worst_severity"`
	Clean      bool           `json:"clean"`
}

// New builds a Report and computes its summary.
func New(tool, host, distro string, t time.Time, findings []Finding) Report {
	if findings == nil {
		findings = []Finding{}
	}
	r := Report{
		Tool:     tool,
		Host:     host,
		Time:     t,
		Distro:   distro,
		Findings: findings,
	}
	r.Summary = summarize(findings)
	return r
}

func summarize(findings []Finding) Summary {
	s := Summary{BySeverity: map[string]int{}, Worst: SeverityInfo, Clean: true}
	s.Total = len(findings)
	for _, f := range findings {
		s.BySeverity[f.Severity.String()]++
		if f.Severity > s.Worst {
			s.Worst = f.Severity
		}
	}
	s.Clean = s.Worst < SeverityMedium
	return s
}

// ExitCode is 0 when clean and 2 when any finding reaches Medium, signalling
// drift to a systemd OnFailure handler or a calling script.
func (r Report) ExitCode() int {
	if r.Summary.Clean {
		return 0
	}
	return 2
}

// sanitizeJournal strips control characters (newline, carriage return, tab and
// any byte below 0x20) from a value before it is written as a raw field in a
// journald line. Without this, attacker-controlled text — notably Path, which
// carries a container Name from `podman inspect` JSON — could embed a CR/LF and
// forge an extra journald record. Detail is rendered with %q (already escaped)
// and is left untouched.
func sanitizeJournal(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
}

// EmitJournal writes one sd-daemon-prefixed line per finding to w (stderr under
// systemd, where journald reads the "<N>" priority prefix), then a summary line.
func EmitJournal(w io.Writer, r Report) error {
	for _, f := range r.Findings {
		line := fmt.Sprintf("<%d>%s[%s] %s: %s", f.Severity.syslogPriority(), r.Tool, f.Check, f.Severity, sanitizeJournal(f.Title))
		if f.Path != "" {
			line += fmt.Sprintf(" path=%s", sanitizeJournal(f.Path))
		}
		if f.Technique != "" {
			line += fmt.Sprintf(" technique=%s", sanitizeJournal(f.Technique))
		}
		if f.Detail != "" {
			line += fmt.Sprintf(" detail=%q", f.Detail)
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	pri := 6
	if !r.Summary.Clean {
		pri = 4
	}
	_, err := fmt.Fprintf(w, "<%d>%s[summary] %d findings, worst=%s, clean=%t\n",
		pri, r.Tool, r.Summary.Total, r.Summary.Worst, r.Summary.Clean)
	return err
}

// EmitWebhook POSTs the report as JSON to url. A blank url is a no-op, keeping
// the webhook optional. authHeader, when set, is sent as the Authorization
// header; it is read from the environment, never baked into source.
func EmitWebhook(ctx context.Context, client *http.Client, url, authHeader string, r Report) error {
	if url == "" {
		return nil
	}
	if client == nil {
		client = http.DefaultClient
	}
	// Never follow redirects. The collector URL is fixed, so a 3xx is anomalous —
	// a compromised or spoofed collector could 302 us elsewhere to harvest the
	// auth token and the report (Go keeps the Authorization header across a
	// port-only redirect). Copy the client so the caller's is untouched; the 3xx
	// then surfaces as an error through the status check below.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client = &noRedirect
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "posturescan")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
