// Package report defines the finding and report types shared by every
// credsentinel check, plus the two emit paths the design mandates: journald and
// a webhook. It is copied unchanged from the suite's authwatch tool so the
// collector ingests one report shape across the whole defensive-suite.
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
// Medium; Info/Low cover skipped checks and unbaselined-but-benign observations.
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
// journald assigns the right level when credsentinel runs as a systemd unit.
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

// Report is the full output of one credsentinel run.
type Report struct {
	Tool     string    `json:"tool"`
	Host     string    `json:"host"`
	Time     time.Time `json:"time"`
	Distro   string    `json:"distro,omitempty"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
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

// ExitCode is 0 when clean and 2 when any finding reaches Medium, signalling a
// likely compromise to a systemd OnFailure handler or a calling script.
func (r Report) ExitCode() int {
	if r.Summary.Clean {
		return 0
	}
	return 2
}

// sanitize neutralizes log-forgery: a finding field (Title/Path/Technique) can
// carry attacker-controlled bytes — e.g. a decoy path or a scanned file name with
// an embedded CR/LF — which, written raw into a one-line-per-finding journal,
// would let an attacker inject a whole forged log line. Replace newlines, tabs,
// carriage returns and any other control byte (< 0x20) with a single space so one
// finding stays one line. Detail is exempt because EmitJournal writes it with %q,
// which already escapes control bytes.
func sanitize(s string) string {
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
		line := fmt.Sprintf("<%d>%s[%s] %s: %s", f.Severity.syslogPriority(), r.Tool, f.Check, f.Severity, sanitize(f.Title))
		if f.Path != "" {
			line += fmt.Sprintf(" path=%s", sanitize(f.Path))
		}
		if f.Technique != "" {
			line += fmt.Sprintf(" technique=%s", sanitize(f.Technique))
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
	req.Header.Set("User-Agent", "credsentinel")
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
