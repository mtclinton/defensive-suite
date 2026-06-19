// Package osv queries the OSV.dev vulnerability database for advisories on a
// pinned (package, version). The threat instguard cares most about is a
// malicious-package advisory — OSV ids prefixed "MAL-" (the OpenSSF malicious-
// packages feed) — which is what flags a Mastra/Shai-Hulud-style poisoned
// release. The HTTP client is injectable so it is tested with httptest and the
// whole package degrades gracefully (an Info finding, never a crash) with no
// network.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// Doer is the subset of *http.Client the client needs, so tests inject a
// transport (httptest) and offline callers inject nil to skip the network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client queries a single OSV endpoint. A nil HTTP doer means "offline": every
// query short-circuits to a graceful skip.
type Client struct {
	URL  string
	HTTP Doer
}

// queryRequest is the OSV /v1/query body for a versioned npm package.
type queryRequest struct {
	Version string         `json:"version"`
	Package packageElement `json:"package"`
}

type packageElement struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// queryResponse is the subset of the OSV response we read.
type queryResponse struct {
	Vulns []Vuln `json:"vulns"`
}

// Vuln is a single OSV advisory.
type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Modified string   `json:"modified"`
}

// IsMalicious reports whether an advisory is a malicious-package record. OSV
// uses the "MAL-" id prefix (and the same prefix can appear among aliases) for
// the OpenSSF malicious-packages feed.
func (v Vuln) IsMalicious() bool {
	if strings.HasPrefix(strings.ToUpper(v.ID), "MAL-") {
		return true
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "MAL-") {
			return true
		}
	}
	return false
}

// Query asks OSV about one npm (name, version). With no HTTP client it returns a
// nil slice and a nil error — offline is not a failure, it is a known limitation
// surfaced as an Info finding by the caller. A non-2xx or malformed response is
// an error the caller turns into a Low "query failed" finding.
func (c Client) Query(ctx context.Context, name, version string) ([]Vuln, error) {
	if c.HTTP == nil {
		return nil, nil
	}
	body, err := json.Marshal(queryRequest{
		Version: version,
		Package: packageElement{Name: name, Ecosystem: "npm"},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "instguard")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("osv query %s@%s: status %d", name, version, resp.StatusCode)
	}
	var qr queryResponse
	if err := json.Unmarshal(data, &qr); err != nil {
		return nil, fmt.Errorf("osv query %s@%s: %w", name, version, err)
	}
	return qr.Vulns, nil
}

// Findings turns an OSV result into instguard findings. A MAL- advisory is
// Critical (a known-malicious release — block it); any other advisory is Medium
// (a known vuln — review). A pinned set with no version is skipped upstream.
func Findings(name, version string, vulns []Vuln) []report.Finding {
	var findings []report.Finding
	for _, v := range vulns {
		if v.IsMalicious() {
			findings = append(findings, report.Finding{
				Check: "osv", Severity: report.SeverityCritical, Package: name,
				Title:     "OSV malicious-package advisory (MAL-) for pinned version",
				Detail:    fmt.Sprintf("%s@%s %s: %s", name, version, v.ID, oneLine(v.Summary)),
				Technique: "T1195.002",
			})
			continue
		}
		findings = append(findings, report.Finding{
			Check: "osv", Severity: report.SeverityMedium, Package: name,
			Title:     "OSV advisory for pinned version",
			Detail:    fmt.Sprintf("%s@%s %s: %s", name, version, v.ID, oneLine(v.Summary)),
			Technique: "T1195.001",
		})
	}
	return findings
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
