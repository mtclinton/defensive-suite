package osv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

func TestIsMalicious(t *testing.T) {
	tests := []struct {
		v    Vuln
		want bool
	}{
		{Vuln{ID: "MAL-2024-0001"}, true},
		{Vuln{ID: "mal-2024-0002"}, true}, // case-insensitive
		{Vuln{ID: "GHSA-xxxx", Aliases: []string{"MAL-2025-9"}}, true},
		{Vuln{ID: "GHSA-xxxx", Aliases: []string{"CVE-2024-1"}}, false},
		{Vuln{ID: "CVE-2024-1234"}, false},
	}
	for _, tc := range tests {
		if got := tc.v.IsMalicious(); got != tc.want {
			t.Errorf("IsMalicious(%+v)=%v want %v", tc.v, got, tc.want)
		}
	}
}

func TestQueryReturnsMalAdvisory(t *testing.T) {
	var gotReq queryRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		_ = json.NewEncoder(w).Encode(queryResponse{Vulns: []Vuln{
			{ID: "MAL-2025-0042", Summary: "malicious code in poisoned-pkg"},
		}})
	}))
	defer srv.Close()

	c := Client{URL: srv.URL, HTTP: srv.Client()}
	vulns, err := c.Query(context.Background(), "poisoned-pkg", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if gotReq.Package.Name != "poisoned-pkg" || gotReq.Package.Ecosystem != "npm" || gotReq.Version != "1.2.3" {
		t.Errorf("request body=%+v", gotReq)
	}
	if len(vulns) != 1 || !vulns[0].IsMalicious() {
		t.Fatalf("vulns=%+v", vulns)
	}
	f := Findings("poisoned-pkg", "1.2.3", vulns)
	if len(f) != 1 || f[0].Severity != report.SeverityCritical {
		t.Errorf("MAL advisory should be critical: %+v", f)
	}
}

func TestQueryNonMalAdvisoryIsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(queryResponse{Vulns: []Vuln{{ID: "GHSA-aaaa-bbbb"}}})
	}))
	defer srv.Close()
	c := Client{URL: srv.URL, HTTP: srv.Client()}
	vulns, _ := c.Query(context.Background(), "x", "1.0.0")
	f := Findings("x", "1.0.0", vulns)
	if len(f) != 1 || f[0].Severity != report.SeverityMedium {
		t.Errorf("non-MAL advisory should be medium: %+v", f)
	}
}

func TestQueryNoVulnsIsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := Client{URL: srv.URL, HTTP: srv.Client()}
	vulns, err := c.Query(context.Background(), "safe", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(Findings("safe", "1.0.0", vulns)) != 0 {
		t.Error("clean package should produce no findings")
	}
}

func TestQueryOfflineNilClientIsGraceful(t *testing.T) {
	c := Client{URL: "http://unused", HTTP: nil}
	vulns, err := c.Query(context.Background(), "x", "1.0.0")
	if err != nil {
		t.Errorf("offline should not error: %v", err)
	}
	if vulns != nil {
		t.Errorf("offline should return nil vulns: %+v", vulns)
	}
}

func TestQueryHTTPErrorPropagates(t *testing.T) {
	c := Client{URL: "http://x", HTTP: doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: network unreachable")
	})}
	if _, err := c.Query(context.Background(), "x", "1.0.0"); err == nil {
		t.Error("network error should propagate so the caller logs a Low finding")
	}
}

func TestQueryBadStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := Client{URL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Query(context.Background(), "x", "1.0.0"); err == nil {
		t.Error("non-2xx should be an error")
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
