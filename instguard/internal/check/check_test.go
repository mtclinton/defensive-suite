package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/instguard/internal/config"
	"github.com/mtclinton/defensive-suite/instguard/internal/report"
	"github.com/mtclinton/defensive-suite/instguard/internal/runner"
	"github.com/mtclinton/defensive-suite/instguard/internal/verdict"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRunCleanProject(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"lodash":"^4.0.0"},"scripts":{"build":"tsc"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}, "node_modules/lodash":{"version":"4.17.21"}}}`,
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OfflineOSV = true // no network in this test

	fixed := time.Date(2026, 6, 19, 0, 0, 0, 0, time.UTC)
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{
		Clock: func() time.Time { return fixed },
	})
	if rep.Tool != "instguard" {
		t.Errorf("tool=%s", rep.Tool)
	}
	if !rep.Time.Equal(fixed) {
		t.Errorf("injected clock not used: %v", rep.Time)
	}
	if rep.Summary.Blocked != 0 {
		t.Errorf("clean project should have 0 blocked, got %d (%+v)", rep.Summary.Blocked, rep.Verdicts)
	}
	// lodash should get a SAFE verdict.
	for _, v := range rep.Verdicts {
		if v.Package == "lodash" && v.Decision != verdict.Safe {
			t.Errorf("lodash should be SAFE: %+v", v)
		}
	}
}

func TestRunDriftBlocks(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"left-pad":"^1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`,
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OfflineOSV = true
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{})
	if rep.Summary.Blocked == 0 {
		t.Errorf("declared-but-unlocked left-pad should produce a BLOCK: %+v", rep.Verdicts)
	}
}

func TestRunOSVMalBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "MAL-2025-1", "summary": "malicious"}},
		})
	}))
	defer srv.Close()

	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"poison":"^1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}, "node_modules/poison":{"version":"1.0.0"}}}`,
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OSVQueryURL = srv.URL

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{HTTP: srv.Client()})
	blockedPoison := false
	for _, v := range rep.Verdicts {
		if v.Package == "poison" && v.Decision == verdict.Block {
			blockedPoison = true
		}
	}
	if !blockedPoison {
		t.Errorf("MAL advisory should block 'poison': %+v", rep.Verdicts)
	}
}

// Fix #1: two installed copies of the same package at different node_modules
// paths must BOTH be queried against OSV. The poisoned nested copy (evil@6.6.6)
// has a MAL advisory; if the resolver collapsed it under the clean evil@1.0.0
// it would never be queried and the package would not BLOCK.
func TestRunOSVQueriesEveryDistinctVersion(t *testing.T) {
	var mu sync.Mutex
	queried := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		key := req.Package.Name + "@" + req.Version
		mu.Lock()
		queried[key] = true
		mu.Unlock()
		vulns := []map[string]any{}
		if key == "evil@6.6.6" { // only the poisoned nested copy is malicious
			vulns = append(vulns, map[string]any{"id": "MAL-2025-9", "summary": "malicious"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": vulns})
	}))
	defer srv.Close()

	dir := writeProject(t, map[string]string{
		"package.json": `{"name":"app","dependencies":{"evil":"^1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{
			"":{},
			"node_modules/evil":{"version":"1.0.0"},
			"node_modules/foo/node_modules/evil":{"version":"6.6.6"}
		}}`,
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OSVQueryURL = srv.URL

	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{HTTP: srv.Client()})

	mu.Lock()
	defer mu.Unlock()
	if !queried["evil@1.0.0"] {
		t.Errorf("clean copy evil@1.0.0 was not queried: %v", queried)
	}
	if !queried["evil@6.6.6"] {
		t.Errorf("poisoned nested copy evil@6.6.6 was not queried (collapsed!): %v", queried)
	}
	blocked := false
	for _, v := range rep.Verdicts {
		if v.Package == "evil" && v.Decision == verdict.Block {
			blocked = true
		}
	}
	if !blocked {
		t.Errorf("MAL advisory on the nested copy should BLOCK 'evil': %+v", rep.Verdicts)
	}
}

func TestRunOSVOfflineIsGraceful(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"x":"^1.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}, "node_modules/x":{"version":"1.0.0"}}}`,
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	// HTTP nil and OfflineOSV unset -> offline path.
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{})
	hasOSVInfo := false
	for _, f := range rep.Findings {
		if f.Check == "osv" && f.Severity == report.SeverityInfo {
			hasOSVInfo = true
		}
	}
	if !hasOSVInfo {
		t.Errorf("offline OSV should produce an Info skip, not crash: %+v", rep.Findings)
	}
}

func TestRunCooldownFresh(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name":"app","dependencies":{"fresh":"^9.0.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}, "node_modules/fresh":{"version":"9.9.9"}}}`,
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OfflineOSV = true
	now := time.Date(2026, 6, 19, 0, 0, 0, 0, time.UTC)
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{
		Clock:        func() time.Time { return now },
		ReleaseDates: map[string]time.Time{"fresh@9.9.9": now.Add(-12 * time.Hour)},
	})
	hit := false
	for _, f := range rep.Findings {
		if f.Check == "cooldown" && f.Package == "fresh" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("fresh release should trip the cooldown: %+v", rep.Findings)
	}
}

func TestRunAURObfuscatedNpm(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"PKGBUILD": "build() {\n  \\x6e\\x70\\x6d install evil\n}",
	})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OfflineOSV = true
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{})
	hit := false
	for _, f := range rep.Findings {
		if f.Check == "aur" && f.Severity == report.SeverityCritical {
			hit = true
		}
	}
	if !hit {
		t.Errorf("obfuscated npm in PKGBUILD should be critical: %+v", rep.Findings)
	}
}

func TestRunNPMAbsentIsInfo(t *testing.T) {
	dir := writeProject(t, map[string]string{"package.json": `{"name":"app"}`})
	cfg := config.Defaults()
	cfg.ProjectDir = dir
	cfg.OfflineOSV = true
	// Fake runner has no npm response -> ErrNotFound -> Info, not a crash.
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{})
	for _, f := range rep.Findings {
		if f.Check == "npm" && f.Severity != report.SeverityInfo {
			t.Errorf("npm absence should be Info: %+v", f)
		}
	}
}
