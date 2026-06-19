package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

func TestParsePackageJSONMergesDeps(t *testing.T) {
	pj, err := ParsePackageJSON([]byte(`{
		"name": "app", "version": "1.0.0",
		"dependencies": {"left-pad": "^1.0.0"},
		"devDependencies": {"jest": "^29.0.0"},
		"optionalDependencies": {"fsevents": "^2.0.0"},
		"peerDependencies": {"react": "^18.0.0"},
		"scripts": {"postinstall": "node x.js"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	deps := pj.AllDeps()
	for _, want := range []string{"left-pad", "jest", "fsevents"} {
		if _, ok := deps[want]; !ok {
			t.Errorf("AllDeps missing %q", want)
		}
	}
	// peerDependencies are advisory and must not be treated as installed.
	if _, ok := deps["react"]; ok {
		t.Error("peerDependencies should not be in AllDeps")
	}
	if pj.Scripts["postinstall"] != "node x.js" {
		t.Errorf("scripts not parsed: %v", pj.Scripts)
	}
}

func TestLockedVersionsModernPackagesMap(t *testing.T) {
	lock, err := ParsePackageLock([]byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/left-pad": {"version": "1.3.0"},
			"node_modules/@scope/pkg": {"version": "2.1.0"},
			"node_modules/a/node_modules/b": {"version": "0.0.1"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := lock.LockedVersions()
	if !hasVersion(got["left-pad"], "1.3.0") {
		t.Errorf("left-pad=%q", got["left-pad"])
	}
	if !hasVersion(got["@scope/pkg"], "2.1.0") {
		t.Errorf("@scope/pkg=%q", got["@scope/pkg"])
	}
	// Nested node_modules resolve to the innermost package name.
	if !hasVersion(got["b"], "0.0.1") {
		t.Errorf("nested b=%q", got["b"])
	}
	if _, ok := got[""]; ok {
		t.Error("root entry should be skipped")
	}
}

func TestLockedVersionsLegacyTree(t *testing.T) {
	lock, err := ParsePackageLock([]byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"left-pad": {"version": "1.3.0"},
			"jest": {"version": "29.7.0"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := lock.LockedVersions()
	if !hasVersion(got["left-pad"], "1.3.0") || !hasVersion(got["jest"], "29.7.0") {
		t.Errorf("legacy versions=%v", got)
	}
}

func TestDepNameFromPath(t *testing.T) {
	tests := map[string]string{
		"node_modules/left-pad":            "left-pad",
		"node_modules/@scope/pkg":          "@scope/pkg",
		"node_modules/a/node_modules/b":    "b",
		"node_modules/a/node_modules/@s/c": "@s/c",
		"":                                 "",
		"weird-no-marker":                  "",
	}
	for in, want := range tests {
		if got := depNameFromPath(in); got != want {
			t.Errorf("depNameFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDriftDeclaredButUnlocked(t *testing.T) {
	declared := map[string]string{"left-pad": "^1.0.0", "jest": "^29.0.0"}
	locked := map[string][]string{"jest": {"29.7.0"}} // left-pad missing
	f := Drift(declared, locked, true)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].Package != "left-pad" || f[0].Severity != report.SeverityHigh {
		t.Errorf("finding=%+v", f[0])
	}
}

func TestDriftNoLockfileWithDeps(t *testing.T) {
	f := Drift(map[string]string{"x": "1"}, nil, false)
	if len(f) != 1 || f[0].Severity != report.SeverityHigh {
		t.Errorf("missing-lock drift=%+v", f)
	}
}

func TestDriftNoLockfileNoDepsIsClean(t *testing.T) {
	if f := Drift(nil, nil, false); len(f) != 0 {
		t.Errorf("no deps, no lock should be clean: %+v", f)
	}
}

func TestDriftAllLockedIsClean(t *testing.T) {
	declared := map[string]string{"a": "1", "b": "2"}
	locked := map[string][]string{"a": {"1.0.0"}, "b": {"2.0.0"}, "c": {"3.0.0"}}
	if f := Drift(declared, locked, true); len(f) != 0 {
		t.Errorf("all declared locked should be clean (extra transitive c is fine): %+v", f)
	}
}

func TestCompetingLockfiles(t *testing.T) {
	if f := CompetingLockfiles(map[string]bool{"package-lock.json": true}); len(f) != 0 {
		t.Errorf("single lock should be clean: %+v", f)
	}
	f := CompetingLockfiles(map[string]bool{"package-lock.json": true, "yarn.lock": true})
	if len(f) != 1 || f[0].Severity != report.SeverityMedium {
		t.Errorf("two locks should flag medium: %+v", f)
	}
}

func TestScanFixture(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{
		"name": "app",
		"dependencies": {"left-pad": "^1.0.0", "lodash": "^4.0.0"}
	}`)
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}}
	}`)
	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ManifestFound || !res.LockFound {
		t.Fatalf("manifest=%v lock=%v", res.ManifestFound, res.LockFound)
	}
	if !hasVersion(res.Locked["lodash"], "4.17.21") {
		t.Errorf("locked=%v", res.Locked)
	}
	drift := 0
	for _, f := range res.Findings {
		if f.Package == "left-pad" && f.Check == "lockfile" {
			drift++
		}
	}
	if drift != 1 {
		t.Errorf("expected left-pad drift finding, findings=%+v", res.Findings)
	}
}

func TestScanMissingPackageJSON(t *testing.T) {
	res, err := Scan(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.ManifestFound {
		t.Error("manifest should not be found")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != report.SeverityInfo {
		t.Errorf("want single info finding, got %+v", res.Findings)
	}
}

func TestScanInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{ not json`)
	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != report.SeverityMedium {
		t.Errorf("invalid json should yield a medium finding: %+v", res.Findings)
	}
}

// Fix #1: two installed copies of the same package at different node_modules
// paths must NOT collapse to one version — both distinct versions have to be
// preserved so each is queried against OSV/cooldown.
func TestLockedVersionsKeepsDistinctVersionsForSameName(t *testing.T) {
	lock, err := ParsePackageLock([]byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app"},
			"node_modules/evil": {"version": "1.0.0"},
			"node_modules/foo/node_modules/evil": {"version": "6.6.6"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := lock.LockedVersions()
	vs := got["evil"]
	if len(vs) != 2 {
		t.Fatalf("expected 2 distinct versions of evil, got %v", vs)
	}
	// Sorted, deduplicated: both the clean and the poisoned nested copy survive.
	if vs[0] != "1.0.0" || vs[1] != "6.6.6" {
		t.Errorf("distinct versions not preserved/sorted: %v", vs)
	}
}

// Fix #1: a duplicate (same name AND same version at two paths) dedups to one.
func TestLockedVersionsDedupsIdenticalVersions(t *testing.T) {
	lock, err := ParsePackageLock([]byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {},
			"node_modules/dup": {"version": "2.0.0"},
			"node_modules/a/node_modules/dup": {"version": "2.0.0"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if vs := lock.LockedVersions()["dup"]; len(vs) != 1 || vs[0] != "2.0.0" {
		t.Errorf("identical versions should dedup to one: %v", vs)
	}
}

// Fix #2: the legacy (lockfileVersion 1) "dependencies" tree nests; a transitive
// package under a parent's own "dependencies" must be enumerated, not skipped.
func TestLockedVersionsLegacyNestedTransitive(t *testing.T) {
	lock, err := ParsePackageLock([]byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"top": {
				"version": "1.0.0",
				"dependencies": {
					"deep": {
						"version": "9.9.9",
						"dependencies": {
							"deeper": {"version": "0.0.7"}
						}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := lock.LockedVersions()
	if !hasVersion(got["top"], "1.0.0") {
		t.Errorf("top-level missing: %v", got)
	}
	if !hasVersion(got["deep"], "9.9.9") {
		t.Errorf("transitive 'deep' must be included: %v", got)
	}
	if !hasVersion(got["deeper"], "0.0.7") {
		t.Errorf("doubly-nested 'deeper' must be included: %v", got)
	}
}

// Fix #4: a package.json larger than the read cap degrades to a Medium finding
// instead of being loaded into memory / OOMing.
func TestScanOversizePackageJSONDegrades(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, maxManifestBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	mustWrite(t, filepath.Join(dir, "package.json"), string(big))
	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.ManifestFound {
		t.Error("oversize manifest should not be reported as parsed")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != report.SeverityMedium {
		t.Fatalf("oversize package.json should yield one Medium finding: %+v", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Title, "too large") {
		t.Errorf("finding should name the size cap: %+v", res.Findings[0])
	}
}

// Fix #4: an oversize package-lock.json degrades to a Medium finding, and the
// (validly small) manifest is still parsed.
func TestScanOversizeLockfileDegrades(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{"name":"app","dependencies":{"x":"^1.0.0"}}`)
	big := make([]byte, maxManifestBytes+1)
	for i := range big {
		big[i] = 'b'
	}
	mustWrite(t, filepath.Join(dir, "package-lock.json"), string(big))
	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ManifestFound {
		t.Error("the small manifest should still parse")
	}
	hit := false
	for _, f := range res.Findings {
		if f.Severity == report.SeverityMedium && strings.Contains(f.Title, "package-lock.json too large") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("oversize lockfile should yield a Medium 'too large' finding: %+v", res.Findings)
	}
	// The lock was refused, so its versions are empty.
	if len(res.Locked) != 0 {
		t.Errorf("oversize lock should not populate Locked: %v", res.Locked)
	}
}

func hasVersion(versions []string, want string) bool {
	for _, v := range versions {
		if v == want {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
