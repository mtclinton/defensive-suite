// Package lockfile parses package.json and the npm package-lock.json and diffs
// the two. A dependency declared in package.json but missing from the lock (or
// resolved in the lock but undeclared) is the gap a payload lives in: an install
// that silently pulls — or pins — a package the manifest never named. It also
// flags the ambiguity of multiple competing lockfiles (yarn.lock / pnpm-lock).
//
// All parsing is pure and operates on bytes/strings so it is exhaustively table
// tested; the only filesystem touch is Scan, which reads the files and delegates.
package lockfile

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// maxManifestBytes bounds package.json / package-lock.json reads so a hostile or
// runaway manifest can't OOM the scan. 4 MiB is far above any real lockfile yet
// caps the worst case; consistent with the readLimited cap in the check package
// and the io.LimitReader bounds in osv.go/report.go.
const maxManifestBytes = 4 << 20

// PackageJSON is the subset of package.json instguard cares about.
type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Scripts              map[string]string `json:"scripts"`
}

// AllDeps merges the dependency maps that npm install actually resolves and
// installs (peer deps are advisory and excluded). The boolean reports whether
// any were present.
func (p PackageJSON) AllDeps() map[string]string {
	out := map[string]string{}
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDependencies} {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// ParsePackageJSON parses package.json bytes.
func ParsePackageJSON(b []byte) (PackageJSON, error) {
	var p PackageJSON
	err := json.Unmarshal(b, &p)
	return p, err
}

// PackageLock is the subset of package-lock.json instguard needs. Both the
// modern lockfileVersion>=2 "packages" map (keyed by install path, e.g.
// "node_modules/left-pad") and the legacy "dependencies" tree are parsed so the
// drift diff works across npm versions.
type PackageLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]LockPackage     `json:"packages"`
	Dependencies    map[string]LockLegacyEntry `json:"dependencies"`
}

// LockPackage is one entry in the modern "packages" map.
type LockPackage struct {
	Version string `json:"version"`
}

// LockLegacyEntry is one entry in the legacy "dependencies" tree. The tree
// nests: a package's own resolved dependencies sit under its "dependencies"
// key (this is how lockfileVersion 1 represents a transitive install at a
// distinct node_modules path). Walking the nesting is what lets a poisoned
// transitive copy still be OSV/cooldown-checked instead of being silently
// skipped because only top-level names were enumerated.
type LockLegacyEntry struct {
	Version      string                     `json:"version"`
	Dependencies map[string]LockLegacyEntry `json:"dependencies"`
}

// ParsePackageLock parses package-lock.json bytes.
func ParsePackageLock(b []byte) (PackageLock, error) {
	var l PackageLock
	err := json.Unmarshal(b, &l)
	return l, err
}

// LockedVersions flattens the lock into a name->versions map. The value is the
// set of DISTINCT versions resolved for that package name, sorted and
// deduplicated. Keying by name alone (and storing a single version) would
// collapse two installed copies of the same package at different paths — e.g.
// node_modules/evil@1.0.0 and node_modules/foo/node_modules/evil@6.6.6 — into one
// nondeterministic version, so a poisoned nested copy would silently skip the
// OSV/cooldown queries. Preserving every distinct version means every (name,
// version) actually installed is checked.
//
// The modern "packages" map wins when present (it is authoritative for
// lockfileVersion>=2); the root entry ("" key) is skipped, and the node_modules/
// prefix is stripped. Otherwise the legacy "dependencies" tree is walked
// recursively so transitive (nested) packages are included too.
func (l PackageLock) LockedVersions() map[string][]string {
	set := map[string]map[string]struct{}{}
	add := func(name, version string) {
		if name == "" {
			return
		}
		if set[name] == nil {
			set[name] = map[string]struct{}{}
		}
		set[name][version] = struct{}{}
	}

	if len(l.Packages) > 0 {
		for path, p := range l.Packages {
			if path == "" {
				continue // the project root, not a dependency
			}
			add(depNameFromPath(path), p.Version)
		}
	} else {
		walkLegacy(l.Dependencies, add)
	}

	out := make(map[string][]string, len(set))
	for name, versions := range set {
		vs := make([]string, 0, len(versions))
		for v := range versions {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		out[name] = vs
	}
	return out
}

// walkLegacy recurses the legacy dependencies tree, emitting every (name,
// version) it encounters — including transitive packages nested under a
// parent's own "dependencies" — so they are not skipped from OSV/cooldown.
func walkLegacy(deps map[string]LockLegacyEntry, add func(name, version string)) {
	for name, e := range deps {
		add(name, e.Version)
		if len(e.Dependencies) > 0 {
			walkLegacy(e.Dependencies, add)
		}
	}
}

// depNameFromPath turns "node_modules/@scope/pkg/node_modules/inner" into
// "inner" — the last node_modules segment names the installed package, which is
// what a (name, version) advisory query keys on.
func depNameFromPath(path string) string {
	const marker = "node_modules/"
	idx := -1
	// Find the last occurrence of the node_modules/ marker.
	for i := 0; i+len(marker) <= len(path); i++ {
		if path[i:i+len(marker)] == marker {
			idx = i + len(marker)
		}
	}
	if idx < 0 {
		return ""
	}
	return path[idx:]
}

// Drift compares declared dependencies (from package.json) against the resolved
// lock. It returns one finding per declared-but-unlocked package (High: the
// install will resolve something the lock never pinned) and is the core of the
// "gap a payload lives in" check. Undeclared-but-locked transitive packages are
// normal (they are dependencies-of-dependencies) and are not flagged here.
func Drift(declared map[string]string, locked map[string][]string, lockPresent bool) []report.Finding {
	var findings []report.Finding
	if !lockPresent {
		if len(declared) == 0 {
			return findings
		}
		return []report.Finding{{
			Check: "lockfile", Severity: report.SeverityHigh,
			Title:     "package.json declares dependencies but no package-lock.json is present",
			Detail:    "without a lockfile every install re-resolves versions; pin with `npm ci` against a committed lock",
			Technique: "T1195.001",
		}}
	}
	names := sortedKeys(declared)
	for _, name := range names {
		if _, ok := locked[name]; !ok {
			findings = append(findings, report.Finding{
				Check: "lockfile", Severity: report.SeverityHigh, Package: name,
				Title:     "dependency declared in package.json but absent from package-lock.json",
				Detail:    "lockfile drift: the install resolves this package fresh, outside the pinned set — the gap a payload lives in",
				Technique: "T1195.001",
			})
		}
	}
	return findings
}

// CompetingLockfiles flags the ambiguity of more than one package manager's
// lockfile coexisting (npm + yarn + pnpm): the manager actually run decides what
// installs, and the others drift silently. present maps a lockfile basename to
// whether it exists.
func CompetingLockfiles(present map[string]bool) []report.Finding {
	var found []string
	for _, name := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if present[name] {
			found = append(found, name)
		}
	}
	if len(found) <= 1 {
		return nil
	}
	return []report.Finding{{
		Check: "lockfile", Severity: report.SeverityMedium,
		Title:  "multiple competing lockfiles present",
		Detail: "found " + joinComma(found) + "; only the manager actually run is authoritative, the others drift unenforced",
	}}
}

// Result bundles what Scan found so the orchestrator and verdict layer can reuse
// the already-parsed manifest (scripts, deps) without re-reading files.
type Result struct {
	Manifest      PackageJSON
	ManifestFound bool
	LockFound     bool
	Locked        map[string][]string // name -> sorted, distinct resolved versions
	Findings      []report.Finding
}

// Scan reads package.json and package-lock.json from dir, runs the drift and
// competing-lockfile checks, and returns the parsed manifest for downstream use.
// A missing package.json yields an Info finding (nothing to guard) and no error.
func Scan(dir string) (Result, error) {
	res := Result{Locked: map[string][]string{}}

	pjPath := filepath.Join(dir, "package.json")
	pjBytes, overflow, err := readBounded(pjPath, maxManifestBytes)
	if err != nil {
		if os.IsNotExist(err) {
			res.Findings = append(res.Findings, report.Finding{
				Check: "lockfile", Severity: report.SeverityInfo, Path: pjPath,
				Title: "no package.json found; npm checks skipped",
			})
			return res, nil
		}
		return res, err
	}
	if overflow {
		// Degrade rather than OOM/parse a hostile manifest: a package.json larger
		// than the cap is unparseable for our purposes, so flag it and stop.
		res.Findings = append(res.Findings, report.Finding{
			Check: "lockfile", Severity: report.SeverityMedium, Path: pjPath,
			Title:  "package.json too large to parse safely",
			Detail: "exceeds the read cap; refusing to load it into memory",
		})
		return res, nil
	}
	manifest, err := ParsePackageJSON(pjBytes)
	if err != nil {
		res.Findings = append(res.Findings, report.Finding{
			Check: "lockfile", Severity: report.SeverityMedium, Path: pjPath,
			Title: "package.json is not valid JSON", Detail: err.Error(),
		})
		return res, nil
	}
	res.Manifest = manifest
	res.ManifestFound = true

	present := map[string]bool{}
	for _, name := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if fileExists(filepath.Join(dir, name)) {
			present[name] = true
		}
	}
	res.LockFound = present["package-lock.json"]

	if res.LockFound {
		lockPath := filepath.Join(dir, "package-lock.json")
		lockBytes, lockOverflow, err := readBounded(lockPath, maxManifestBytes)
		if err == nil {
			switch {
			case lockOverflow:
				res.Findings = append(res.Findings, report.Finding{
					Check: "lockfile", Severity: report.SeverityMedium, Path: lockPath,
					Title:  "package-lock.json too large to parse safely",
					Detail: "exceeds the read cap; refusing to load it into memory",
				})
			default:
				if lock, perr := ParsePackageLock(lockBytes); perr == nil {
					res.Locked = lock.LockedVersions()
				} else {
					res.Findings = append(res.Findings, report.Finding{
						Check: "lockfile", Severity: report.SeverityMedium, Path: lockPath,
						Title: "package-lock.json is not valid JSON", Detail: perr.Error(),
					})
				}
			}
		}
	}

	res.Findings = append(res.Findings, Drift(manifest.AllDeps(), res.Locked, res.LockFound)...)
	res.Findings = append(res.Findings, CompetingLockfiles(present)...)
	return res, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// readBounded reads at most maxBytes from path. It returns (data, overflow,
// err): overflow is true when the file has more than maxBytes of content, in
// which case data holds the first maxBytes (the caller degrades to a finding
// rather than trusting a truncated parse). A non-existent file is surfaced as
// err so the caller can branch on os.IsNotExist.
func readBounded(path string, maxBytes int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	// Read one extra byte beyond the cap: if it is present, the file overflows.
	buf, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > maxBytes {
		return buf[:maxBytes], true, nil
	}
	return buf, false, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
