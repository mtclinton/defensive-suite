// Package pkgverify verifies auth-critical binaries against package-manager
// checksums (`rpm -V` on RPM distros; debsums/`dpkg -V` on Debian) and answers
// "which package owns this file?" for the unowned-PAM-module check. Per the
// DESIGN note, binary verification is masked to checksum-only to cut the noise
// of config files that legitimately change.
package pkgverify

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

// Family is the host package-manager family.
type Family int

const (
	FamilyUnknown Family = iota
	FamilyRPM
	FamilyDeb
)

func (f Family) String() string {
	switch f {
	case FamilyRPM:
		return "rpm"
	case FamilyDeb:
		return "deb"
	default:
		return "unknown"
	}
}

var rpmIDs = map[string]bool{
	"fedora": true, "rhel": true, "centos": true, "rocky": true,
	"almalinux": true, "opensuse": true, "suse": true, "sles": true, "amzn": true,
}

var debIDs = map[string]bool{
	"debian": true, "ubuntu": true, "linuxmint": true, "raspbian": true,
	"pop": true, "elementary": true, "kali": true,
}

// DetectFamily parses /etc/os-release content (ID and ID_LIKE) to choose the
// package-manager family.
func DetectFamily(osRelease string) Family {
	var id, idLike string
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = strings.ToLower(v)
		case "ID_LIKE":
			idLike = strings.ToLower(v)
		}
	}
	tokens := append([]string{id}, strings.Fields(idLike)...)
	for _, t := range tokens {
		if rpmIDs[t] {
			return FamilyRPM
		}
		if debIDs[t] {
			return FamilyDeb
		}
	}
	return FamilyUnknown
}

// Discrepancy is one verification mismatch for a path.
type Discrepancy struct {
	Path    string
	Flags   string // 9-char attribute string, "missing", or "FAILED"
	Missing bool
	Digest  bool // content/digest mismatch — the signal we keep for binaries
}

// parseVerify parses `rpm -V` / `dpkg -V` output. Each line is either
// "missing   /path" or "<9 attr chars> [filetype] /path"; '5' means the
// content digest differs.
func parseVerify(output string) []Discrepancy {
	var out []Discrepancy
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		path := fields[len(fields)-1]
		if fields[0] == "missing" {
			out = append(out, Discrepancy{Path: path, Flags: "missing", Missing: true})
			continue
		}
		flags := fields[0]
		// A valid attribute string is made only of these characters.
		if strings.Trim(flags, ".?SM5DLUGTPca") != "" || len(flags) < 8 {
			continue
		}
		out = append(out, Discrepancy{Path: path, Flags: flags, Digest: strings.Contains(flags, "5")})
	}
	return out
}

// parseDebsums parses `debsums <file>` output, where a tampered file ends in
// "FAILED".
func parseDebsums(output string) []Discrepancy {
	var out []Discrepancy
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasSuffix(line, "FAILED") {
			path := strings.TrimSpace(strings.TrimSuffix(line, "FAILED"))
			out = append(out, Discrepancy{Path: path, Flags: "FAILED", Digest: true})
		}
	}
	return out
}

func filterPath(ds []Discrepancy, path string) []Discrepancy {
	var out []Discrepancy
	for _, d := range ds {
		if d.Path == path {
			out = append(out, d)
		}
	}
	return out
}

// OwnerOf returns the owning package, or owned=false when no package owns path.
func OwnerOf(ctx context.Context, r runner.Runner, fam Family, path string) (pkg string, owned bool, err error) {
	switch fam {
	case FamilyRPM:
		res, err := r.Run(ctx, "rpm", "-qf", path)
		if err != nil {
			return "", false, err
		}
		out := strings.TrimSpace(res.Stdout)
		if res.ExitCode != 0 || out == "" ||
			strings.Contains(res.Stdout, "not owned by") || strings.Contains(res.Stderr, "not owned by") {
			return "", false, nil
		}
		return out, true, nil
	case FamilyDeb:
		res, err := r.Run(ctx, "dpkg", "-S", path)
		if err != nil {
			return "", false, err
		}
		if res.ExitCode != 0 {
			return "", false, nil
		}
		return parseDpkgSearch(res.Stdout, path)
	default:
		return "", false, errors.New("unknown package family")
	}
}

// parseDpkgSearch extracts the owning package from `dpkg -S <path>` output. It
// skips "diversion by ..." lines, prefers the line whose file equals path, and
// returns the first package when several share the file ("pkgA, pkgB: /path").
func parseDpkgSearch(out, path string) (string, bool, error) {
	var fallback string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "diversion by ") {
			continue
		}
		pkgs, file, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		first := strings.TrimSpace(strings.SplitN(pkgs, ",", 2)[0])
		if first == "" {
			continue
		}
		if strings.TrimSpace(file) == path {
			return first, true, nil
		}
		if fallback == "" {
			fallback = first
		}
	}
	if fallback != "" {
		return fallback, true, nil
	}
	return "", false, nil
}

// VerifyFile returns the digest/missing discrepancies for a single file.
func VerifyFile(ctx context.Context, r runner.Runner, fam Family, path string) ([]Discrepancy, error) {
	switch fam {
	case FamilyRPM:
		res, err := r.Run(ctx, "rpm", "-Vf", path)
		if err != nil {
			return nil, err
		}
		return filterPath(parseVerify(res.Stdout), path), nil
	case FamilyDeb:
		res, err := r.Run(ctx, "debsums", path)
		if errors.Is(err, runner.ErrNotFound) {
			// debsums absent — fall back to dpkg -V on the owning package.
			pkg, owned, oErr := OwnerOf(ctx, r, fam, path)
			if oErr != nil || !owned {
				return nil, oErr
			}
			res2, vErr := r.Run(ctx, "dpkg", "-V", pkg)
			if vErr != nil {
				return nil, vErr
			}
			return filterPath(parseVerify(res2.Stdout), path), nil
		}
		if err != nil {
			return nil, err
		}
		return filterPath(parseDebsums(res.Stdout), path), nil
	default:
		return nil, errors.New("unknown package family")
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Verify checks each existing binary against package checksums. Only digest and
// missing-file discrepancies are reported (checksum-only mask); a tampered auth
// binary is a Critical compromise indicator (T1554).
func Verify(ctx context.Context, r runner.Runner, fam Family, binaries []string) []report.Finding {
	if fam == FamilyUnknown {
		return []report.Finding{{
			Check: "pkgverify", Severity: report.SeverityInfo,
			Title: "package family unknown; checksum verification skipped",
		}}
	}
	var findings []report.Finding
	toolMissing := false
	for _, bin := range binaries {
		if !fileExists(bin) {
			continue
		}
		ds, err := VerifyFile(ctx, r, fam, bin)
		if errors.Is(err, runner.ErrNotFound) {
			toolMissing = true
			continue
		}
		if err != nil {
			findings = append(findings, report.Finding{
				Check: "pkgverify", Severity: report.SeverityLow, Path: bin,
				Title: "verification error", Detail: err.Error(),
			})
			continue
		}
		for _, d := range ds {
			if !d.Digest && !d.Missing {
				continue // mask metadata-only diffs per DESIGN note
			}
			title := "auth binary fails package checksum (digest mismatch)"
			if d.Missing {
				title = "auth binary missing from package metadata"
			}
			findings = append(findings, report.Finding{
				Check: "pkgverify", Severity: report.SeverityCritical, Path: d.Path,
				Title: title, Detail: "flags=" + d.Flags, Technique: "T1554",
			})
		}
	}
	if toolMissing {
		findings = append(findings, report.Finding{
			Check: "pkgverify", Severity: report.SeverityInfo,
			Title: "package verifier not installed; some checksum checks skipped",
		})
	}
	return findings
}
