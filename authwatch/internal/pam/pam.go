// Package pam scans the PAM module directories for the highest-fidelity
// backdoor signal in the DESIGN: a security `.so` that no package owns
// (T1556.003). It also re-verifies owned modules against package checksums to
// catch in-place tampering (the Velvet Ant backdoored pam_unix.so).
package pam

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/mtclinton/defensive-suite/authwatch/internal/pkgverify"
	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

// Modules returns every *.so under the given security directories.
func Modules(dirs []string) []string {
	var mods []string
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.so"))
		if err != nil {
			continue
		}
		mods = append(mods, matches...)
	}
	return mods
}

// Scan checks ownership and integrity of every PAM module under dirs.
func Scan(ctx context.Context, r runner.Runner, fam pkgverify.Family, dirs []string) []report.Finding {
	if fam == pkgverify.FamilyUnknown {
		return []report.Finding{{
			Check: "pam", Severity: report.SeverityInfo,
			Title: "package family unknown; PAM module ownership not verified",
		}}
	}
	var findings []report.Finding
	for _, mod := range Modules(dirs) {
		pkg, owned, err := pkgverify.OwnerOf(ctx, r, fam, mod)
		if errors.Is(err, runner.ErrNotFound) {
			findings = append(findings, report.Finding{
				Check: "pam", Severity: report.SeverityInfo, Path: mod,
				Title: "package tool absent; PAM module ownership unverified",
			})
			continue
		}
		if err != nil {
			findings = append(findings, report.Finding{
				Check: "pam", Severity: report.SeverityLow, Path: mod,
				Title: "PAM ownership check error", Detail: err.Error(),
			})
			continue
		}
		if !owned {
			findings = append(findings, report.Finding{
				Check: "pam", Severity: report.SeverityCritical, Path: mod,
				Title:     "unowned PAM module — no package provides it",
				Detail:    "a security .so installed outside the package manager is a high-confidence PAM backdoor",
				Technique: "T1556.003", Sigma: "lnx_auditd_pam_backdoor",
			})
			continue
		}
		// Owned — re-verify the on-disk content against package checksums.
		ds, vErr := pkgverify.VerifyFile(ctx, r, fam, mod)
		if vErr != nil {
			continue
		}
		for _, d := range ds {
			if !d.Digest && !d.Missing {
				continue
			}
			findings = append(findings, report.Finding{
				Check: "pam", Severity: report.SeverityCritical, Path: mod,
				Title:     "PAM module tampered (digest mismatch vs package)",
				Detail:    "owner=" + pkg + " flags=" + d.Flags,
				Technique: "T1556.003", Sigma: "lnx_auditd_pam_backdoor",
			})
		}
	}
	return findings
}
