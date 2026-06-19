package tools

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/runner"
)

// ServiceExposure is one row of `systemd-analyze security` overview: a unit and
// its exposure score (0.0 safest .. 10.0 most exposed).
type ServiceExposure struct {
	Unit     string
	Exposure float64
	Level    string // UNSAFE | EXPOSED | MEDIUM | OK
}

// ParseSystemdSecurity parses `systemd-analyze security` overview output. Each
// data line is "UNIT  EXPOSURE  PREDICATE  HAPPY", e.g.
// "sshd.service        9.6 UNSAFE   :(". The header line ("UNIT EXPOSURE ...")
// and blanks are skipped. Pure and table-tested.
func ParseSystemdSecurity(output string) []ServiceExposure {
	var out []ServiceExposure
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		unit := fields[0]
		if !strings.Contains(unit, ".") || strings.EqualFold(unit, "UNIT") {
			continue // header or non-unit line
		}
		exp, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		out = append(out, ServiceExposure{Unit: unit, Exposure: exp, Level: levelFor(exp, fields[2])})
	}
	return out
}

// levelFor classifies an exposure score, preferring systemd's own predicate word
// when present (UNSAFE/EXPOSED/MEDIUM/OK) and falling back to thresholds.
func levelFor(exp float64, predicate string) string {
	switch strings.ToUpper(predicate) {
	case "UNSAFE", "EXPOSED", "MEDIUM", "OK":
		return strings.ToUpper(predicate)
	}
	switch {
	case exp >= 8.0:
		return "UNSAFE"
	case exp >= 6.0:
		return "EXPOSED"
	case exp >= 4.0:
		return "MEDIUM"
	default:
		return "OK"
	}
}

// SystemdSecurity runs `systemd-analyze security --no-pager` and reports units
// whose exposure is high. UNSAFE (>=8) is Medium, EXPOSED (>=6) is Low; safer
// services are not reported individually (a summary Info finding is emitted).
func SystemdSecurity(ctx context.Context, r runner.Runner) []report.Finding {
	res, err := r.Run(ctx, "systemd-analyze", "security", "--no-pager")
	if errors.Is(err, runner.ErrNotFound) {
		return []report.Finding{{
			Check: "systemd-analyze", Severity: report.SeverityInfo,
			Title: "systemd-analyze not available; per-service exposure skipped",
		}}
	}
	if err != nil {
		return []report.Finding{{
			Check: "systemd-analyze", Severity: report.SeverityLow,
			Title: "systemd-analyze run error", Detail: err.Error(),
		}}
	}
	rows := ParseSystemdSecurity(res.Stdout)
	if len(rows) == 0 {
		return []report.Finding{{
			Check: "systemd-analyze", Severity: report.SeverityLow,
			Title: "systemd-analyze produced no parseable exposure rows",
		}}
	}
	var findings []report.Finding
	unsafe := 0
	for _, row := range rows {
		switch row.Level {
		case "UNSAFE":
			unsafe++
			findings = append(findings, report.Finding{
				Check: "systemd-analyze", Severity: report.SeverityMedium, Path: row.Unit,
				Title:  "service exposure UNSAFE (" + formatExp(row.Exposure) + "/10)",
				Detail: "consider systemd hardening directives (ProtectSystem, NoNewPrivileges, ...)",
			})
		case "EXPOSED":
			findings = append(findings, report.Finding{
				Check: "systemd-analyze", Severity: report.SeverityLow, Path: row.Unit,
				Title: "service exposure EXPOSED (" + formatExp(row.Exposure) + "/10)",
			})
		}
	}
	findings = append(findings, report.Finding{
		Check: "systemd-analyze", Severity: report.SeverityInfo,
		Title: "systemd-analyze security scanned " + strconv.Itoa(len(rows)) +
			" services (" + strconv.Itoa(unsafe) + " UNSAFE)",
	})
	return findings
}

func formatExp(e float64) string {
	return strconv.FormatFloat(e, 'f', 1, 64)
}
