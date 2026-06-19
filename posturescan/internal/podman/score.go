package podman

import (
	"fmt"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

// Control is one scored hardening control for a container spec.
type Control struct {
	Name   string
	Pass   bool
	Weight int
	Detail string
}

// Score is the rolled-up posture score for one container.
type Score struct {
	Name     string
	Points   int
	Max      int
	Controls []Control
}

// Percent is the 0-100 posture score.
func (s Score) Percent() int {
	if s.Max == 0 {
		return 0
	}
	return s.Points * 100 / s.Max
}

// Evaluate scores a Spec across the six DESIGN.md Podman controls plus a
// privileged-container override. A privileged container fails outright (it
// negates the other isolation), so it zeroes the score. Pure for table tests.
func (s Spec) Evaluate() Score {
	if s.Privileged {
		return Score{
			Name: s.Name, Points: 0, Max: 100,
			Controls: []Control{{
				Name: "not-privileged", Pass: false, Weight: 100,
				Detail: "privileged container — negates cap-drop, seccomp, and userns isolation",
			}},
		}
	}
	controls := []Control{
		{Name: "rootless", Pass: s.Rootless, Weight: 20,
			Detail: "runs without host root (user namespace / non-root user)"},
		{Name: "cap-drop-all", Pass: s.CapDropAll, Weight: 25,
			Detail: "--cap-drop=all (or empty bounding set) so no stray CAP_BPF/SYS_ADMIN"},
		{Name: "no-new-privileges", Pass: s.NoNewPrivs, Weight: 15,
			Detail: "no-new-privileges blocks setuid privilege regain"},
		{Name: "seccomp", Pass: s.SeccompPresent, Weight: 15,
			Detail: "a seccomp profile is applied (not unconfined)"},
		{Name: "read-only-rootfs", Pass: s.ReadOnlyRootfs, Weight: 15,
			Detail: "read-only root filesystem"},
		{Name: "user-namespace", Pass: s.UserNamespace, Weight: 10,
			Detail: "user namespace remaps container root to an unprivileged host UID"},
	}
	sc := Score{Name: s.Name, Controls: controls}
	for _, c := range controls {
		sc.Max += c.Weight
		if c.Pass {
			sc.Points += c.Weight
		}
	}
	return sc
}

// Findings turns a spec's posture into report findings: one summary line plus a
// Medium/High finding per failed control. A score below 60 is itself a Medium.
func (s Spec) Findings() []report.Finding {
	sc := s.Evaluate()
	pct := sc.Percent()
	sev := report.SeverityInfo
	switch {
	case pct < 50:
		sev = report.SeverityHigh
	case pct < 80:
		sev = report.SeverityMedium
	}
	findings := []report.Finding{{
		Check: "podman", Severity: sev, Path: s.Name,
		Title:  fmt.Sprintf("container posture score %d/100", pct),
		Detail: failedSummary(sc),
	}}
	// Surface a dedicated finding for each failed control so the journal/webhook
	// names the missing control, not just the score.
	for _, c := range sc.Controls {
		if c.Pass {
			continue
		}
		csev := report.SeverityLow
		if c.Name == "cap-drop-all" || c.Name == "not-privileged" {
			csev = report.SeverityHigh
		}
		findings = append(findings, report.Finding{
			Check: "podman", Severity: csev, Path: s.Name,
			Title:  "container posture: missing " + c.Name,
			Detail: c.Detail,
		})
	}
	return findings
}

func failedSummary(sc Score) string {
	var failed []string
	for _, c := range sc.Controls {
		if !c.Pass {
			failed = append(failed, c.Name)
		}
	}
	if len(failed) == 0 {
		return "all controls pass"
	}
	out := "missing:"
	for _, f := range failed {
		out += " " + f
	}
	return out
}

// DangerousCaps returns the spec's capabilities that are in the danger set,
// for the cross-package caps audit. The set mirrors caps.dangerousCaps.
func (s Spec) DangerousCaps() []string {
	danger := map[string]bool{
		"CAP_BPF": true, "CAP_SYS_ADMIN": true,
		"CAP_SYS_MODULE": true, "CAP_SYS_PTRACE": true,
	}
	var out []string
	for _, c := range s.Caps {
		if danger[c] {
			out = append(out, c)
		}
	}
	return out
}
