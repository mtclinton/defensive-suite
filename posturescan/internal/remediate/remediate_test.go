package remediate

import (
	"strings"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/sysctl"
)

func TestBuildPlanGeneratesDropIn(t *testing.T) {
	targets := sysctl.GoalProfile()
	rows := []report.SysctlRow{
		{Key: "kernel.yama.ptrace_scope", Want: "2", Got: "0", Status: sysctl.StatusDifferent},
		{Key: "kernel.unprivileged_bpf_disabled", Want: "2", Got: "2", Status: sysctl.StatusOK},
		{Key: "kernel.dmesg_restrict", Want: "1", Got: "(unset)", Status: sysctl.StatusUnknown},
		{Key: "kernel.lockdown", Want: "confidentiality", Got: "none", Status: sysctl.StatusDifferent},
		{Key: "module.sig_enforce", Want: "1", Got: "(unset)", Status: sysctl.StatusUnknown},
	}
	p := BuildPlan(targets, rows, "/etc/sysctl.d/99-posturescan.conf", time.Unix(0, 0))

	// Runtime sysctls that drifted must appear; OK ones must not.
	if !strings.Contains(p.DropInContent, "kernel.yama.ptrace_scope = 2") {
		t.Errorf("drop-in missing ptrace_scope:\n%s", p.DropInContent)
	}
	if !strings.Contains(p.DropInContent, "kernel.dmesg_restrict = 1") {
		t.Errorf("drop-in missing dmesg_restrict:\n%s", p.DropInContent)
	}
	if strings.Contains(p.DropInContent, "unprivileged_bpf_disabled") {
		t.Error("OK key should not be in the drop-in")
	}
	// Boot-time-only keys must NOT be sysctl lines, but must appear as Notes.
	if strings.Contains(p.DropInContent, "kernel.lockdown =") || strings.Contains(p.DropInContent, "module.sig_enforce =") {
		t.Error("boot-time keys should not be emitted as sysctl lines")
	}
	if len(p.Notes) != 2 {
		t.Errorf("want 2 boot-time notes (lockdown, sig_enforce), got %d: %v", len(p.Notes), p.Notes)
	}
	// The plan must show, not run, the privileged command.
	joined := strings.Join(p.Commands, "\n")
	if !strings.Contains(joined, "sysctl --system") {
		t.Errorf("plan should show `sysctl --system`: %v", p.Commands)
	}
}

func TestBuildPlanCleanHost(t *testing.T) {
	rows := []report.SysctlRow{
		{Key: "kernel.yama.ptrace_scope", Status: sysctl.StatusOK},
	}
	p := BuildPlan(sysctl.GoalProfile(), rows, "/etc/sysctl.d/99-posturescan.conf", time.Unix(0, 0))
	if len(p.Keys) != 0 {
		t.Errorf("clean host should have no keys to set: %v", p.Keys)
	}
	if len(p.Commands) != 0 {
		t.Errorf("clean host should have no commands: %v", p.Commands)
	}
	if !strings.Contains(p.DropInContent, "already matches") {
		t.Errorf("clean drop-in should note no changes:\n%s", p.DropInContent)
	}
}

func TestRenderIsDryRun(t *testing.T) {
	rows := []report.SysctlRow{
		{Key: "kernel.yama.ptrace_scope", Want: "2", Got: "0", Status: sysctl.StatusDifferent},
	}
	p := BuildPlan(sysctl.GoalProfile(), rows, "/etc/sysctl.d/99-posturescan.conf", time.Unix(0, 0))
	out := Render(p)
	for _, want := range []string{"DRY RUN", "NOT written", "NOT executed", "sysctl --system"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}
