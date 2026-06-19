package check

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/posturescan/internal/config"
	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
	"github.com/mtclinton/defensive-suite/posturescan/internal/runner"
	"github.com/mtclinton/defensive-suite/posturescan/internal/sysctl"
)

// fixtureProcSys builds a /proc/sys-style tree and a lockdown file, returning
// the proc-sys root and lockdown path.
func fixtureProcSys(t *testing.T, vals map[string]string, lockdown string) (string, string) {
	t.Helper()
	root := t.TempDir()
	for k, v := range vals {
		rel := filepath.FromSlash(replaceDots(k))
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lockPath := filepath.Join(t.TempDir(), "lockdown")
	if lockdown != "" {
		if err := os.WriteFile(lockPath, []byte(lockdown), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, lockPath
}

func replaceDots(k string) string {
	out := ""
	for _, c := range k {
		if c == '.' {
			out += "/"
		} else {
			out += string(c)
		}
	}
	return out
}

func TestSysctlRowsFromFixture(t *testing.T) {
	root, lock := fixtureProcSys(t, map[string]string{
		"kernel.unprivileged_bpf_disabled": "2",
		"kernel.yama.ptrace_scope":         "0", // DIFFERENT
		"kernel.kptr_restrict":             "2",
		"kernel.dmesg_restrict":            "1",
	}, "none [integrity] confidentiality")

	cfg := config.Defaults()
	cfg.ProcSysRoot = root
	cfg.LockdownPath = lock

	// sysctl -a fallback supplies module.sig_enforce; modules_disabled stays unset.
	r := &runner.Fake{Responses: map[string]runner.Result{
		"sysctl -a": {Stdout: "module.sig_enforce = 1\n"},
	}}
	rows, findings := SysctlRows(context.Background(), cfg, r, Targets(cfg))

	byKey := map[string]report.SysctlRow{}
	for _, row := range rows {
		byKey[row.Key] = row
	}
	if byKey["kernel.yama.ptrace_scope"].Status != sysctl.StatusDifferent {
		t.Errorf("ptrace_scope should be DIFFERENT: %+v", byKey["kernel.yama.ptrace_scope"])
	}
	if byKey["module.sig_enforce"].Status != sysctl.StatusOK {
		t.Errorf("module.sig_enforce should come from sysctl -a fallback: %+v", byKey["module.sig_enforce"])
	}
	if byKey["kernel.lockdown"].Status != sysctl.StatusDifferent {
		t.Errorf("lockdown integrity should be DIFFERENT vs confidentiality: %+v", byKey["kernel.lockdown"])
	}
	// ptrace_scope drift must be a High finding.
	var sawHigh bool
	for _, f := range findings {
		if f.Path == "kernel.yama.ptrace_scope" && f.Severity == report.SeverityHigh {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Errorf("expected High ptrace_scope finding, got %+v", findings)
	}
}

func TestRunAssemblesPosture(t *testing.T) {
	root, lock := fixtureProcSys(t, map[string]string{
		"kernel.unprivileged_bpf_disabled": "2",
		"kernel.yama.ptrace_scope":         "2",
		"kernel.kptr_restrict":             "2",
		"kernel.dmesg_restrict":            "1",
		"kernel.modules_disabled":          "1",
	}, "none integrity [confidentiality]")

	cfg := config.Defaults()
	cfg.ProcSysRoot = root
	cfg.LockdownPath = lock
	cfg.SystemdDirs = []string{t.TempDir()} // empty -> info finding
	cfg.ContainerSpecs = nil

	r := &runner.Fake{Responses: map[string]runner.Result{
		"sysctl -a": {Stdout: "module.sig_enforce = 1\n"},
	}}
	rep := Run(context.Background(), cfg, r, Options{Clock: func() time.Time { return time.Unix(0, 0) }})

	if rep.Tool != "posturescan" {
		t.Errorf("tool=%q", rep.Tool)
	}
	if rep.Posture == nil {
		t.Fatal("posture should be attached")
	}
	if rep.Posture.HardeningIndex != 100 {
		t.Errorf("fully-hardened fixture should index 100, got %d (rows=%+v)",
			rep.Posture.HardeningIndex, rep.Posture.Sysctls)
	}
	if rep.Posture.TargetIndex != 100 {
		t.Errorf("target index=%d", rep.Posture.TargetIndex)
	}
	// A fully hardened host with no stray caps should be clean.
	if !rep.Summary.Clean {
		t.Errorf("hardened host should be clean, findings=%+v", rep.Findings)
	}
}

func TestRunFlagsStrayCapAndContainer(t *testing.T) {
	root, lock := fixtureProcSys(t, map[string]string{
		"kernel.yama.ptrace_scope": "2",
	}, "none integrity [confidentiality]")

	unitDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(unitDir, "evil.service"),
		[]byte("[Service]\nAmbientCapabilities=CAP_BPF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(t.TempDir(), "priv.json")
	if err := os.WriteFile(specPath,
		[]byte(`[{"Name":"/danger","HostConfig":{"Privileged":true,"CapAdd":["CAP_SYS_ADMIN"]},"Config":{"User":"root"}}]`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.ProcSysRoot = root
	cfg.LockdownPath = lock
	cfg.SystemdDirs = []string{unitDir}
	cfg.ContainerSpecs = []string{specPath}

	r := &runner.Fake{}
	rep := Run(context.Background(), cfg, r, Options{Clock: func() time.Time { return time.Unix(0, 0) }})

	var sawCritCap, sawPrivContainer bool
	for _, f := range rep.Findings {
		if f.Check == "caps" && f.Severity == report.SeverityCritical {
			sawCritCap = true
		}
		if f.Check == "podman" && f.Severity == report.SeverityHigh {
			sawPrivContainer = true
		}
	}
	if !sawCritCap {
		t.Error("stray CAP_BPF unit should be Critical")
	}
	if !sawPrivContainer {
		t.Error("privileged container should yield a High podman finding")
	}
	if rep.Summary.Clean {
		t.Error("run with stray caps + privileged container must not be clean")
	}
}

func TestRunWrapToolsAbsentDegrades(t *testing.T) {
	root, lock := fixtureProcSys(t, map[string]string{"kernel.yama.ptrace_scope": "2"}, "none integrity [confidentiality]")
	cfg := config.Defaults()
	cfg.ProcSysRoot = root
	cfg.LockdownPath = lock
	cfg.SystemdDirs = []string{t.TempDir()}

	// Fake runner has no tool responses, so lynis/oscap/systemd-analyze are absent.
	rep := Run(context.Background(), cfg, &runner.Fake{}, Options{
		Clock: func() time.Time { return time.Unix(0, 0) }, WrapTools: true,
	})
	var lynisInfo, oscapInfo, sdInfo bool
	for _, f := range rep.Findings {
		switch f.Check {
		case "lynis":
			lynisInfo = f.Severity == report.SeverityInfo
		case "oscap":
			oscapInfo = f.Severity == report.SeverityInfo
		case "systemd-analyze":
			sdInfo = f.Severity == report.SeverityInfo
		}
	}
	if !lynisInfo || !oscapInfo || !sdInfo {
		t.Errorf("absent tools should degrade to info skips: lynis=%v oscap=%v sd=%v", lynisInfo, oscapInfo, sdInfo)
	}
}
