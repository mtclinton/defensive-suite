package rules

import (
	"testing"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/tetragon"
)

func testCfg() Config {
	return Config{
		StagingDirs:    []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		SensitivePaths: []string{"/etc/ld.so.preload", "/root/.ssh/authorized_keys", "/lib64/security/"},
		BPFLoadFuncs:   []string{"security_bpf_prog_load", "bpf_check"},
		WriteFuncs:     []string{"security_file_permission"},
		BPFAllowlist:   []string{"/usr/bin/cilium-agent", "/opt/tetragon/"},
	}
}

func only(t *testing.T, f []report.Finding) report.Finding {
	t.Helper()
	if len(f) != 1 {
		t.Fatalf("want exactly 1 finding, got %d: %+v", len(f), f)
	}
	return f[0]
}

func TestExecFromStagingDir(t *testing.T) {
	f := only(t, Eval(tetragon.Event{Kind: "exec", Binary: "/tmp/.x/payload"}, testCfg()))
	if f.Severity != report.SeverityMedium || f.Technique != "T1059" {
		t.Errorf("finding=%+v", f)
	}
}

func TestExecFilelessTakesPrecedence(t *testing.T) {
	// also under /tmp, but fileless should win and be High, not Medium.
	f := only(t, Eval(tetragon.Event{Kind: "exec", Binary: "/tmp/x (deleted)"}, testCfg()))
	if f.Severity != report.SeverityHigh || f.Technique != "T1620" {
		t.Errorf("finding=%+v", f)
	}
	if f2 := only(t, Eval(tetragon.Event{Kind: "exec", Binary: "memfd:payload"}, testCfg())); f2.Severity != report.SeverityHigh {
		t.Errorf("memfd should be High: %+v", f2)
	}
}

func TestExecCleanNoFinding(t *testing.T) {
	if f := Eval(tetragon.Event{Kind: "exec", Binary: "/usr/bin/ls"}, testCfg()); len(f) != 0 {
		t.Errorf("clean exec should yield nothing: %+v", f)
	}
}

func TestBPFLoadFlagged(t *testing.T) {
	f := only(t, Eval(tetragon.Event{Kind: "kprobe", Function: "security_bpf_prog_load", Binary: "/usr/bin/evil", Pid: 9}, testCfg()))
	if f.Severity != report.SeverityHigh || f.Technique != "T1014" {
		t.Errorf("finding=%+v", f)
	}
}

func TestBPFLoadAllowlisted(t *testing.T) {
	if f := only(t, Eval(tetragon.Event{Kind: "kprobe", Function: "bpf_check", Binary: "/usr/bin/cilium-agent"}, testCfg())); f.Severity != report.SeverityInfo {
		t.Errorf("allowlisted loader should be Info: %+v", f)
	}
	if f := only(t, Eval(tetragon.Event{Kind: "kprobe", Function: "bpf_check", Binary: "/opt/tetragon/tetragon"}, testCfg())); f.Severity != report.SeverityInfo {
		t.Errorf("dir-allowlisted loader should be Info: %+v", f)
	}
}

func TestTrustPathWrite(t *testing.T) {
	cases := []struct {
		path string
		tech string
	}{
		{"/etc/ld.so.preload", "T1574.006"},
		{"/root/.ssh/authorized_keys", "T1098.004"},
		{"/lib64/security/pam_evil.so", "T1556.003"}, // dir-prefix match
	}
	for _, c := range cases {
		f := only(t, Eval(tetragon.Event{Kind: "kprobe", Function: "security_file_permission", Binary: "/usr/bin/tee", Paths: []string{c.path}}, testCfg()))
		if f.Severity != report.SeverityCritical || f.Technique != c.tech {
			t.Errorf("path %s → %+v (want Critical/%s)", c.path, f, c.tech)
		}
	}
}

func TestWriteNonSensitiveAndExitNoFinding(t *testing.T) {
	if f := Eval(tetragon.Event{Kind: "kprobe", Function: "security_file_permission", Paths: []string{"/tmp/foo"}}, testCfg()); len(f) != 0 {
		t.Errorf("non-sensitive write should yield nothing: %+v", f)
	}
	if f := Eval(tetragon.Event{Kind: "exit", Binary: "/usr/bin/ls"}, testCfg()); len(f) != 0 {
		t.Errorf("exit should yield nothing: %+v", f)
	}
}
