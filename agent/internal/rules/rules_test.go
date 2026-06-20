package rules

import (
	"testing"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/tetragon"
)

func testCfg() Config {
	return Config{
		StagingDirs: []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		SensitivePaths: []string{
			"/etc/ld.so.preload",
			"*/.ssh/authorized_keys", "*/.ssh/authorized_keys2",
			"/lib64/security/",
		},
		BPFLoadFuncs: []string{"security_bpf_prog_load", "bpf_check"},
		WriteFuncs:   []string{"security_file_permission", "security_path_truncate"},
		BPFAllowlist: []string{"/usr/bin/cilium-agent", "/opt/tetragon/"},
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

// security_file_permission fires on read+write+exec; a READ mask (4) on a
// sensitive path must NOT produce a finding (sshd reading sshd_config, an
// authorized_keys read on login, PAM reading a module), while a WRITE mask (2)
// must produce a Critical.
func TestWriteRuleMaskGating(t *testing.T) {
	const maskRead, maskWrite, maskExec = 4, 2, 1
	read := Eval(tetragon.Event{
		Kind: "kprobe", Function: "security_file_permission",
		Binary: "/usr/sbin/sshd", Paths: []string{"/root/.ssh/authorized_keys"},
		Ints: []int64{maskRead},
	}, testCfg())
	if len(read) != 0 {
		t.Errorf("read mask on a sensitive path should yield NO finding: %+v", read)
	}
	if exec := Eval(tetragon.Event{
		Kind: "kprobe", Function: "security_file_permission",
		Paths: []string{"/etc/ld.so.preload"}, Ints: []int64{maskExec},
	}, testCfg()); len(exec) != 0 {
		t.Errorf("exec-only mask should yield NO finding: %+v", exec)
	}
	write := only(t, Eval(tetragon.Event{
		Kind: "kprobe", Function: "security_file_permission",
		Binary: "/usr/bin/tee", Paths: []string{"/etc/ld.so.preload"},
		Ints: []int64{maskWrite},
	}, testCfg()))
	if write.Severity != report.SeverityCritical || write.Technique != "T1574.006" {
		t.Errorf("write mask on a sensitive path should be Critical: %+v", write)
	}
	// MAY_WRITE combined with MAY_READ (6) is still a write.
	if rw := Eval(tetragon.Event{
		Kind: "kprobe", Function: "security_file_permission",
		Paths: []string{"/etc/ld.so.preload"}, Ints: []int64{maskRead | maskWrite},
	}, testCfg()); len(rw) != 1 {
		t.Errorf("read+write mask should flag: %+v", rw)
	}
	// A write-only hook (no mask arg) flags as before.
	if noMask := Eval(tetragon.Event{
		Kind: "kprobe", Function: "security_path_truncate",
		Paths: []string{"/etc/ld.so.preload"},
	}, testCfg()); len(noMask) != 1 {
		t.Errorf("maskless write-only hook should still flag: %+v", noMask)
	}
}

// Per-user authorized_keys (any user, plus authorized_keys2) must be caught by
// the suffix entries, mapped to T1098.004 — previously only /root exact matched.
func TestPerUserAuthorizedKeys(t *testing.T) {
	const maskWrite = 2
	cases := []string{
		"/home/alice/.ssh/authorized_keys",
		"/root/.ssh/authorized_keys2",
		"/home/bob/.ssh/authorized_keys2",
	}
	for _, p := range cases {
		f := only(t, Eval(tetragon.Event{
			Kind: "kprobe", Function: "security_file_permission",
			Binary: "/usr/bin/tee", Paths: []string{p}, Ints: []int64{maskWrite},
		}, testCfg()))
		if f.Severity != report.SeverityCritical || f.Technique != "T1098.004" {
			t.Errorf("write to %s → %+v (want Critical/T1098.004)", p, f)
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
