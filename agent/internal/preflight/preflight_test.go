package preflight

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
)

// gzipBytes returns s gzip-compressed — a realistic /proc/config.gz blob so the
// preflight check is exercised through real decompression, not a magic-byte guess.
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// ----------------------------------------------------------------------------
// fakes — no test touches a real binary, /boot, or the Tetragon socket.
// ----------------------------------------------------------------------------

// fakeRunner answers Run from a map keyed by "name arg1 arg2 …". A missing key
// returns an error (modelling an absent binary / inactive unit).
type fakeRunner struct {
	out  map[string]string
	errs map[string]error
}

func newRunner() *fakeRunner {
	return &fakeRunner{out: map[string]string{}, errs: map[string]error{}}
}

func key(name string, args ...string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (f *fakeRunner) set(out string, name string, args ...string) *fakeRunner {
	f.out[key(name, args...)] = out
	return f
}

func (f *fakeRunner) fail(err error, name string, args ...string) *fakeRunner {
	f.errs[key(name, args...)] = err
	return f
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	k := key(name, args...)
	if err, ok := f.errs[k]; ok {
		return f.out[k], err
	}
	if out, ok := f.out[k]; ok {
		return out, nil
	}
	return "", errors.New("exec: " + k + ": not found")
}

// fakeFS answers Stat/ReadFile from in-memory maps.
type fakeFS struct {
	files map[string][]byte
}

func newFS() *fakeFS { return &fakeFS{files: map[string][]byte{}} }

func (f *fakeFS) put(path string, data []byte) *fakeFS {
	f.files[path] = data
	return f
}

func (f *fakeFS) Stat(name string) (os.FileInfo, error) {
	if _, ok := f.files[name]; ok {
		return fakeInfo{name: name}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (f *fakeFS) ReadFile(name string) ([]byte, error) {
	if data, ok := f.files[name]; ok {
		return data, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

type fakeInfo struct{ name string }

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() os.FileMode  { return 0 }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any           { return nil }

// healthyHost returns a runner+fs+env that makes every check pass at the
// hard/soft level, so individual tests can break one thing at a time.
func healthyHost() (Inputs, *fakeRunner, *fakeFS) {
	const release = "6.8.0-test"
	rt := newRunner().
		set(release, "uname", "-r").
		set("nftables v1.0.9 (Old Doc Yourself)", "nft", "--version").
		set("fapolicyd v1.3", "fapolicyd", "--version").
		set("active", "systemctl", "is-active", "fapolicyd").
		set("tetra version 1.1.0", "tetra", "version").
		set("active", "systemctl", "is-active", "tetragon").
		set("NAME\ndsuite-observe", "tetra", "tracingpolicy", "list")
	fsk := newFS().
		put("/sys/kernel/btf/vmlinux", []byte("btf")).
		put("/boot/config-"+release, []byte("CONFIG_BPF_KPROBE_OVERRIDE=y\n")).
		put("/var/run/tetragon/tetragon.sock", []byte{})
	env := func(k string) string {
		switch k {
		case "AGENT_RESPONSE_TOKEN":
			return "tok"
		}
		return ""
	}
	return Inputs{Runner: rt, FS: fsk, Getenv: env}, rt, fsk
}

// find returns the named check from a slice (test helper).
func find(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in %v", name, names(checks))
	return Check{}
}

func names(checks []Check) []string {
	var out []string
	for _, c := range checks {
		out = append(out, c.Name)
	}
	return out
}

// ----------------------------------------------------------------------------
// the happy path
// ----------------------------------------------------------------------------

func TestRun_HealthyHostIsReady(t *testing.T) {
	in, _, _ := healthyHost()
	checks := Run(in)

	if !Ready(checks) {
		for _, c := range checks {
			if !c.OK && c.Severity >= SeverityMedium {
				t.Errorf("unexpected blocker: %+v", c)
			}
		}
		t.Fatal("healthy host should be READY")
	}
	if got := ExitCode(checks); got != ExitReady {
		t.Fatalf("exit code = %d, want %d", got, ExitReady)
	}
	// Every probe should be represented exactly once.
	want := []string{
		"kernel-release", "kernel-btf", "kprobe-override", "nftables",
		"fapolicyd", "tetragon-binary", "tetragon-active", "tetragon-socket",
		"enforce-policy", "response-readiness",
	}
	for _, w := range want {
		find(t, checks, w) // fails if missing
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks %v, want %d", len(checks), names(checks), len(want))
	}
}

// ----------------------------------------------------------------------------
// each check: OK and not-OK
// ----------------------------------------------------------------------------

func TestCheckKernelRelease(t *testing.T) {
	if c := checkKernelRelease("6.8.0"); !c.OK || !strings.Contains(c.Detail, "6.8.0") {
		t.Fatalf("present release: %+v", c)
	}
	c := checkKernelRelease("")
	if c.OK || c.Severity != SeverityInfo {
		t.Fatalf("missing release should be not-OK info: %+v", c)
	}
}

func TestCheckBTF(t *testing.T) {
	ok := newFS().put("/sys/kernel/btf/vmlinux", []byte("x"))
	if c := checkBTF(ok); !c.OK {
		t.Fatalf("BTF present should be OK: %+v", c)
	}
	c := checkBTF(newFS())
	if c.OK || c.Severity != SeverityHigh {
		t.Fatalf("missing BTF should be HIGH blocker: %+v", c)
	}
}

func TestCheckKprobeOverride(t *testing.T) {
	const rel = "6.8.0"
	t.Run("enabled in /boot/config", func(t *testing.T) {
		f := newFS().put("/boot/config-"+rel, []byte("CONFIG_FOO=y\nCONFIG_BPF_KPROBE_OVERRIDE=y\n"))
		if c := checkKprobeOverride(f, rel); !c.OK {
			t.Fatalf("=y should be OK: %+v", c)
		}
	})
	t.Run("not-set form is medium-advisory", func(t *testing.T) {
		f := newFS().put("/boot/config-"+rel, []byte("# CONFIG_BPF_KPROBE_OVERRIDE is not set\n"))
		c := checkKprobeOverride(f, rel)
		if c.OK || c.Severity != SeverityMedium {
			t.Fatalf("not-set should be not-OK medium: %+v", c)
		}
	})
	t.Run("absent everywhere is medium-advisory", func(t *testing.T) {
		c := checkKprobeOverride(newFS(), rel)
		if c.OK || c.Severity != SeverityMedium {
			t.Fatalf("no config should be not-OK medium: %+v", c)
		}
	})
	t.Run("gzipped /proc/config.gz with the option is OK", func(t *testing.T) {
		f := newFS().put("/proc/config.gz", gzipBytes(t, "CONFIG_FOO=y\nCONFIG_BPF_KPROBE_OVERRIDE=y\n"))
		if c := checkKprobeOverride(f, rel); !c.OK {
			t.Fatalf("gz with the option set should be OK: %+v", c)
		}
	})
	t.Run("gzipped /proc/config.gz without the option is medium-advisory", func(t *testing.T) {
		f := newFS().put("/proc/config.gz", gzipBytes(t, "CONFIG_FOO=y\n# CONFIG_BPF_KPROBE_OVERRIDE is not set\n"))
		c := checkKprobeOverride(f, rel)
		if c.OK || c.Severity != SeverityMedium {
			t.Fatalf("gz without the option should be not-OK medium: %+v", c)
		}
	})
}

func TestCheckNftables(t *testing.T) {
	ok := newRunner().set("nftables v1.0.9", "nft", "--version")
	if c := checkNftables(ok); !c.OK || !strings.Contains(c.Detail, "v1.0.9") {
		t.Fatalf("present nft should be OK: %+v", c)
	}
	c := checkNftables(newRunner())
	if c.OK || c.Severity != SeverityMedium {
		t.Fatalf("missing nft should be medium: %+v", c)
	}
}

func TestCheckFapolicyd(t *testing.T) {
	t.Run("installed and active", func(t *testing.T) {
		rt := newRunner().
			set("v1.3", "fapolicyd", "--version").
			set("active", "systemctl", "is-active", "fapolicyd")
		if c := checkFapolicyd(rt); !c.OK {
			t.Fatalf("should be OK: %+v", c)
		}
	})
	t.Run("missing binary", func(t *testing.T) {
		c := checkFapolicyd(newRunner())
		if c.OK || c.Severity != SeverityMedium {
			t.Fatalf("missing fapolicyd should be medium: %+v", c)
		}
	})
	t.Run("installed but inactive", func(t *testing.T) {
		rt := newRunner().
			set("v1.3", "fapolicyd", "--version").
			set("inactive", "systemctl", "is-active", "fapolicyd").
			fail(errors.New("exit 3"), "systemctl", "is-active", "fapolicyd")
		c := checkFapolicyd(rt)
		if c.OK || c.Severity != SeverityMedium || !strings.Contains(c.Detail, "not active") {
			t.Fatalf("inactive fapolicyd should be medium not-active: %+v", c)
		}
	})
}

func TestCheckTetragonBinary(t *testing.T) {
	ok := newRunner().set("tetra version 1.1.0", "tetra", "version")
	if c := checkTetragonBinary(ok); !c.OK {
		t.Fatalf("present tetra should be OK: %+v", c)
	}
	c := checkTetragonBinary(newRunner())
	if c.OK || c.Severity != SeverityHigh {
		t.Fatalf("missing tetra should be HIGH: %+v", c)
	}
}

func TestCheckTetragonActive(t *testing.T) {
	ok := newRunner().set("active", "systemctl", "is-active", "tetragon")
	if c := checkTetragonActive(ok); !c.OK {
		t.Fatalf("active tetragon should be OK: %+v", c)
	}
	rt := newRunner().
		set("inactive", "systemctl", "is-active", "tetragon").
		fail(errors.New("exit 3"), "systemctl", "is-active", "tetragon")
	c := checkTetragonActive(rt)
	if c.OK || c.Severity != SeverityHigh {
		t.Fatalf("inactive tetragon should be HIGH: %+v", c)
	}
}

func TestCheckTetragonSocket(t *testing.T) {
	ok := newFS().put("/var/run/tetragon/tetragon.sock", []byte{})
	if c := checkTetragonSocket(ok); !c.OK {
		t.Fatalf("socket present should be OK: %+v", c)
	}
	c := checkTetragonSocket(newFS())
	if c.OK || c.Severity != SeverityHigh {
		t.Fatalf("missing socket should be HIGH: %+v", c)
	}
}

func TestCheckEnforcePolicy(t *testing.T) {
	t.Run("none loaded", func(t *testing.T) {
		rt := newRunner().set("NAME", "tetra", "tracingpolicy", "list")
		c := checkEnforcePolicy(rt)
		if !c.OK || !strings.Contains(c.Detail, "unarmed") {
			t.Fatalf("no policies should report unarmed: %+v", c)
		}
	})
	t.Run("observe only", func(t *testing.T) {
		rt := newRunner().set("NAME\ndsuite-observe", "tetra", "tracingpolicy", "list")
		c := checkEnforcePolicy(rt)
		if !c.OK || strings.Contains(c.Detail, "may already be armed") {
			t.Fatalf("observe-only should not warn armed: %+v", c)
		}
		if !strings.Contains(c.Detail, "dsuite-observe") {
			t.Fatalf("should list the loaded policy: %+v", c)
		}
	})
	t.Run("enforce loaded warns armed", func(t *testing.T) {
		rt := newRunner().set("NAME\ndsuite-enforce", "tetra", "tracingpolicy", "list")
		c := checkEnforcePolicy(rt)
		if !c.OK || !strings.Contains(c.Detail, "may already be armed") {
			t.Fatalf("enforce policy should warn armed: %+v", c)
		}
	})
	t.Run("list error is non-blocking info", func(t *testing.T) {
		c := checkEnforcePolicy(newRunner())
		if !c.OK || c.Severity != SeverityInfo {
			t.Fatalf("list failure should be non-blocking info: %+v", c)
		}
	})
}

func TestCheckResponseReadiness(t *testing.T) {
	t.Run("token unset", func(t *testing.T) {
		c := checkResponseReadiness(func(string) string { return "" })
		if c.OK || c.Severity != SeverityInfo {
			t.Fatalf("no token should be not-OK info: %+v", c)
		}
	})
	t.Run("token set, dry-run", func(t *testing.T) {
		env := func(k string) string {
			if k == "AGENT_RESPONSE_TOKEN" {
				return "x"
			}
			return ""
		}
		c := checkResponseReadiness(env)
		if !c.OK || !strings.Contains(c.Detail, "DRY-RUN") {
			t.Fatalf("token-only should be OK dry-run: %+v", c)
		}
	})
	t.Run("token set, enabled would be live", func(t *testing.T) {
		env := func(k string) string {
			switch k {
			case "AGENT_RESPONSE_TOKEN":
				return "x"
			case "AGENT_ENABLE_RESPONSE":
				return "yes"
			}
			return ""
		}
		c := checkResponseReadiness(env)
		if !c.OK || !strings.Contains(c.Detail, "LIVE") {
			t.Fatalf("token+enable should report LIVE: %+v", c)
		}
	})
}

// ----------------------------------------------------------------------------
// blocker scenarios drive the exit code
// ----------------------------------------------------------------------------

func TestRun_HardBlockerNotReady(t *testing.T) {
	in, _, fsk := healthyHost()
	delete(fsk.files, "/sys/kernel/btf/vmlinux") // remove BTF → HIGH blocker
	checks := Run(in)
	if Ready(checks) {
		t.Fatal("missing BTF must make host NOT ready")
	}
	if got := ExitCode(checks); got != ExitNotReady {
		t.Fatalf("exit = %d, want %d", got, ExitNotReady)
	}
	if c := find(t, checks, "kernel-btf"); c.OK {
		t.Fatalf("kernel-btf should be not-OK: %+v", c)
	}
}

func TestRun_SoftBlockerNotReady(t *testing.T) {
	in, rt, _ := healthyHost()
	delete(rt.out, key("nft", "--version")) // remove nft → MEDIUM blocker
	checks := Run(in)
	if Ready(checks) {
		t.Fatal("missing nft (medium) must make host NOT ready")
	}
	if got := ExitCode(checks); got != ExitNotReady {
		t.Fatalf("exit = %d, want %d", got, ExitNotReady)
	}
}

func TestRun_InfoOnlyGapStaysReady(t *testing.T) {
	in, _, _ := healthyHost()
	// Override env: no response token → info-level not-OK, must NOT block.
	in.Getenv = func(string) string { return "" }
	checks := Run(in)
	rr := find(t, checks, "response-readiness")
	if rr.OK || rr.Severity != SeverityInfo {
		t.Fatalf("response-readiness should be not-OK info: %+v", rr)
	}
	if !Ready(checks) {
		t.Fatal("an info-only gap must NOT make the host not-ready")
	}
	if got := ExitCode(checks); got != ExitReady {
		t.Fatalf("exit = %d, want %d (info gap stays ready)", got, ExitReady)
	}
}

// ----------------------------------------------------------------------------
// ToReport mapping + severity
// ----------------------------------------------------------------------------

func TestToReport_MapsOnlyNotOK(t *testing.T) {
	checks := []Check{
		{Name: "kernel-btf", OK: false, Severity: SeverityHigh, Detail: "no btf", Remedy: "boot btf kernel"},
		{Name: "nftables", OK: false, Severity: SeverityMedium, Detail: "no nft", Remedy: "install nftables"},
		{Name: "response-readiness", OK: false, Severity: SeverityInfo, Detail: "no token", Remedy: "set token"},
		{Name: "kernel-release", OK: true, Detail: "6.8"},
	}
	rep := ToReport("host1", time.Unix(0, 0), checks)

	if rep.Tool != Tool {
		t.Fatalf("tool = %q, want %q", rep.Tool, Tool)
	}
	if rep.Host != "host1" {
		t.Fatalf("host = %q", rep.Host)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("want 3 findings (OK check omitted), got %d", len(rep.Findings))
	}

	by := map[string]report.Finding{}
	for _, f := range rep.Findings {
		by[f.Check] = f
	}
	if f, ok := by["preflight.kernel-btf"]; !ok || f.Severity != report.SeverityHigh {
		t.Fatalf("btf mapping wrong: %+v", f)
	}
	if f, ok := by["preflight.nftables"]; !ok || f.Severity != report.SeverityMedium {
		t.Fatalf("nft mapping wrong: %+v", f)
	}
	// info → Low keeps the finding below the "clean" threshold.
	f := by["preflight.response-readiness"]
	if f.Severity != report.SeverityLow {
		t.Fatalf("info should map to Low, got %v", f.Severity)
	}
	// Remedy lands in Detail.
	if by["preflight.kernel-btf"].Detail != "boot btf kernel" {
		t.Fatalf("remedy should map to Detail: %+v", by["preflight.kernel-btf"])
	}
	// Title is the observed detail.
	if by["preflight.kernel-btf"].Title != "no btf" {
		t.Fatalf("detail should map to Title: %+v", by["preflight.kernel-btf"])
	}
}

func TestToReport_AllOKIsCleanReport(t *testing.T) {
	checks := []Check{{Name: "x", OK: true}, {Name: "y", OK: true}}
	rep := ToReport("h", time.Unix(0, 0), checks)
	if len(rep.Findings) != 0 {
		t.Fatalf("all-OK should have no findings, got %d", len(rep.Findings))
	}
	if !rep.Summary.Clean {
		t.Fatal("all-OK report should be clean")
	}
	if rep.ExitCode() != 0 {
		t.Fatalf("clean report exit = %d", rep.ExitCode())
	}
}

func TestToReport_InfoOnlyStaysClean(t *testing.T) {
	// An info-only not-OK check maps to Low, which is below Medium, so the
	// report stays clean — consistent with Ready() ignoring info gaps.
	checks := []Check{{Name: "response-readiness", OK: false, Severity: SeverityInfo, Detail: "no token"}}
	rep := ToReport("h", time.Unix(0, 0), checks)
	if !rep.Summary.Clean {
		t.Fatalf("info-only report should be clean: %+v", rep.Summary)
	}
}

// ----------------------------------------------------------------------------
// exit codes / Ready
// ----------------------------------------------------------------------------

func TestExitCodeAndReady(t *testing.T) {
	ready := []Check{{Name: "a", OK: true}, {Name: "b", OK: false, Severity: SeverityInfo}}
	if !Ready(ready) || ExitCode(ready) != ExitReady {
		t.Fatalf("info-only gap should be ready: ready=%v exit=%d", Ready(ready), ExitCode(ready))
	}
	mediumBlock := []Check{{Name: "a", OK: false, Severity: SeverityMedium}}
	if Ready(mediumBlock) || ExitCode(mediumBlock) != ExitNotReady {
		t.Fatalf("medium blocker should be not-ready")
	}
	highBlock := []Check{{Name: "a", OK: false, Severity: SeverityHigh}}
	if Ready(highBlock) || ExitCode(highBlock) != ExitNotReady {
		t.Fatalf("high blocker should be not-ready")
	}
	if ExitError != 1 {
		t.Fatalf("ExitError must be 1, got %d", ExitError)
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityInfo:   "info",
		SeverityMedium: "medium",
		SeverityHigh:   "high",
		Severity(99):   "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Fatalf("Severity(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// ----------------------------------------------------------------------------
// human-format function
// ----------------------------------------------------------------------------

func TestWriteTable_ReadyVerdict(t *testing.T) {
	in, _, _ := healthyHost()
	checks := Run(in)
	var b strings.Builder
	WriteTable(&b, checks)
	out := b.String()
	if !strings.Contains(out, "READY") || strings.Contains(out, "NOT READY") {
		t.Fatalf("ready host should print READY verdict:\n%s", out)
	}
	if !strings.Contains(out, "READ-ONLY") {
		t.Fatalf("table should reassure it is read-only:\n%s", out)
	}
	if !strings.Contains(out, "STATUS") || !strings.Contains(out, "kernel-btf") {
		t.Fatalf("table should have a header and the checks:\n%s", out)
	}
}

func TestWriteTable_NotReadyListsBlockers(t *testing.T) {
	in, _, fsk := healthyHost()
	delete(fsk.files, "/sys/kernel/btf/vmlinux")
	checks := Run(in)
	var b strings.Builder
	WriteTable(&b, checks)
	out := b.String()
	if !strings.Contains(out, "NOT READY") {
		t.Fatalf("missing BTF should print NOT READY:\n%s", out)
	}
	if !strings.Contains(out, "kernel-btf") {
		t.Fatalf("blocker list should name kernel-btf:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatalf("not-OK row should show FAIL:\n%s", out)
	}
	if !strings.Contains(out, "remedies:") {
		t.Fatalf("not-ready output should print remedies:\n%s", out)
	}
}

// ----------------------------------------------------------------------------
// the injected Runner/FS contract: real impls exist and are read-only by type.
// (We do not exec real binaries here; we just confirm the zero-value Inputs
// resolves to the real impls without panicking on construction.)
// ----------------------------------------------------------------------------

func TestInputsDefaultsResolveRealImpls(t *testing.T) {
	in := Inputs{}
	if _, ok := in.runner().(RealRunner); !ok {
		t.Fatal("zero Inputs should default to RealRunner")
	}
	if _, ok := in.fs().(RealFS); !ok {
		t.Fatal("zero Inputs should default to RealFS")
	}
	if in.getenv() == nil {
		t.Fatal("zero Inputs should default getenv to os.Getenv")
	}
}
