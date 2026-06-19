package caps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

func TestParseUnitGrants(t *testing.T) {
	unit := `[Service]
ExecStart=/usr/bin/foo
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_SYS_ADMIN
# CapabilityBoundingSet=CAP_SYS_MODULE  (commented — not a grant)
`
	grants := ParseUnitGrants("foo.service", unit)
	got := map[string]bool{}
	for _, g := range grants {
		got[g.Cap] = true
	}
	if !got["CAP_BPF"] || !got["CAP_SYS_ADMIN"] {
		t.Errorf("missing dangerous grants: %v", got)
	}
	if got["CAP_NET_ADMIN"] {
		t.Error("CAP_NET_ADMIN is not in the danger set; should not be flagged")
	}
	if got["CAP_SYS_MODULE"] {
		t.Error("commented directive should be ignored")
	}
}

func capSet(grants []Grant) map[string]bool {
	got := map[string]bool{}
	for _, g := range grants {
		got[g.Cap] = true
	}
	return got
}

func TestParseUnitGrantsInversionGrants(t *testing.T) {
	// Per systemd.exec(5) a leading '~' INVERTS the set: "all caps EXCEPT the
	// listed ones are included". So `~CAP_SYS_ADMIN CAP_BPF` actually KEEPS every
	// other dangerous cap (CAP_SYS_MODULE, CAP_SYS_PTRACE) while still listing
	// none of them — and the two it names are the ones excluded.
	unit := "[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN CAP_BPF\n"
	got := capSet(ParseUnitGrants("x.service", unit))
	if got["CAP_SYS_ADMIN"] || got["CAP_BPF"] {
		t.Errorf("excluded caps must NOT be granted by an inverted set: %v", got)
	}
	if !got["CAP_SYS_MODULE"] || !got["CAP_SYS_PTRACE"] {
		t.Errorf("inverted set should grant the dangerous caps it does NOT exclude: %v", got)
	}
}

func TestParseUnitGrantsInversionKeepsDangerous(t *testing.T) {
	// The classic bypass: `~CAP_NET_BIND_SERVICE` excludes only a harmless cap,
	// so EVERY dangerous cap (CAP_BPF, CAP_SYS_ADMIN, CAP_SYS_MODULE,
	// CAP_SYS_PTRACE) is still granted. Applies to AmbientCapabilities too.
	for _, key := range []string{"CapabilityBoundingSet", "AmbientCapabilities"} {
		unit := "[Service]\n" + key + "=~CAP_NET_BIND_SERVICE\n"
		got := capSet(ParseUnitGrants("x.service", unit))
		for _, c := range []string{"CAP_BPF", "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE"} {
			if !got[c] {
				t.Errorf("%s=~CAP_NET_BIND_SERVICE must still grant %s, got %v", key, c, got)
			}
		}
	}
}

func TestParseUnitGrantsBareTildeGrantsAll(t *testing.T) {
	// A bare '~' resets to the FULL capability set — every dangerous cap is in.
	unit := "[Service]\nCapabilityBoundingSet=~\n"
	got := capSet(ParseUnitGrants("x.service", unit))
	for c := range dangerousCaps {
		if !got[c] {
			t.Errorf("bare '~' should grant all dangerous caps; missing %s in %v", c, got)
		}
	}
}

func TestNormalizeCap(t *testing.T) {
	cases := map[string]string{"bpf": "CAP_BPF", "CAP_BPF": "CAP_BPF", " sys_admin ": "CAP_SYS_ADMIN", "": ""}
	for in, want := range cases {
		if got := normalizeCap(in); got != want {
			t.Errorf("normalizeCap(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsLegit(t *testing.T) {
	legit := []string{"tetragon", "cilium", "bpfsentry"}
	if !IsLegit("tetragon.service", legit) {
		t.Error("tetragon should be legit")
	}
	if !IsLegit("my-Cilium-agent", legit) {
		t.Error("case-insensitive substring should match")
	}
	if IsLegit("nginx.service", legit) {
		t.Error("nginx is not a legit eBPF tool")
	}
}

func TestGrantFindingSeverity(t *testing.T) {
	legit := []string{"tetragon"}
	// stray CAP_BPF -> Critical
	f := grantFinding(Grant{Workload: "evil.service", Cap: "CAP_BPF", Source: "systemd"}, legit)
	if f.Severity != report.SeverityCritical {
		t.Errorf("stray CAP_BPF should be Critical, got %v", f.Severity)
	}
	// stray CAP_SYS_ADMIN -> High
	f = grantFinding(Grant{Workload: "evil.service", Cap: "CAP_SYS_ADMIN", Source: "systemd"}, legit)
	if f.Severity != report.SeverityHigh {
		t.Errorf("stray CAP_SYS_ADMIN should be High, got %v", f.Severity)
	}
	// legit tool with CAP_BPF -> Info
	f = grantFinding(Grant{Workload: "tetragon.service", Cap: "CAP_BPF", Source: "systemd"}, legit)
	if f.Severity != report.SeverityInfo {
		t.Errorf("legit CAP_BPF should be Info, got %v", f.Severity)
	}
}

func TestAuditUnitDirs(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "evil.service"), "[Service]\nAmbientCapabilities=CAP_BPF\n")
	write(t, filepath.Join(dir, "tetragon.service"), "[Service]\nAmbientCapabilities=CAP_BPF\n")
	write(t, filepath.Join(dir, "clean.service"), "[Service]\nExecStart=/bin/true\n")
	write(t, filepath.Join(dir, "notes.txt"), "AmbientCapabilities=CAP_BPF\n") // not a .service

	findings := AuditUnitDirs([]string{dir}, []string{"tetragon"})
	var crit, info int
	for _, f := range findings {
		switch f.Severity {
		case report.SeverityCritical:
			crit++
		case report.SeverityInfo:
			info++
		}
	}
	if crit != 1 {
		t.Errorf("want 1 critical (evil), got %d (%+v)", crit, findings)
	}
	if info != 1 {
		t.Errorf("want 1 info (tetragon allowed), got %d", info)
	}
}

func TestAuditUnitDirsEmpty(t *testing.T) {
	findings := AuditUnitDirs([]string{t.TempDir()}, nil)
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("empty dirs should yield one info finding, got %+v", findings)
	}
}

func TestAuditContainerSpecs(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	write(t, bad, `{"HostConfig":{"CapAdd":["CAP_BPF"],"Privileged":false},"Config":{"User":"root"}}`)
	notjson := filepath.Join(dir, "x.txt")
	write(t, notjson, "not json")

	findings, specs := AuditContainerSpecs([]string{bad, notjson}, []string{"tetragon"})
	if len(specs) != 1 {
		t.Fatalf("want 1 parsed spec, got %d", len(specs))
	}
	var sawCrit, sawUnrecognized bool
	for _, f := range findings {
		if f.Severity == report.SeverityCritical {
			sawCrit = true
		}
		if f.Title == "container spec not recognized (neither OCI config.json nor podman inspect)" {
			sawUnrecognized = true
		}
	}
	if !sawCrit {
		t.Error("CAP_BPF in container should be Critical")
	}
	if !sawUnrecognized {
		t.Error("non-JSON file should produce an unrecognized finding")
	}
}

func TestAuditContainerSpecsNoneConfigured(t *testing.T) {
	findings, specs := AuditContainerSpecs(nil, nil)
	if specs != nil {
		t.Error("no specs expected")
	}
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("want one info skip finding, got %+v", findings)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
