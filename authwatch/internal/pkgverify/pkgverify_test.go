package pkgverify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
	"github.com/mtclinton/defensive-suite/authwatch/internal/runner"
)

func TestDetectFamily(t *testing.T) {
	cases := []struct {
		name string
		osr  string
		want Family
	}{
		{"fedora", "ID=fedora\nID_LIKE=\"\"\n", FamilyRPM},
		{"rhel", `ID="rhel"`, FamilyRPM},
		{"rocky via id_like", "ID=rocky\nID_LIKE=\"rhel centos fedora\"", FamilyRPM},
		{"ubuntu", "ID=ubuntu\nID_LIKE=debian", FamilyDeb},
		{"mint via id_like", "ID=linuxmint\nID_LIKE=\"ubuntu debian\"", FamilyDeb},
		{"arch", "ID=arch", FamilyUnknown},
		{"empty", "", FamilyUnknown},
	}
	for _, c := range cases {
		if got := DetectFamily(c.osr); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestParseVerify(t *testing.T) {
	out := `S.5....T.  /usr/sbin/sshd
.......T.  c /etc/ssh/sshd_config
missing     /usr/lib64/security/pam_x.so
prelink: some noise line`
	byPath := map[string]Discrepancy{}
	for _, d := range parseVerify(out) {
		byPath[d.Path] = d
	}
	if !byPath["/usr/sbin/sshd"].Digest {
		t.Error("sshd should show a digest mismatch")
	}
	if byPath["/etc/ssh/sshd_config"].Digest {
		t.Error("sshd_config (mtime only) should not be a digest mismatch")
	}
	if !byPath["/usr/lib64/security/pam_x.so"].Missing {
		t.Error("pam_x.so should be missing")
	}
}

func TestParseDebsums(t *testing.T) {
	out := "/usr/bin/ssh                     OK\n/usr/sbin/sshd                   FAILED\n"
	ds := parseDebsums(out)
	if len(ds) != 1 || ds[0].Path != "/usr/sbin/sshd" || !ds[0].Digest {
		t.Errorf("debsums=%+v", ds)
	}
}

func TestOwnerOfRPM(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"rpm -qf /owned":   {Stdout: "openssh-9.6\n", ExitCode: 0},
		"rpm -qf /unowned": {Stdout: "file /unowned is not owned by any package\n", ExitCode: 1},
	}}
	if pkg, owned, _ := OwnerOf(context.Background(), f, FamilyRPM, "/owned"); !owned || pkg != "openssh-9.6" {
		t.Errorf("owned=%v pkg=%q", owned, pkg)
	}
	if _, owned, _ := OwnerOf(context.Background(), f, FamilyRPM, "/unowned"); owned {
		t.Error("unowned should be false")
	}
}

func TestOwnerOfDeb(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"dpkg -S /owned":   {Stdout: "openssh-server: /owned\n", ExitCode: 0},
		"dpkg -S /unowned": {Stdout: "dpkg-query: no path found matching pattern /unowned\n", ExitCode: 1},
	}}
	if pkg, owned, _ := OwnerOf(context.Background(), f, FamilyDeb, "/owned"); !owned || pkg != "openssh-server" {
		t.Errorf("owned=%v pkg=%q", owned, pkg)
	}
	if _, owned, _ := OwnerOf(context.Background(), f, FamilyDeb, "/unowned"); owned {
		t.Error("unowned should be false")
	}
}

func TestVerifyDigestIsCritical(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sshd")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &runner.Fake{Responses: map[string]runner.Result{
		"rpm -Vf " + bin: {Stdout: "S.5....T.  " + bin + "\n", ExitCode: 1},
	}}
	findings := Verify(context.Background(), f, FamilyRPM, []string{bin})
	if len(findings) != 1 || findings[0].Severity != report.SeverityCritical || findings[0].Technique != "T1554" {
		t.Errorf("findings=%+v", findings)
	}
}

func TestVerifyMasksMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ssh")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &runner.Fake{Responses: map[string]runner.Result{
		"rpm -Vf " + bin: {Stdout: ".......T.  " + bin + "\n", ExitCode: 1},
	}}
	findings := Verify(context.Background(), f, FamilyRPM, []string{bin})
	if len(findings) != 0 {
		t.Errorf("metadata-only diff should be masked, got %+v", findings)
	}
}

func TestVerifyUnknownFamily(t *testing.T) {
	findings := Verify(context.Background(), &runner.Fake{}, FamilyUnknown, []string{"/x"})
	if len(findings) != 1 || findings[0].Severity != report.SeverityInfo {
		t.Errorf("findings=%+v", findings)
	}
}

func TestVerifyDebDebsumsFailedIsCritical(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sshd")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &runner.Fake{Responses: map[string]runner.Result{
		"debsums " + bin: {Stdout: bin + "    FAILED\n", ExitCode: 2},
	}}
	findings := Verify(context.Background(), f, FamilyDeb, []string{bin})
	if len(findings) != 1 || findings[0].Severity != report.SeverityCritical {
		t.Errorf("debsums FAILED should be Critical: %+v", findings)
	}
}

func TestVerifyDebDpkgFallback(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sshd")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// debsums absent (unmapped -> ErrNotFound) -> dpkg -S then dpkg -V fallback.
	f := &runner.Fake{Responses: map[string]runner.Result{
		"dpkg -S " + bin:         {Stdout: "openssh-server: " + bin + "\n", ExitCode: 0},
		"dpkg -V openssh-server": {Stdout: "??5??????   " + bin + "\n", ExitCode: 1},
	}}
	findings := Verify(context.Background(), f, FamilyDeb, []string{bin})
	if len(findings) != 1 || findings[0].Severity != report.SeverityCritical {
		t.Errorf("dpkg -V fallback digest mismatch should be Critical: %+v", findings)
	}
}

func TestVerifyDebClean(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ssh")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &runner.Fake{Responses: map[string]runner.Result{
		"debsums " + bin: {Stdout: bin + "   OK\n", ExitCode: 0},
	}}
	if findings := Verify(context.Background(), f, FamilyDeb, []string{bin}); len(findings) != 0 {
		t.Errorf("clean debsums should yield no findings: %+v", findings)
	}
}

func TestOwnerOfDebMultiPackageAndDiversion(t *testing.T) {
	f := &runner.Fake{Responses: map[string]runner.Result{
		"dpkg -S /multi": {Stdout: "pkgA, pkgB: /multi\n", ExitCode: 0},
		"dpkg -S /div":   {Stdout: "diversion by libc6 from: /div\nlibc6: /div\n", ExitCode: 0},
	}}
	if pkg, owned, _ := OwnerOf(context.Background(), f, FamilyDeb, "/multi"); !owned || pkg != "pkgA" {
		t.Errorf("multi-owner: pkg=%q owned=%v (want pkgA)", pkg, owned)
	}
	if pkg, owned, _ := OwnerOf(context.Background(), f, FamilyDeb, "/div"); !owned || pkg != "libc6" {
		t.Errorf("diversion: pkg=%q owned=%v (want libc6)", pkg, owned)
	}
}
