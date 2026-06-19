package authkeys

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

func keyLine(typ string, blob []byte, comment string) string {
	return typ + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint([]byte("test-key-blob"))
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fp=%s", fp)
	}
	if strings.Contains(fp, "=") {
		t.Error("OpenSSH fingerprints strip base64 padding")
	}
}

func TestParseAndFingerprintLine(t *testing.T) {
	blob := []byte("0123456789abcdef0123456789abcdef")
	keys := ParseAuthorizedKeys(keyLine("ssh-ed25519", blob, "user@host"))
	if len(keys) != 1 {
		t.Fatalf("keys=%d", len(keys))
	}
	if keys[0].Type != "ssh-ed25519" {
		t.Errorf("type=%s", keys[0].Type)
	}
	if keys[0].Comment != "user@host" {
		t.Errorf("comment=%s", keys[0].Comment)
	}
	if keys[0].Fingerprint != Fingerprint(blob) {
		t.Error("parsed fingerprint does not match the decoded blob")
	}
}

func TestParseWithOptions(t *testing.T) {
	line := `command="/bin/x",no-pty ` + keyLine("ssh-rsa", []byte("abcdefghij"), "k@h")
	keys := ParseAuthorizedKeys(line)
	if len(keys) != 1 {
		t.Fatalf("keys=%d", len(keys))
	}
	if !strings.Contains(keys[0].Options, "command=") {
		t.Errorf("options=%q", keys[0].Options)
	}
	if keys[0].Type != "ssh-rsa" {
		t.Errorf("type=%s", keys[0].Type)
	}
}

func TestParseSkipsCommentsAndJunk(t *testing.T) {
	content := "# a comment\n\nthis is not a key\n" + keyLine("ssh-ed25519", []byte("xyzxyzxyzxyz"), "ok")
	if keys := ParseAuthorizedKeys(content); len(keys) != 1 {
		t.Errorf("keys=%d", len(keys))
	}
}

func TestAuditFlagsNonAllowlisted(t *testing.T) {
	goodBlob := []byte("good-key-1234567")
	badBlob := []byte("attacker-key-890")
	content := keyLine("ssh-ed25519", goodBlob, "trusted") + "\n" + keyLine("ssh-ed25519", badBlob, "attacker")
	allow := map[string]bool{Fingerprint(goodBlob): true}
	f := Audit("/root/.ssh/authorized_keys", content, allow)
	if len(f) != 1 || f[0].Severity != report.SeverityHigh || f[0].Technique != "T1098.004" {
		t.Errorf("audit=%+v", f)
	}
	if !strings.Contains(f[0].Detail, "attacker") {
		t.Errorf("detail should name the offending key: %q", f[0].Detail)
	}
}

func TestLoadAllowlistFingerprintAndPubkey(t *testing.T) {
	fpBlob := []byte("fingerprint-blob-x")
	pubBlob := []byte("pubkey-blob-yyyy")
	dir := t.TempDir()
	p := filepath.Join(dir, "allow")
	content := "# trusted keys\n" + Fingerprint(fpBlob) + "\n" + keyLine("ssh-rsa", pubBlob, "host") + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := LoadAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}
	if !set[Fingerprint(fpBlob)] {
		t.Error("fingerprint line not loaded")
	}
	if !set[Fingerprint(pubBlob)] {
		t.Error("public-key line not loaded")
	}
}

func TestLoadAllowlistEmptyPath(t *testing.T) {
	set, err := LoadAllowlist("")
	if err != nil || len(set) != 0 {
		t.Errorf("empty path: set=%v err=%v", set, err)
	}
}

func TestParseCertificateKey(t *testing.T) {
	blob := []byte("cert-blob-0123456789")
	keys := ParseAuthorizedKeys(keyLine("ssh-ed25519-cert-v01@openssh.com", blob, "attacker@evil"))
	if len(keys) != 1 {
		t.Fatalf("certificate key was not parsed: %d", len(keys))
	}
	if keys[0].Fingerprint != Fingerprint(blob) {
		t.Error("cert key fingerprint mismatch")
	}
}

func TestAuditFlagsUnattributableCertKey(t *testing.T) {
	blob := []byte("attacker-cert-blob-xy")
	line := keyLine("sk-ssh-ed25519-cert-v01@openssh.com", blob, "evil")
	f := Audit("/root/.ssh/authorized_keys", line, map[string]bool{})
	if len(f) != 1 || f[0].Severity != report.SeverityHigh {
		t.Errorf("unattributable cert key should be High: %+v", f)
	}
}
