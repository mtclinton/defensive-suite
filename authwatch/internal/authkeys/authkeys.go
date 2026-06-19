// Package authkeys audits authorized_keys files against an allowlist of
// attributable key fingerprints, catching keys an attacker appended for
// persistence (Velvet Ant, T1098.004). Fingerprints are the OpenSSH SHA256 form
// computed from the decoded key blob, so they match `ssh-keygen -lf` output.
package authkeys

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/mtclinton/defensive-suite/authwatch/internal/report"
)

// Key is one parsed authorized_keys entry.
type Key struct {
	Options     string
	Type        string
	Fingerprint string // "SHA256:..."
	Comment     string
	Raw         string
}

var keyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-ed25519":                        true,
	"ssh-dss":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// isKeyType reports whether tok is an authorized_keys key-type token. It accepts
// the plain types above and any OpenSSH certificate type (…-cert-v01@openssh.com)
// — a cert-based key is just as usable for persistence and must be audited too.
func isKeyType(tok string) bool {
	return keyTypes[tok] || strings.HasSuffix(tok, "-cert-v01@openssh.com")
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of a key blob.
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

// parseLine parses a single authorized_keys line by locating the key-type token;
// anything before it is options, the next token is the base64 blob, the rest is
// the comment.
func parseLine(line string) (Key, bool) {
	fields := strings.Fields(line)
	idx := -1
	for i, f := range fields {
		if isKeyType(f) {
			idx = i
			break
		}
	}
	if idx == -1 || idx+1 >= len(fields) {
		return Key{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[idx+1])
	if err != nil || len(blob) == 0 {
		return Key{}, false
	}
	k := Key{Type: fields[idx], Fingerprint: Fingerprint(blob), Raw: line}
	if idx > 0 {
		k.Options = strings.Join(fields[:idx], " ")
	}
	if idx+2 < len(fields) {
		k.Comment = strings.Join(fields[idx+2:], " ")
	}
	return k, true
}

// ParseAuthorizedKeys parses every key line in content, skipping blanks/comments.
func ParseAuthorizedKeys(content string) []Key {
	var keys []Key
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, ok := parseLine(line); ok {
			keys = append(keys, k)
		}
	}
	return keys
}

// LoadAllowlist reads a file of attributable keys — each line either an OpenSSH
// "SHA256:..." fingerprint or a full public-key line — into a fingerprint set.
func LoadAllowlist(path string) (map[string]bool, error) {
	set := map[string]bool{}
	if path == "" {
		return set, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return set, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "SHA256:") {
			set[strings.Fields(line)[0]] = true
			continue
		}
		if k, ok := parseLine(line); ok {
			set[k.Fingerprint] = true
		}
	}
	return set, nil
}

// Audit flags every key whose fingerprint is not in the allowlist (T1098.004).
func Audit(path, content string, allow map[string]bool) []report.Finding {
	var findings []report.Finding
	for _, k := range ParseAuthorizedKeys(content) {
		if allow[k.Fingerprint] {
			continue
		}
		findings = append(findings, report.Finding{
			Check: "authkeys", Severity: report.SeverityHigh, Path: path,
			Title:     "unattributable authorized_keys entry",
			Detail:    fmt.Sprintf("type=%s fp=%s comment=%q", k.Type, k.Fingerprint, k.Comment),
			Technique: "T1098.004",
		})
	}
	return findings
}
