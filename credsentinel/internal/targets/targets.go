// Package targets enumerates the exact credential files the stealers on the blog
// walk (atomic-lockfile's preinstall ELF, QLNX, the easy-day-js stage two): the
// registry/cloud/cluster credential files that gate build pipelines. These are
// the highest-value paths for the exposure scanner to cover regardless of what
// gitleaks/trufflehog would have found by walking the tree generically.
package targets

import (
	"os"
	"path/filepath"
)

// Target is one credential file (or glob) a stealer is known to read.
type Target struct {
	// Rel is the path relative to the home directory, possibly a glob.
	Rel string
	// Kind labels the credential class for findings and triage.
	Kind string
}

// StealerTargets is the canonical list, mirroring DESIGN.md and the threat model:
// `.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, `.kube/config`,
// `.docker/config.json`, `~/.codex/auth.json`, SSH private keys, Vault tokens.
var StealerTargets = []Target{
	{Rel: ".npmrc", Kind: "npm registry token"},
	{Rel: ".pypirc", Kind: "PyPI upload credentials"},
	{Rel: ".git-credentials", Kind: "git credential store"},
	{Rel: ".aws/credentials", Kind: "AWS credentials"},
	{Rel: ".aws/config", Kind: "AWS config (may carry sso/role creds)"},
	{Rel: ".kube/config", Kind: "Kubernetes kubeconfig"},
	{Rel: ".docker/config.json", Kind: "Docker registry auth"},
	{Rel: ".codex/auth.json", Kind: "Codex auth token"},
	{Rel: ".config/gh/hosts.yml", Kind: "GitHub CLI token"},
	{Rel: ".netrc", Kind: "netrc credentials"},
	// SSH private keys — common filenames plus a glob for the rest.
	{Rel: ".ssh/id_rsa", Kind: "SSH private key"},
	{Rel: ".ssh/id_ecdsa", Kind: "SSH private key"},
	{Rel: ".ssh/id_ed25519", Kind: "SSH private key"},
	{Rel: ".ssh/id_dsa", Kind: "SSH private key"},
	{Rel: ".ssh/*.pem", Kind: "SSH/TLS private key"},
	// HashiCorp Vault token files.
	{Rel: ".vault-token", Kind: "Vault token"},
	{Rel: ".vault/token", Kind: "Vault token"},
}

// Hit is a stealer target that exists on disk.
type Hit struct {
	Path string
	Kind string
}

// Resolve expands every target against home and returns the ones that exist on
// disk. Globs are expanded; a glob with no matches contributes nothing. The
// result is a path list the scanners feed file-by-file, so the built-in scanner
// and gitleaks/trufflehog all cover the exact stealer hit list explicitly.
func Resolve(home string, ts []Target) []Hit {
	var hits []Hit
	seen := map[string]bool{}
	for _, t := range ts {
		full := filepath.Join(home, t.Rel)
		matches := []string{full}
		if hasGlobMeta(t.Rel) {
			m, err := filepath.Glob(full)
			if err != nil || len(m) == 0 {
				continue
			}
			matches = m
		}
		for _, p := range matches {
			if seen[p] {
				continue
			}
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			seen[p] = true
			hits = append(hits, Hit{Path: p, Kind: t.Kind})
		}
	}
	return hits
}

func hasGlobMeta(s string) bool {
	for _, c := range s {
		switch c {
		case '*', '?', '[':
			return true
		}
	}
	return false
}
