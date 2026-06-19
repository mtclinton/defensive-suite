package targets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStealerTargetsCoversDesignList(t *testing.T) {
	// The DESIGN.md / THREAT_MODEL.md named paths must all be present.
	want := []string{
		".npmrc", ".pypirc", ".git-credentials", ".aws/credentials",
		".kube/config", ".docker/config.json", ".codex/auth.json", ".vault-token",
	}
	have := map[string]bool{}
	for _, tg := range StealerTargets {
		have[tg.Rel] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("StealerTargets missing the design-named path %q", w)
		}
	}
	// SSH private keys must be covered (specific names and a glob).
	if !have[".ssh/id_rsa"] || !have[".ssh/id_ed25519"] {
		t.Error("StealerTargets missing SSH private keys")
	}
}

func TestResolveExistingFilesOnly(t *testing.T) {
	home := t.TempDir()
	// Create .npmrc and .aws/credentials; leave .pypirc absent.
	mustWrite(t, filepath.Join(home, ".npmrc"), "//registry.npmjs.org/:_authToken=abc\n")
	mustMkdir(t, filepath.Join(home, ".aws"))
	mustWrite(t, filepath.Join(home, ".aws", "credentials"), "[default]\n")

	hits := Resolve(home, StealerTargets)
	got := map[string]string{}
	for _, h := range hits {
		got[h.Path] = h.Kind
	}
	if _, ok := got[filepath.Join(home, ".npmrc")]; !ok {
		t.Error(".npmrc should resolve")
	}
	if _, ok := got[filepath.Join(home, ".aws", "credentials")]; !ok {
		t.Error(".aws/credentials should resolve")
	}
	if _, ok := got[filepath.Join(home, ".pypirc")]; ok {
		t.Error("absent .pypirc must not resolve")
	}
}

func TestResolveGlobExpansion(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".ssh"))
	mustWrite(t, filepath.Join(home, ".ssh", "server.pem"), "-----BEGIN PRIVATE KEY-----\n")

	hits := Resolve(home, []Target{{Rel: ".ssh/*.pem", Kind: "k"}})
	if len(hits) != 1 || filepath.Base(hits[0].Path) != "server.pem" {
		t.Errorf("glob expansion=%+v", hits)
	}
}

func TestResolveSkipsDirectories(t *testing.T) {
	home := t.TempDir()
	// .ssh exists as a dir; a bare directory target must not be a hit.
	mustMkdir(t, filepath.Join(home, ".aws"))
	hits := Resolve(home, []Target{{Rel: ".aws", Kind: "dir"}})
	if len(hits) != 0 {
		t.Errorf("directory should not resolve as a credential file: %+v", hits)
	}
}

func TestResolveDeduplicates(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".npmrc"), "x")
	// Two targets pointing at the same file should yield one hit.
	hits := Resolve(home, []Target{{Rel: ".npmrc", Kind: "a"}, {Rel: ".npmrc", Kind: "b"}})
	if len(hits) != 1 {
		t.Errorf("expected dedup to one hit, got %+v", hits)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}
