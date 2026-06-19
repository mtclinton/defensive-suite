package egress

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/mtclinton/defensive-suite/egresswatch/internal/report"
	"github.com/mtclinton/defensive-suite/egresswatch/internal/runner"
)

// maxProcRead bounds every /proc read. procDir is operator-overridable for
// offline-snapshot forensics, so a hostile snapshot could substitute a huge
// /proc/net/tcp and OOM the tool. Real net files are far under this.
const maxProcRead = 8 << 20 // 8 MiB

// readFileLimited reads at most maxProcRead bytes from path.
func readFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxProcRead))
}

// LoadAllowlist reads and parses the allowlist JSON at path. A blank path is not
// an error: it returns the zero Allowlist (loopback allowed, nothing else) and
// ok=false so the caller can report "no allowlist; observed-only" mode.
func LoadAllowlist(path string) (al Allowlist, ok bool, err error) {
	if path == "" {
		return Allowlist{AllowLoopback: true}, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Allowlist{}, false, err
	}
	al, err = ParseAllowlist(data)
	if err != nil {
		return Allowlist{}, false, err
	}
	return al, true, nil
}

// GatherConns collects observed outbound connections. source is "ss" (parse
// `ss -tunp`) or "proc" (parse /proc/net/tcp{,6}+udp{,6} under procDir). The
// runner is only used for the ss source; the proc source reads files directly.
func GatherConns(ctx context.Context, r runner.Runner, source, procDir string) ([]Conn, error) {
	if source == "ss" {
		res, err := r.Run(ctx, "ss", "-tunp")
		if err != nil {
			return nil, err
		}
		return ParseSS(res.Stdout), nil
	}
	var conns []Conn
	read := func(name, proto string, is6 bool) {
		b, err := readFileLimited(filepath.Join(procDir, "net", name))
		if err != nil {
			return
		}
		conns = append(conns, ParseProcNet(string(b), proto, is6)...)
	}
	read("tcp", "tcp", false)
	read("tcp6", "tcp", true)
	read("udp", "udp", false)
	read("udp6", "udp", true)
	return conns, nil
}

// Scan loads the allowlist, gathers connections, evaluates them, and returns
// findings. A denied connection (not on the allowlist) is a Medium finding —
// the OpenSnitch "deny" decision as data. Without an allowlist, observed
// connections are reported Info-only (nothing is judged).
func Scan(ctx context.Context, r runner.Runner, allowlistPath, source, procDir string) []report.Finding {
	var findings []report.Finding

	al, haveAllowlist, err := LoadAllowlist(allowlistPath)
	if err != nil {
		return []report.Finding{{
			Check: "egress", Severity: report.SeverityLow,
			Title: "could not load egress allowlist", Detail: err.Error(),
		}}
	}

	conns, err := GatherConns(ctx, r, source, procDir)
	if err != nil {
		sev := report.SeverityInfo
		if !errors.Is(err, runner.ErrNotFound) {
			sev = report.SeverityLow
		}
		return append(findings, report.Finding{
			Check: "egress", Severity: sev,
			Title: "could not gather observed connections", Detail: err.Error(),
		})
	}

	if !haveAllowlist {
		findings = append(findings, report.Finding{
			Check: "egress", Severity: report.SeverityInfo,
			Title: "no egress allowlist configured; connections reported but not judged",
		})
		for _, c := range conns {
			findings = append(findings, report.Finding{
				Check: "egress", Severity: report.SeverityInfo,
				Title: "observed outbound connection (unjudged)", Detail: c.String(),
			})
		}
		return findings
	}

	for _, d := range al.EvaluateAll(conns) {
		if d.Allowed {
			continue
		}
		findings = append(findings, report.Finding{
			Check: "egress", Severity: report.SeverityMedium,
			Title:     "outbound connection not on the egress allowlist",
			Detail:    d.Conn.String() + " (" + d.Reason + ")",
			Technique: "T1071", // application-layer C2 / unexpected egress
			Rule:      "egresswatch-egress-allowlist",
		})
	}
	return findings
}
