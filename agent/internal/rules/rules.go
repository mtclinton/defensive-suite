// Package rules turns a normalized Tetragon event into findings. M1 is
// observe-only — it detects and reports; enforcement (SIGKILL/Override) is a
// later milestone and lives in Tetragon TracingPolicies, not here.
package rules

import (
	"fmt"
	"strings"

	"github.com/mtclinton/defensive-suite/agent/internal/report"
	"github.com/mtclinton/defensive-suite/agent/internal/tetragon"
)

// Config is the rule-engine tuning (derived from the agent config).
type Config struct {
	StagingDirs    []string
	SensitivePaths []string
	BPFLoadFuncs   []string
	WriteFuncs     []string
	BPFAllowlist   []string
}

// Eval returns the findings a single event triggers (possibly none).
func Eval(e tetragon.Event, cfg Config) []report.Finding {
	switch e.Kind {
	case "exec":
		return execRules(e, cfg)
	case "kprobe":
		return kprobeRules(e, cfg)
	default:
		return nil
	}
}

func execRules(e tetragon.Event, cfg Config) []report.Finding {
	// Fileless execution (deleted on-disk image / memfd) — high-fidelity, takes
	// precedence over the staging-dir signal.
	if strings.Contains(e.Binary, "(deleted)") || strings.HasPrefix(e.Binary, "memfd:") || strings.Contains(e.Flags, "memfd") {
		return []report.Finding{{
			Check: "realtime.exec", Severity: report.SeverityHigh,
			Title:  "fileless execution (deleted or memfd binary)",
			Detail: execDetail(e), Path: e.Binary, Technique: "T1620",
		}}
	}
	for _, d := range cfg.StagingDirs {
		if strings.HasPrefix(e.Binary, d) {
			return []report.Finding{{
				Check: "realtime.exec", Severity: report.SeverityMedium,
				Title:  "execution from a staging directory",
				Detail: execDetail(e), Path: e.Binary, Technique: "T1059",
			}}
		}
	}
	return nil
}

func kprobeRules(e tetragon.Event, cfg Config) []report.Finding {
	var out []report.Finding

	if contains(cfg.BPFLoadFuncs, e.Function) {
		sev, title := report.SeverityHigh, "eBPF program loaded by an unrecognized loader"
		if allowlisted(e.Binary, cfg.BPFAllowlist) {
			sev, title = report.SeverityInfo, "eBPF program loaded by an allowlisted loader"
		}
		out = append(out, report.Finding{
			Check: "realtime.bpf", Severity: sev, Title: title,
			Detail: fmt.Sprintf("fn=%s loader=%s pid=%d", e.Function, e.Binary, e.Pid),
			Path:   e.Binary, Technique: "T1014",
		})
	}

	if contains(cfg.WriteFuncs, e.Function) && writeIntent(e) {
		for _, p := range e.Paths {
			if match, ok := sensitiveMatch(p, cfg.SensitivePaths); ok {
				sev := severityFor(match)
				title := "write to a persistence path"
				if sev == report.SeverityCritical {
					title = "write to a trust-path file"
				}
				out = append(out, report.Finding{
					Check: "realtime.write", Severity: sev, Title: title,
					Detail: fmt.Sprintf("%s wrote %s (fn=%s pid=%d)", e.Binary, p, e.Function, e.Pid),
					Path:   p, Technique: techniqueFor(match),
				})
			}
		}
	}
	return out
}

// severityFor tiers a sensitive-path write. The high-fidelity trust paths
// (linker preload, PAM, the PAM module dirs, SSH keys, sshd_config) are almost
// never legitimately written → Critical. The persistence paths (systemd, cron,
// shell init, rc.local, udev) are also written by package managers / admins, so
// they are High — surfaced, but not crying Critical on every apt install.
func severityFor(match string) report.Severity {
	switch {
	case strings.Contains(match, "ld.so"),
		strings.Contains(match, "pam.d"),
		strings.Contains(match, "security/"),
		strings.Contains(match, "authorized_keys"),
		strings.Contains(match, ".ssh/"),
		strings.Contains(match, "sshd_config"),
		strings.Contains(match, "sudoers"):
		return report.SeverityCritical
	default:
		return report.SeverityHigh
	}
}

// isShellInit reports whether a sensitive entry is a shell startup file (system
// or per-user) — modifying one is shell-configuration persistence (T1546.004).
func isShellInit(s string) bool {
	for _, k := range []string{"profile", "bashrc", "bash_login", "zshrc", "zshenv", "zprofile"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// writeIntent gates a trust-path "write" finding on actual write intent.
// security_file_permission's LSM hook fires on read+write+exec, carrying an
// access mask (arg index 1: MAY_READ=4 / MAY_WRITE=2 / MAY_EXEC=1). When a mask
// is present we only flag when MAY_WRITE is set — otherwise sshd reading
// sshd_config, an authorized_keys read on login, or PAM reading a module become
// Critical false positives. A hook that carries no mask (a genuinely write-only
// path like security_path_truncate) flags as before.
func writeIntent(e tetragon.Event) bool {
	if e.HasMask() {
		return e.MayWrite()
	}
	return true
}

func execDetail(e tetragon.Event) string {
	if e.Args != "" {
		return fmt.Sprintf("%s %s (pid=%d uid=%d parent=%s)", e.Binary, e.Args, e.Pid, e.UID, e.Parent)
	}
	return fmt.Sprintf("%s (pid=%d uid=%d parent=%s)", e.Binary, e.Pid, e.UID, e.Parent)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// allowlisted matches a loader binary exactly, or by a directory prefix entry.
func allowlisted(binary string, allow []string) bool {
	for _, a := range allow {
		if a == binary || (strings.HasSuffix(a, "/") && strings.HasPrefix(binary, a)) {
			return true
		}
	}
	return false
}

// sensitiveMatch reports whether path hits a sensitive entry. Three entry forms:
//   - ending in "/"        → directory prefix (e.g. "/etc/pam.d/")
//   - beginning with "*"   → suffix match (e.g. "*/.ssh/authorized_keys" covers
//     every user's key file, including /root and /home/<user>)
//   - otherwise            → exact file path
//
// It returns the matched entry for technique attribution.
func sensitiveMatch(path string, sensitive []string) (string, bool) {
	for _, s := range sensitive {
		switch {
		case strings.HasSuffix(s, "/"):
			if strings.HasPrefix(path, s) {
				return s, true
			}
		case strings.HasPrefix(s, "*"):
			if strings.HasSuffix(path, s[1:]) {
				return s, true
			}
		default:
			if path == s {
				return s, true
			}
		}
	}
	return "", false
}

func techniqueFor(sensitive string) string {
	switch {
	case strings.Contains(sensitive, "ld.so"):
		return "T1574.006" // hijack execution flow: dynamic linker (preload / conf.d)
	case strings.Contains(sensitive, "pam.d") || strings.Contains(sensitive, "security/"):
		return "T1556.003" // modify authentication process: PAM
	case strings.Contains(sensitive, "authorized_keys") || strings.Contains(sensitive, ".ssh/"):
		return "T1098.004" // account manipulation: SSH authorized_keys
	case strings.Contains(sensitive, "sudoers"):
		return "T1548.003" // abuse elevation control: sudo and sudo caching
	case strings.Contains(sensitive, "systemd"):
		return "T1543.002" // create or modify system process: systemd service
	case strings.Contains(sensitive, "cron"):
		return "T1053.003" // scheduled task/job: cron
	case strings.Contains(sensitive, "modprobe") || strings.Contains(sensitive, "modules"):
		return "T1547.006" // boot or logon autostart: kernel modules and extensions
	case strings.Contains(sensitive, "udev"):
		return "T1546.017" // event triggered execution: udev rules
	case strings.Contains(sensitive, "autostart"):
		return "T1547.013" // boot or logon autostart: XDG autostart entries
	case strings.Contains(sensitive, "rc.local") || strings.Contains(sensitive, "init.d"):
		return "T1037.004" // boot or logon init scripts: RC scripts
	case isShellInit(sensitive):
		return "T1546.004" // event triggered execution: Unix shell config
	default:
		return "T1565.001" // stored data manipulation (e.g. sshd_config tamper)
	}
}
