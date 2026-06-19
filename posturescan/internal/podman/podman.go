// Package podman parses container specs — OCI runtime config.json and
// `podman inspect` JSON — into a normalized Spec, then audits capabilities and
// scores the rootless-Podman hardening posture the DESIGN doc asks for
// (rootless, --cap-drop=all, no-new-privileges, seccomp present, read-only
// rootfs, user namespaces). Parsing and scoring are pure for table tests.
package podman

import (
	"encoding/json"
	"sort"
	"strings"
)

// Spec is the normalized view of a container, populated from either an OCI
// config.json or a `podman inspect` element. Only the fields posturescan scores
// on are kept.
type Spec struct {
	Name           string   // container/unit name (for findings)
	Caps           []string // effective/bounding/permitted capabilities, normalized CAP_*
	NoNewPrivs     bool     // no-new-privileges set
	Rootless       bool     // running rootless (UID-mapped, not host root)
	ReadOnlyRootfs bool     // read-only root filesystem
	SeccompPresent bool     // a seccomp profile is applied (not "unconfined"/empty)
	UserNamespace  bool     // a user namespace is configured (UID/GID mappings)
	CapDropAll     bool     // capabilities were dropped to (near) none / ALL
	Privileged     bool     // privileged container (overrides most isolation)
}

// ---- OCI runtime spec (config.json) ----

type ociSpec struct {
	Process *struct {
		NoNewPrivileges bool `json:"noNewPrivileges"`
		Capabilities    *struct {
			Bounding  []string `json:"bounding"`
			Effective []string `json:"effective"`
			Permitted []string `json:"permitted"`
		} `json:"capabilities"`
	} `json:"process"`
	Root *struct {
		Readonly bool `json:"readonly"`
	} `json:"root"`
	Linux *struct {
		Seccomp     json.RawMessage `json:"seccomp"`
		UIDMappings []struct {
			Size int `json:"size"`
		} `json:"uidMappings"`
		Namespaces []struct {
			Type string `json:"type"`
		} `json:"namespaces"`
	} `json:"linux"`
}

// ---- podman inspect element (subset) ----

type podmanInspect struct {
	Name       string `json:"Name"`
	HostConfig *struct {
		Privileged     bool     `json:"Privileged"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
		UsernsMode     string   `json:"UsernsMode"`
	} `json:"HostConfig"`
	Config *struct {
		User string `json:"User"`
	} `json:"Config"`
}

func normalizeCap(tok string) string {
	tok = strings.ToUpper(strings.TrimSpace(tok))
	if tok == "" {
		return ""
	}
	if !strings.HasPrefix(tok, "CAP_") {
		tok = "CAP_" + tok
	}
	return tok
}

func dedupeCaps(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		n := normalizeCap(c)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Parse decodes a container spec from JSON, auto-detecting OCI config.json vs a
// `podman inspect` array/object. ok is false when neither shape matches.
func Parse(data []byte) (Spec, bool) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return Spec{}, false
	}
	// podman inspect emits a JSON array; unwrap to the first element.
	if strings.HasPrefix(trimmed, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil || len(arr) == 0 {
			return Spec{}, false
		}
		return Parse(arr[0])
	}

	// Try OCI runtime spec first (has a top-level "ociVersion" or "process").
	if s, ok := parseOCI(data); ok {
		return s, true
	}
	if s, ok := parsePodmanInspect(data); ok {
		return s, true
	}
	return Spec{}, false
}

func parseOCI(data []byte) (Spec, bool) {
	var o ociSpec
	if err := json.Unmarshal(data, &o); err != nil {
		return Spec{}, false
	}
	if o.Process == nil && o.Root == nil && o.Linux == nil {
		return Spec{}, false // not an OCI spec
	}
	s := Spec{Name: "oci-container"}
	if o.Process != nil {
		s.NoNewPrivs = o.Process.NoNewPrivileges
		if o.Process.Capabilities != nil {
			var all []string
			all = append(all, o.Process.Capabilities.Bounding...)
			all = append(all, o.Process.Capabilities.Effective...)
			all = append(all, o.Process.Capabilities.Permitted...)
			s.Caps = dedupeCaps(all)
		}
	}
	// No capabilities listed in an OCI spec means the bounding set was emptied.
	s.CapDropAll = len(s.Caps) == 0
	if o.Root != nil {
		s.ReadOnlyRootfs = o.Root.Readonly
	}
	if o.Linux != nil {
		s.SeccompPresent = seccompPresent(o.Linux.Seccomp)
		for _, m := range o.Linux.UIDMappings {
			if m.Size > 0 {
				s.UserNamespace = true
			}
		}
		for _, ns := range o.Linux.Namespaces {
			if ns.Type == "user" {
				s.UserNamespace = true
			}
		}
		// A user namespace with UID mappings means the container is not the host
		// root user — i.e. rootless from the host's perspective.
		s.Rootless = s.UserNamespace
	}
	return s, true
}

// seccompPresent reports whether the OCI linux.seccomp block applies a real
// filter, versus "unconfined" (null) or a functionally-unconfined allow-all
// profile. A profile whose defaultAction is SCMP_ACT_ALLOW (or SCMP_ACT_LOG)
// with no syscall rules narrowing it lets every syscall through — it is not a
// seccomp control, so it must not be scored as one (that would hide a missing
// seccomp finding and award undeserved points).
func seccompPresent(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return false
	}
	var probe struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	if probe.DefaultAction == "" {
		return false
	}
	// An allow-everything default with no narrowing syscall rules is unconfined.
	switch strings.ToUpper(strings.TrimSpace(probe.DefaultAction)) {
	case "SCMP_ACT_ALLOW", "SCMP_ACT_LOG":
		if len(probe.Syscalls) == 0 {
			return false
		}
	}
	return true
}

func parsePodmanInspect(data []byte) (Spec, bool) {
	var p podmanInspect
	if err := json.Unmarshal(data, &p); err != nil {
		return Spec{}, false
	}
	if p.HostConfig == nil && p.Config == nil {
		return Spec{}, false
	}
	s := Spec{Name: strings.TrimPrefix(p.Name, "/")}
	if s.Name == "" {
		s.Name = "podman-container"
	}
	if p.HostConfig != nil {
		hc := p.HostConfig
		s.Privileged = hc.Privileged
		s.ReadOnlyRootfs = hc.ReadonlyRootfs
		s.Caps = dedupeCaps(hc.CapAdd)
		for _, d := range hc.CapDrop {
			if strings.EqualFold(strings.TrimSpace(d), "all") {
				s.CapDropAll = true
			}
		}
		for _, opt := range hc.SecurityOpt {
			low := strings.ToLower(opt)
			if strings.Contains(low, "no-new-privileges") {
				s.NoNewPrivs = true
			}
			if strings.HasPrefix(low, "seccomp=") && !strings.Contains(low, "unconfined") {
				s.SeccompPresent = true
			}
		}
		// Podman applies its default seccomp profile unless explicitly unconfined.
		if !hasUnconfinedSeccomp(hc.SecurityOpt) {
			s.SeccompPresent = true
		}
		un := strings.ToLower(strings.TrimSpace(hc.UsernsMode))
		if un != "" && un != "host" {
			s.UserNamespace = true
		}
	}
	if p.Config != nil {
		u := strings.TrimSpace(p.Config.User)
		// Rootless / non-root user: a UID other than 0/root, or a user namespace.
		if u != "" && u != "0" && u != "root" && !strings.HasPrefix(u, "0:") {
			s.Rootless = true
		}
	}
	if s.UserNamespace {
		s.Rootless = true
	}
	return s, true
}

func hasUnconfinedSeccomp(opts []string) bool {
	for _, o := range opts {
		if strings.EqualFold(strings.TrimSpace(o), "seccomp=unconfined") {
			return true
		}
	}
	return false
}
