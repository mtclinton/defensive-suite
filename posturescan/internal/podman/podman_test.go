package podman

import (
	"testing"

	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

const ociHardened = `{
  "ociVersion": "1.0.2",
  "process": {
    "noNewPrivileges": true,
    "capabilities": { "bounding": [], "effective": [], "permitted": [] }
  },
  "root": { "readonly": true },
  "linux": {
    "seccomp": { "defaultAction": "SCMP_ACT_ERRNO" },
    "uidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
    "namespaces": [ { "type": "user" }, { "type": "pid" } ]
  }
}`

const ociWeak = `{
  "ociVersion": "1.0.2",
  "process": {
    "noNewPrivileges": false,
    "capabilities": { "bounding": ["CAP_BPF","CAP_SYS_ADMIN","CAP_CHOWN"] }
  },
  "root": { "readonly": false },
  "linux": { "seccomp": null }
}`

const podmanInspectHardened = `[
  {
    "Name": "/web",
    "HostConfig": {
      "Privileged": false,
      "ReadonlyRootfs": true,
      "CapAdd": [],
      "CapDrop": ["ALL"],
      "SecurityOpt": ["no-new-privileges", "seccomp=/usr/share/containers/seccomp.json"],
      "UsernsMode": "auto"
    },
    "Config": { "User": "1000" }
  }
]`

const podmanInspectPrivileged = `[
  {
    "Name": "/danger",
    "HostConfig": {
      "Privileged": true,
      "CapAdd": ["CAP_SYS_ADMIN"],
      "SecurityOpt": ["seccomp=unconfined"],
      "UsernsMode": "host"
    },
    "Config": { "User": "root" }
  }
]`

func TestParseOCIHardened(t *testing.T) {
	s, ok := Parse([]byte(ociHardened))
	if !ok {
		t.Fatal("should parse OCI spec")
	}
	if !s.NoNewPrivs || !s.ReadOnlyRootfs || !s.SeccompPresent || !s.UserNamespace || !s.CapDropAll || !s.Rootless {
		t.Errorf("hardened OCI spec misparsed: %+v", s)
	}
	if len(s.DangerousCaps()) != 0 {
		t.Errorf("hardened spec should have no dangerous caps: %v", s.DangerousCaps())
	}
}

func TestParseOCIWeak(t *testing.T) {
	s, ok := Parse([]byte(ociWeak))
	if !ok {
		t.Fatal("should parse OCI spec")
	}
	if s.NoNewPrivs || s.ReadOnlyRootfs || s.SeccompPresent || s.CapDropAll {
		t.Errorf("weak spec should fail controls: %+v", s)
	}
	dc := s.DangerousCaps()
	if len(dc) != 2 {
		t.Errorf("want CAP_BPF + CAP_SYS_ADMIN, got %v", dc)
	}
}

func TestParsePodmanInspectHardened(t *testing.T) {
	s, ok := Parse([]byte(podmanInspectHardened))
	if !ok {
		t.Fatal("should parse podman inspect")
	}
	if s.Name != "web" {
		t.Errorf("name=%q", s.Name)
	}
	if !s.CapDropAll || !s.NoNewPrivs || !s.SeccompPresent || !s.ReadOnlyRootfs || !s.UserNamespace || !s.Rootless {
		t.Errorf("hardened podman spec misparsed: %+v", s)
	}
}

func TestParsePodmanInspectPrivileged(t *testing.T) {
	s, ok := Parse([]byte(podmanInspectPrivileged))
	if !ok {
		t.Fatal("should parse")
	}
	if !s.Privileged {
		t.Error("should be privileged")
	}
	if s.SeccompPresent {
		t.Error("seccomp=unconfined should not count as present")
	}
}

func TestParseUnrecognized(t *testing.T) {
	for _, in := range []string{"", "not json", `{"unrelated":true}`, "[]"} {
		if _, ok := Parse([]byte(in)); ok {
			t.Errorf("input %q should not parse as a spec", in)
		}
	}
}

func TestEvaluateScores(t *testing.T) {
	hardened, _ := Parse([]byte(ociHardened))
	if p := hardened.Evaluate().Percent(); p != 100 {
		t.Errorf("hardened score=%d want 100", p)
	}
	weak, _ := Parse([]byte(ociWeak))
	if p := weak.Evaluate().Percent(); p >= 50 {
		t.Errorf("weak score=%d want < 50", p)
	}
	priv, _ := Parse([]byte(podmanInspectPrivileged))
	if p := priv.Evaluate().Percent(); p != 0 {
		t.Errorf("privileged score=%d want 0", p)
	}
}

func TestFindingsClassification(t *testing.T) {
	hardened, _ := Parse([]byte(ociHardened))
	fs := hardened.Findings()
	if len(fs) != 1 || fs[0].Severity != report.SeverityInfo {
		t.Errorf("hardened spec should yield one info finding, got %+v", fs)
	}

	priv, _ := Parse([]byte(podmanInspectPrivileged))
	fs = priv.Findings()
	var high bool
	for _, f := range fs {
		if f.Severity == report.SeverityHigh {
			high = true
		}
	}
	if !high {
		t.Error("privileged container should yield a High finding")
	}
}

func TestSeccompAllowAllNotPresent(t *testing.T) {
	// An allow-everything default (SCMP_ACT_ALLOW) with no narrowing syscall rules
	// is functionally unconfined and must NOT be scored as a seccomp control.
	allowAll := `{
	  "process": { "noNewPrivileges": true },
	  "linux": { "seccomp": { "defaultAction": "SCMP_ACT_ALLOW" } }
	}`
	s, ok := Parse([]byte(allowAll))
	if !ok {
		t.Fatal("should parse OCI spec")
	}
	if s.SeccompPresent {
		t.Error("allow-all seccomp (SCMP_ACT_ALLOW, no rules) must not count as present")
	}

	// SCMP_ACT_LOG with no rules is likewise unconfined.
	logAll := `{"process":{},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_LOG"}}}`
	if s, _ := Parse([]byte(logAll)); s.SeccompPresent {
		t.Error("allow-all-log seccomp must not count as present")
	}

	// An allow-default WITH narrowing syscall rules (e.g. deny a set) is a real
	// filter and should count.
	allowWithRules := `{"process":{},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ERRNO"}]}}}`
	if s, _ := Parse([]byte(allowWithRules)); !s.SeccompPresent {
		t.Error("allow-default with narrowing syscall rules should count as present")
	}

	// A real deny-by-default filter still counts.
	denyDefault := `{"process":{},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO"}}}`
	if s, _ := Parse([]byte(denyDefault)); !s.SeccompPresent {
		t.Error("deny-by-default seccomp should count as present")
	}
}

func TestDedupeCaps(t *testing.T) {
	got := dedupeCaps([]string{"CAP_BPF", "bpf", "CAP_CHOWN", "", "CAP_BPF"})
	if len(got) != 2 || got[0] != "CAP_BPF" || got[1] != "CAP_CHOWN" {
		t.Errorf("dedupeCaps=%v", got)
	}
}
