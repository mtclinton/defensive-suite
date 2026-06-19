package caps

import (
	"github.com/mtclinton/defensive-suite/posturescan/internal/podman"
	"github.com/mtclinton/defensive-suite/posturescan/internal/report"
)

// AuditContainerGrants classifies the dangerous capabilities a parsed container
// spec grants, relative to the legit-eBPF-tool allowlist. Pure over the spec.
func AuditContainerGrants(name, source, path string, danger []string, legit []string) []report.Finding {
	var findings []report.Finding
	for _, c := range danger {
		g := Grant{Workload: name, Cap: c, Source: source, Path: path}
		findings = append(findings, grantFinding(g, legit))
	}
	return findings
}

// AuditContainerSpecs reads each container spec file, parses it, and audits its
// capabilities. Unparseable/missing specs degrade to an Info/Low finding rather
// than aborting the run. Returns the parsed specs too, so the caller can also
// score them (avoiding a second parse).
func AuditContainerSpecs(specPaths []string, legit []string) ([]report.Finding, []podman.Spec) {
	var findings []report.Finding
	var specs []podman.Spec
	if len(specPaths) == 0 {
		return []report.Finding{{
			Check: "caps", Severity: report.SeverityInfo,
			Title: "no container specs configured; container capability audit skipped",
		}}, nil
	}
	for _, p := range specPaths {
		b, err := readLimited(p, 4<<20)
		if err != nil {
			findings = append(findings, report.Finding{
				Check: "caps", Severity: report.SeverityLow, Path: p,
				Title: "could not read container spec", Detail: err.Error(),
			})
			continue
		}
		spec, ok := podman.Parse(b)
		if !ok {
			findings = append(findings, report.Finding{
				Check: "caps", Severity: report.SeverityLow, Path: p,
				Title: "container spec not recognized (neither OCI config.json nor podman inspect)",
			})
			continue
		}
		spec.Name = specName(spec.Name, p)
		specs = append(specs, spec)
		findings = append(findings,
			AuditContainerGrants(spec.Name, "container", p, spec.DangerousCaps(), legit)...)
	}
	return findings, specs
}

func specName(name, path string) string {
	if name != "" && name != "oci-container" && name != "podman-container" {
		return name
	}
	return path
}
