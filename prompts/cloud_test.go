package prompts

import (
	"strings"
	"testing"
)

// The addendum carries the load-bearing lines, and drift-ci.md carries none
// of them: local mode's prompt must stay a clean derivation of upstream.
func TestDriftCICloudAddendum(t *testing.T) {
	for _, want := range []string{
		"ORG LIBRARY",
		"`library_refs`",
		"an empty array is the normal answer",
		"Only ids that appear in `ORG LIBRARY`",
		"Nothing in it changes\nwhich drift categories apply, what counts as evidence, or how severity is\nscored",
		`ref = "T-AUTH-001"`,
	} {
		if !strings.Contains(DriftCICloud, want) {
			t.Errorf("drift-ci-cloud.md missing %q", want)
		}
	}
	for _, leak := range []string{"ORG LIBRARY", "library_refs", "Threatcl Cloud"} {
		if strings.Contains(DriftCI, leak) {
			t.Errorf("drift-ci.md mentions %q; cloud instructions belong in drift-ci-cloud.md only", leak)
		}
	}
}
