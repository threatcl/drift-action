package prompts

import (
	"regexp"
	"strings"
	"testing"
)

// Guards against accidental truncation of the embedded prompt: every drift
// category heading and the evidence rule must survive edits.
func TestDriftCICarriesTheSharedIP(t *testing.T) {
	headings := []string{
		"### Stale assertions",
		"### Phantom controls",
		"### New unmodeled surface",
		"### DFD drift",
		"### Third-party dependency drift",
		"### Unclassified data",
	}
	for _, h := range headings {
		if !strings.Contains(DriftCI, h) {
			t.Errorf("drift-ci.md missing heading %q", h)
		}
	}
	evidenceRule := "A drift finding without a code reference"
	if !strings.Contains(DriftCI, evidenceRule) {
		t.Error("drift-ci.md missing the evidence rule")
	}
	if !strings.Contains(UpstreamThreatDrift, evidenceRule) {
		t.Error("vendored upstream prompt missing the evidence rule")
	}
}

func TestSourceRecordsFullCommit(t *testing.T) {
	if !regexp.MustCompile(`(?m)^commit: [0-9a-f]{40}$`).MatchString(UpstreamSource) {
		t.Errorf("SOURCE must pin a full 40-char commit SHA:\n%s", UpstreamSource)
	}
}
