package llm

import (
	"strings"
	"testing"
)

// The library section is emitted only when there is one, and sits between
// ENABLED CATEGORIES and DEPENDENCY MANIFEST CHANGES. No placeholder when
// absent: local mode's sections are every corpus recording's fingerprint.
func TestSectionsEmitLibraryOnlyWhenPresent(t *testing.T) {
	local := ReviewRequest{ModelAssertions: "A", Categories: []string{"dfd_drift"}}
	if body := local.Sections(); strings.Contains(body, "ORG LIBRARY") {
		t.Errorf("local request emitted a library section:\n%s", body)
	}

	withLibrary := local
	withLibrary.Library = "Threats:\nT-001 | Account takeover\n"
	body := withLibrary.Sections()
	last := -1
	for _, want := range []string{
		"=== THREAT MODEL ASSERTIONS ===",
		"=== ENABLED CATEGORIES ===",
		"=== ORG LIBRARY ===", "T-001 | Account takeover",
		"=== DEPENDENCY MANIFEST CHANGES ===",
		"=== CONTEXT FILES ===",
		"=== DIFF ===",
	} {
		at := strings.Index(body, want)
		if at < 0 {
			t.Fatalf("missing %q:\n%s", want, body)
		}
		if at < last {
			t.Fatalf("%q is out of order:\n%s", want, body)
		}
		last = at
	}

	// Whitespace-only is absent.
	blank := local
	blank.Library = "  \n"
	if blank.Sections() != local.Sections() {
		t.Error("a whitespace-only library changed the sections")
	}
}
