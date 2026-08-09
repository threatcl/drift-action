package llm

import (
	"strings"
	"testing"
)

func TestSectionsOrdersStableBeforeVolatile(t *testing.T) {
	body := ReviewRequest{
		ModelAssertions: "ASSERTIONS",
		ManifestFacts:   "MANIFEST",
		ContextFiles:    []ContextFile{{Path: "internal/auth/session.go", Contents: "package auth"}},
		Diff:            "DIFF",
	}.Sections()

	wantOrder := []string{
		"=== THREAT MODEL ASSERTIONS ===", "ASSERTIONS",
		"=== DEPENDENCY MANIFEST CHANGES ===", "MANIFEST",
		"=== CONTEXT FILES ===", "--- internal/auth/session.go ---", "package auth",
		"=== DIFF ===", "DIFF",
	}
	last := -1
	for _, want := range wantOrder {
		at := strings.Index(body, want)
		if at < 0 {
			t.Fatalf("section body is missing %q:\n%s", want, body)
		}
		if at < last {
			t.Fatalf("%q is out of order:\n%s", want, body)
		}
		last = at
	}
}

// An empty section says so. Silence invites the model to infer drift from
// whatever else is in the prompt.
func TestSectionsNamesEmptySections(t *testing.T) {
	body := ReviewRequest{ModelAssertions: "ASSERTIONS"}.Sections()

	for _, want := range []string{
		"No dependency manifest changed",
		"no file this pull request touches is referenced",
		"no file survived filtering",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not explain an empty section (%q):\n%s", want, body)
		}
	}
}

// Without this, the categories config setting is a silent no-op.
func TestSectionsRestrictsCategories(t *testing.T) {
	body := ReviewRequest{Categories: []string{"phantom_control", "dfd_drift"}}.Sections()
	if !strings.Contains(body, "phantom_control, dfd_drift") {
		t.Errorf("enabled categories not passed to the model:\n%s", body)
	}

	body = ReviewRequest{}.Sections()
	if strings.Contains(body, "ENABLED CATEGORIES") {
		t.Errorf("an unrestricted run should not narrow the categories:\n%s", body)
	}
}
