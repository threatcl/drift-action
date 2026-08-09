package deps

import (
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/diff"
)

const goModPatch = `@@ -5,8 +5,9 @@ require (
 	github.com/threatcl/spec v0.7.0
+	github.com/getsentry/sentry-go v0.28.0
-	github.com/old/dep v1.4.0
-	github.com/bumped/lib v1.2.0
+	github.com/bumped/lib v2.0.0
 )
`

func TestFactsExtractsEveryChangeKind(t *testing.T) {
	facts := Facts([]diff.Change{
		{Path: "go.mod", Patch: goModPatch},
		{Path: "internal/auth/login.go", Patch: "@@ -1,2 +1,3 @@\n package auth\n+// not a manifest\n"},
	})

	if len(facts) != 3 {
		t.Fatalf("facts = %d, want 3: %+v", len(facts), facts)
	}

	byName := map[string]Delta{}
	for _, fact := range facts {
		byName[fact.Name] = fact
	}
	if added := byName["github.com/getsentry/sentry-go"]; !added.Added() || added.Line == 0 {
		t.Errorf("added fact = %+v, want an addition with a line number", added)
	}
	if removed := byName["github.com/old/dep"]; !removed.Removed() {
		t.Errorf("removed fact = %+v", removed)
	}
	if bumped := byName["github.com/bumped/lib"]; !bumped.MajorBump() {
		t.Errorf("bumped fact = %+v, want a major bump", bumped)
	}
}

func TestRenderStatesFactsNotJudgements(t *testing.T) {
	out := Render(Facts([]diff.Change{{Path: "go.mod", Patch: goModPatch}}))

	for _, want := range []string{
		"added: github.com/getsentry/sentry-go v0.28.0 (go.mod:6)",
		"removed: github.com/old/dep v1.4.0 (go.mod)",
		"changed: github.com/bumped/lib from v1.2.0 to v2.0.0 (major version change)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered facts missing %q:\n%s", want, out)
		}
	}

	// The prompt asks the model to judge; this package must not pre-empt it.
	for _, unwanted := range []string{"undocumented", "third_party_dependency", "should", "finding"} {
		if strings.Contains(strings.ToLower(out), unwanted) {
			t.Errorf("rendered facts editorialise with %q:\n%s", unwanted, out)
		}
	}
}

// Absence is information: without it the model can infer dependency drift
// from unrelated code changes.
func TestRenderStatesAbsenceExplicitly(t *testing.T) {
	out := Render(Facts([]diff.Change{{Path: "server/server.go", Patch: "@@ -1,1 +1,2 @@\n x\n+y\n"}}))
	if !strings.Contains(out, "No dependency manifest changed") {
		t.Errorf("expected an explicit statement of absence:\n%s", out)
	}
}
