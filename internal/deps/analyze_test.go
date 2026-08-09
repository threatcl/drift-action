package deps

import (
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/model"
)

var testModel = ModelDeps{
	Path:       "payments.tm.hcl",
	AnchorLine: 3,
	Assertions: []model.DependencyAssertion{
		{Name: "Sentry", Uptime: "degraded", Line: 40},
		{Name: "Stripe", Uptime: "operational", Line: 50},
		{Name: "Retired Vendor", Uptime: "none", Line: 60},
	},
}

func analyzePatch(file, patch string) []findings.Finding {
	found, _ := Analyze([]diff.Change{{Path: file, Patch: patch}}, testModel)
	return found
}

// A new dependency the model says nothing about is the common case.
func TestUndocumentedDependency(t *testing.T) {
	found := analyzePatch("go.mod", `@@ -5,6 +5,7 @@ require (
 	github.com/threatcl/spec v0.7.0
+	github.com/newvendor/sdk v1.0.0
 )
`)
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(found), found)
	}

	finding := found[0]
	if finding.Category != findings.CategoryDependencyDrift {
		t.Errorf("category = %q", finding.Category)
	}
	if finding.Severity != findings.SeverityReviewRecommended {
		t.Errorf("severity = %q, want review_recommended", finding.Severity)
	}
	// One context line at 5, so the addition lands at 6.
	if len(finding.Evidence) == 0 || finding.Evidence[0].Line != 6 {
		t.Errorf("evidence = %+v, want a citation at line 6", finding.Evidence)
	}
	if finding.ModelExcerpt.File != "payments.tm.hcl" || finding.ModelExcerpt.Line != 3 {
		t.Errorf("model excerpt = %+v, want the anchor line", finding.ModelExcerpt)
	}
	if !strings.Contains(finding.AgentPrompt, "payments.tm.hcl") {
		t.Errorf("agent prompt should name the model file: %q", finding.AgentPrompt)
	}
}

// A documented dependency must not be reported as undocumented just because
// the model names it in prose ("Sentry") and the manifest by module path.
func TestDocumentedDependencyIsQuiet(t *testing.T) {
	found := analyzePatch("go.mod", `@@ -5,6 +5,7 @@ require (
 	github.com/threatcl/spec v0.7.0
+	github.com/getsentry/sentry-go v0.28.0
 )
`)
	if len(found) != 0 {
		t.Errorf("documented dependency should not be reported: %+v", found)
	}
}

func TestOrphanedAssertion(t *testing.T) {
	found := analyzePatch("go.mod", `@@ -5,7 +5,6 @@ require (
 	github.com/threatcl/spec v0.7.0
-	github.com/retired-vendor/client v1.0.0
 )
`)
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Title, "Retired Vendor") {
		t.Errorf("title = %q, want it to name the orphaned block", found[0].Title)
	}
	if found[0].ModelExcerpt.Line != 60 {
		t.Errorf("model excerpt line = %d, want the block's line", found[0].ModelExcerpt.Line)
	}
}

// A major bump only matters when the model says the dependency is operational.
func TestMajorBumpOnlyForOperationalDeps(t *testing.T) {
	operational := analyzePatch("package.json", `@@ -8,9 +8,9 @@
   "dependencies": {
-    "stripe": "^13.0.0",
+    "stripe": "^14.0.0",
   },
`)
	if len(operational) != 1 || !strings.Contains(operational[0].Title, "Major version bump") {
		t.Fatalf("operational bump should be reported: %+v", operational)
	}

	degraded := analyzePatch("go.mod", `@@ -5,6 +5,6 @@ require (
-	github.com/getsentry/sentry-go v0.28.0
+	github.com/getsentry/sentry-go v1.0.0
 )
`)
	if len(degraded) != 0 {
		t.Errorf("non-operational bump should stay quiet: %+v", degraded)
	}
}

func TestNonManifestFilesIgnored(t *testing.T) {
	found := analyzePatch("internal/auth/login.go", `@@ -1,2 +1,3 @@
 package auth
+// github.com/newvendor/sdk v1.0.0
`)
	if len(found) != 0 {
		t.Errorf("source files are not manifests: %+v", found)
	}
}

// A wholesale manifest refresh must not bury every other category, and the
// suppressed count must be reported rather than dropped silently.
func TestFindingsAreCappedAndCounted(t *testing.T) {
	var b strings.Builder
	b.WriteString("@@ -5,1 +5,20 @@ require (\n")
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		b.WriteString("+\tgithub.com/vendor-" + name + "/sdk v1.0.0\n")
	}

	found, omitted := Analyze([]diff.Change{{Path: "go.mod", Patch: b.String()}}, testModel)
	if len(found) != MaxFindings {
		t.Errorf("findings = %d, want the cap of %d", len(found), MaxFindings)
	}
	if omitted != 2 {
		t.Errorf("omitted = %d, want 2", omitted)
	}
}
