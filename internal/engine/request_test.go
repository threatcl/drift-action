package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/deps"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/model"
)

const testModel = `spec_version = "0.7.0"

threatmodel "login service" {
  description = "Login service for the customer web app"
  author      = "@test"

  threat "credential stuffing" {
    description = "Automated credential stuffing against POST /login"
    impacts     = ["Confidentiality"]
    stride      = ["Spoofing"]

    control "login rate limiting" {
      description = "Per-IP token-bucket rate limiting on POST /login, implemented in internal/auth/ratelimit.go"
      implemented = true
    }
  }
}
`

// testWorkspace writes a threat model plus the file its prose references, and
// returns the loaded assertions. The reference is what makes context stuffing
// engage: SelectContext sends the intersection of referenced and touched.
func testWorkspace(t *testing.T) (string, *model.Assertions) {
	t.Helper()
	dir := t.TempDir()

	write := func(rel, contents string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.tm.hcl", testModel)
	write("internal/auth/ratelimit.go", "package auth\n\nfunc Allow(ip string) bool { return true }\n")

	assertions, err := model.LoadIn(dir, "app.tm.hcl")
	if err != nil {
		t.Fatalf("loading the test model: %v", err)
	}
	return dir, assertions
}

// TestAssembleRequestSetsEveryField guards the drift that put this package
// here. The corpus built its own llm.ReviewRequest and stopped setting
// Categories, so the ENABLED CATEGORIES prompt section was never exercised by
// a recording and nobody noticed. Reflecting over the struct means a field
// added to ReviewRequest and not wired in here fails a free test, rather than
// reaching production while the quality corpus keeps measuring a request
// without it.
func TestAssembleRequestSetsEveryField(t *testing.T) {
	dir, assertions := testWorkspace(t)

	cfg := config.Default()
	cfg.Categories = []string{"phantom_control"}

	changes := []diff.Change{
		{
			Path:   "internal/auth/ratelimit.go",
			Status: "modified",
			Patch:  "@@ -1,3 +1,3 @@\n package auth\n \n-func Allow(ip string) bool { return true }\n+func Allow(ip string) bool { return false }\n",
		},
		{
			Path:   "go.mod",
			Status: "modified",
			Patch:  "@@ -3,3 +3,3 @@\n require (\n-	github.com/example/thing v1.2.0\n+	github.com/example/thing v1.3.0\n )\n",
		},
	}

	assembly := AssembleRequest(cfg, RequestInput{
		Workspace:     dir,
		Assertions:    assertions,
		Kept:          changes,
		ManifestFacts: deps.Facts(changes),
	})

	request := reflect.ValueOf(assembly.Request)
	for i := range request.NumField() {
		if request.Field(i).IsZero() {
			t.Errorf("ReviewRequest.%s was left at its zero value — wire it into AssembleRequest, or the corpus measures a request the action does not send",
				request.Type().Field(i).Name)
		}
	}

	// The one the corpus actually lost. Worth asserting by name too: a future
	// reader deleting the reflection loop should still fail here.
	if len(assembly.Request.Categories) != 1 || assembly.Request.Categories[0] != "phantom_control" {
		t.Errorf("Categories did not reach the request: %v", assembly.Request.Categories)
	}
	if len(assembly.Request.ContextFiles) != 1 || assembly.Request.ContextFiles[0].Path != "internal/auth/ratelimit.go" {
		t.Errorf("context stuffing did not send the referenced-and-touched file: %v", assembly.Request.ContextFiles)
	}
}

// TestFilterChangesDoesNotAliasTriggerPaths pins the slices.Concat in
// FilterChanges. Appending the referenced paths onto cfg.TriggerPaths would
// write through to its backing array whenever it has spare capacity, quietly
// growing the caller's config as a side effect of filtering.
func TestFilterChangesDoesNotAliasTriggerPaths(t *testing.T) {
	_, assertions := testWorkspace(t)

	cfg := config.Default()
	cfg.TriggerPaths = append(make([]string, 0, 8), "prompts/")

	FilterChanges(cfg, assertions, []diff.Change{
		{Path: "internal/auth/ratelimit.go", Status: "modified"},
	})

	if len(cfg.TriggerPaths) != 1 || cfg.TriggerPaths[0] != "prompts/" {
		t.Errorf("FilterChanges mutated cfg.TriggerPaths: %v", cfg.TriggerPaths)
	}
	if spare := cfg.TriggerPaths[:cap(cfg.TriggerPaths)]; spare[1] != "" {
		t.Errorf("FilterChanges wrote into TriggerPaths' spare capacity: %q", spare[1])
	}
}
