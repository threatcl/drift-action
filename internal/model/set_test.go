package model

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fixtures are testdata/set/{parent,child}.tm.hcl — a hierarchy split
// across two files — and testdata/extends.tm.hcl, the same hierarchy in one
// file. Line numbers below follow them; update both together.
const testdataRoot = "../../testdata"

// A child may name a parent declared in another file, and spec resolves the
// set as a whole, so the order model_paths lists them in must not matter.
func TestLoadSetCrossFileExtendsEitherOrder(t *testing.T) {
	for _, order := range [][]string{
		{"set/parent.tm.hcl", "set/child.tm.hcl"},
		{"set/child.tm.hcl", "set/parent.tm.hcl"},
	} {
		a, err := LoadSet(testdataRoot, order)
		if err != nil {
			t.Fatalf("LoadSet(%v): %v", order, err)
		}
		if !reflect.DeepEqual(a.Sources, order) {
			t.Errorf("Sources = %v, want the configured order %v", a.Sources, order)
		}
		if got := len(a.Models()); got != 2 {
			t.Errorf("LoadSet(%v) parsed %d models, want 2", order, got)
		}
	}
}

// The configured order is the render order, so a reader of the prompt meets
// the models in the order they listed them.
func TestRenderSetFollowsConfiguredOrder(t *testing.T) {
	a, err := LoadSet(testdataRoot, []string{"set/child.tm.hcl", "set/parent.tm.hcl"})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	out := a.Render()

	header := "Threat model files, parsed together as one set:\n- set/child.tm.hcl\n- set/parent.tm.hcl\n"
	if !strings.HasPrefix(out, header) {
		t.Errorf("rendered set should open by listing every file in order:\n%s", out)
	}
	child := strings.Index(out, `## Threat model "payments api"`)
	parent := strings.Index(out, `## Threat model "payments"`)
	if child < 0 || parent < 0 || child > parent {
		t.Errorf("models should render in configured order (child at %d, parent at %d):\n%s", child, parent, out)
	}
}

// A citation must name the file its block is physically in. Citing the
// child's file for a block in the parent's would send whoever acts on the
// finding to a file that does not contain it.
func TestLoadSetCitesEachBlocksOwnFile(t *testing.T) {
	a, err := LoadSet(testdataRoot, []string{"set/parent.tm.hcl", "set/child.tm.hcl"})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}

	tests := []struct {
		address []string
		want    Location
	}{
		{[]string{"threatmodel", "payments"}, Location{"set/parent.tm.hcl", 3}},
		{[]string{"threatmodel", "payments", "threat", "card data exposure", "control", "log redaction"}, Location{"set/parent.tm.hcl", 18}},
		{[]string{"threatmodel", "payments api"}, Location{"set/child.tm.hcl", 3}},
		{[]string{"threatmodel", "payments api", "threat", "duplicate capture", "control", "idempotency keys"}, Location{"set/child.tm.hcl", 14}},
		{[]string{"threatmodel", "payments api", "third_party_dependency", "card processor"}, Location{"set/child.tm.hcl", 20}},
	}
	for _, tt := range tests {
		if got := a.Lines.Locate(tt.address...); got != tt.want {
			t.Errorf("Locate(%q) = %+v, want %+v", tt.address, got, tt.want)
		}
	}

	out := a.Render()
	for _, want := range []string{
		`- control "log redaction" implemented=true (set/parent.tm.hcl:18)`,
		`- control "idempotency keys" implemented=true (set/child.tm.hcl:14)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered set missing %q:\n%s", want, out)
		}
	}
}

// spec copies a parent's threats into every child. Rendered as resolved,
// each inherited threat appeared twice — the child's copy uncited — and the
// reviewer could not tell the two were one assertion. Each must render once,
// under the model that declares it, and the child must say what it inherits.
func TestRenderInheritedItemsOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func() (*Assertions, error)
	}{
		{"one file", func() (*Assertions, error) { return LoadIn(testdataRoot, "extends.tm.hcl") }},
		{"split across files", func() (*Assertions, error) {
			return LoadSet(testdataRoot, []string{"set/parent.tm.hcl", "set/child.tm.hcl"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := tc.load()
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			out := a.Render()

			for _, item := range []string{
				`- threat "card data exposure"`,
				`- control "log redaction"`,
				`- information_asset "cardholder data"`,
			} {
				if got := strings.Count(out, item); got != 1 {
					t.Errorf("%s rendered %d times, want once:\n%s", item, got, out)
				}
			}
			// Every threat and control line carries a citation: the uncited
			// copy is what inheritance used to leave behind.
			for _, line := range strings.Split(out, "\n") {
				trimmed := strings.TrimSpace(line)
				if (strings.HasPrefix(trimmed, "- threat ") || strings.HasPrefix(trimmed, "- control ")) &&
					!strings.HasSuffix(trimmed, ")") {
					t.Errorf("uncited assertion %q:\n%s", trimmed, out)
				}
			}

			for _, want := range []string{
				"id: payments\n",
				"id: payments.api\n",
				"extends: payments — this model also asserts that model's threats and their controls",
				"an item declared here with the same name overrides the inherited one",
				"Data flow diagrams are not inherited.",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("rendered hierarchy missing %q:\n%s", want, out)
				}
			}
			if got := strings.Count(out, "extends: "); got != 1 {
				t.Errorf("extends line rendered %d times, want once (only the child extends):\n%s", got, out)
			}
		})
	}
}

// A grandchild inherits what its parent inherited, so its line has to say so;
// and a parent whose name is not its id is named, since the reviewer finds
// models by their heading.
func TestRenderExtendsChain(t *testing.T) {
	root := t.TempDir()
	writeModel(t, root, "chain.tm.hcl", `spec_version = "0.7.0"

threatmodel "Platform" {
  id     = "platform"
  author = "@xntrik"
}

threatmodel "Payments" {
  id      = "platform.payments"
  extends = "platform"
  author  = "@xntrik"
}

threatmodel "Payments API" {
  id      = "platform.payments.api"
  extends = "platform.payments"
  author  = "@xntrik"
}
`)
	a, err := LoadIn(root, "chain.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	out := a.Render()

	for _, want := range []string{
		`extends: platform (threat model "Platform") — this model also asserts that model's threats and their controls, information assets, use cases, exclusions and third-party dependencies. They`,
		`extends: platform.payments (threat model "Payments") — this model also asserts that model's threats and their controls, information assets, use cases, exclusions and third-party dependencies, including what it inherits in turn.`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chain missing %q:\n%s", want, out)
		}
	}
}

// Context used reported 3 threats for a file that declares 2 when inherited
// items were counted per model. Counts are over declared items.
func TestSummaryCountsDeclaredItems(t *testing.T) {
	a, err := LoadIn(testdataRoot, "extends.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	s := a.Summary()
	if s.Threats != 2 || s.Controls != 2 || s.Assets != 1 {
		t.Errorf("summary = %d threats, %d controls, %d assets; want the declared 2, 2, 1",
			s.Threats, s.Controls, s.Assets)
	}

	a, err = LoadSet(testdataRoot, []string{"set/parent.tm.hcl", "set/child.tm.hcl"})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	s = a.Summary()
	if want := []string{"set/parent.tm.hcl", "set/child.tm.hcl"}; !reflect.DeepEqual(s.Paths, want) {
		t.Errorf("summary Paths = %v, want every file %v", s.Paths, want)
	}
	if s.Threats != 2 || s.Controls != 2 || s.Assets != 1 || s.Dependencies != 1 {
		t.Errorf("summary = %+v, want the declared 2 threats, 2 controls, 1 asset, 1 dependency", s)
	}
	// Context stuffing hangs off these, so the set must contribute every
	// file's prose.
	if got, want := a.ReferencedPaths(), []string{"internal/api/capture.go", "internal/logging/redact.go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ReferencedPaths = %v, want %v", got, want)
	}
}

// Naming only the child used to fail with spec's own wording, which says
// nothing about the action's configuration. The error must name the fix. The
// spec wording is asserted too: explain matches on it, and a spec bump that
// rewords it would silently drop the hint.
func TestLoadChildAloneNamesTheFix(t *testing.T) {
	_, err := LoadIn(testdataRoot, "set/child.tm.hcl")
	if err == nil {
		t.Fatal("LoadIn(child alone): want an error, got nil")
	}
	for _, want := range []string{"model_paths", unknownExtends, "set/child.tm.hcl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// spec parses sets from HCL only, so a JSON model in a list has to be refused
// by name rather than fail as a syntax error.
func TestLoadSetRejectsJSON(t *testing.T) {
	root := t.TempDir()
	writeModel(t, root, "a.tm.hcl", "spec_version = \"0.7.0\"\n")
	writeModel(t, root, "b.json", "{}\n")

	_, err := LoadSet(root, []string{"a.tm.hcl", "b.json"})
	if err == nil {
		t.Fatal("LoadSet with a JSON file: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "b.json") || !strings.Contains(err.Error(), "HCL") {
		t.Errorf("error = %q, want it to name b.json and say sets are HCL-only", err)
	}
}

// A missing file is named the way the reader configured it. The runner's
// absolute path means nothing to them.
func TestLoadSetMissingFileIsRepoRelative(t *testing.T) {
	root := t.TempDir()
	writeModel(t, root, "set/parent.tm.hcl", "spec_version = \"0.7.0\"\n")
	_, err := LoadSet(root, []string{"set/parent.tm.hcl", "set/missing.tm.hcl"})
	if err == nil {
		t.Fatal("LoadSet with a missing file: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "set/missing.tm.hcl") {
		t.Errorf("error = %q, want it to name the configured path", err)
	}
	if strings.Contains(err.Error(), root) {
		t.Errorf("error = %q, want no runner-absolute path in it", err)
	}
}

// model_paths comes from the pull request's own .threatcl-ci.hcl, and what a
// model file declares is sent to the LLM provider, so no entry may reach a
// file outside the checkout. The file outside is a valid model each time, so
// a refusal can only be the confinement and never a parse failure. Both
// routes are covered: the single-file one hands the path to spec's ParseFile,
// which would follow a symlink anywhere.
func TestLoadSetConfinedToCheckout(t *testing.T) {
	valid, err := os.ReadFile(filepath.Join(testdataRoot, "simple.tm.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "checkout")
	writeModel(t, base, "outside.tm.hcl", string(valid))
	writeModel(t, root, "inside.tm.hcl", string(valid))
	writeModel(t, root, "set/parent.tm.hcl", mustRead(t, filepath.Join(testdataRoot, "set/parent.tm.hcl")))
	symlink(t, filepath.Join(base, "outside.tm.hcl"), filepath.Join(root, "escape-absolute.tm.hcl"))
	symlink(t, "../outside.tm.hcl", filepath.Join(root, "escape-relative.tm.hcl"))
	symlink(t, "inside.tm.hcl", filepath.Join(root, "alias.tm.hcl"))

	for _, tc := range []struct {
		name string
		rels []string
	}{
		{"parent traversal", []string{"../outside.tm.hcl"}},
		{"absolute path", []string{filepath.Join(base, "outside.tm.hcl")}},
		{"absolute symlink out", []string{"escape-absolute.tm.hcl"}},
		{"relative symlink out", []string{"escape-relative.tm.hcl"}},
		{"symlink out within a set", []string{"set/parent.tm.hcl", "escape-relative.tm.hcl"}},
		{"traversal within a set", []string{"set/parent.tm.hcl", "../outside.tm.hcl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := LoadSet(root, tc.rels)
			if err == nil {
				t.Fatalf("LoadSet(%v) loaded %v; want it refused as outside the checkout", tc.rels, a.Sources)
			}
			// An absolute entry is echoed back as configured; a relative one
			// must not have the runner's path filled in.
			if !filepath.IsAbs(tc.rels[len(tc.rels)-1]) && strings.Contains(err.Error(), base) {
				t.Errorf("error = %q, want no runner-absolute path in it", err)
			}
		})
	}

	// A symlink that stays inside is an ordinary repo layout, not an escape.
	if _, err := LoadSet(root, []string{"alias.tm.hcl"}); err != nil {
		t.Errorf("a symlink resolving inside the checkout should load: %v", err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
}

// Listing a file twice is collapsed rather than handed to spec, which would
// reject the set for a duplicate model name. A list that collapses to one
// file takes the single-file route and renders exactly as that file alone.
func TestLoadSetCollapsesDuplicates(t *testing.T) {
	a, err := LoadSet(testdataRoot, []string{"set/parent.tm.hcl", "./set/parent.tm.hcl", "set/child.tm.hcl"})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if want := []string{"set/parent.tm.hcl", "set/child.tm.hcl"}; !reflect.DeepEqual(a.Sources, want) {
		t.Errorf("Sources = %v, want %v", a.Sources, want)
	}

	single, err := LoadSet(testdataRoot, []string{"simple.tm.hcl", "./simple.tm.hcl"})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	alone, err := LoadIn(testdataRoot, "simple.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	if single.Render() != alone.Render() {
		t.Errorf("a list collapsing to one file should render as that file alone:\n%s\n---\n%s",
			single.Render(), alone.Render())
	}
}

// The rendered assertions are part of every corpus recording's request
// fingerprint, so a one-file model without id or extends must render byte for
// byte as it did before multi-file sets existed — otherwise every recording
// stales. testdata/simple.render.golden was captured before that change. Do
// not regenerate it to make this pass: a deliberate render change for
// one-file repos also means re-recording the corpus for every provider.
func TestRenderSingleFileUnchanged(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(testdataRoot, "simple.render.golden"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	a, err := LoadIn(testdataRoot, "simple.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	if got := a.Render(); got != string(want) {
		t.Errorf("single-file render changed.\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func writeModel(t *testing.T, root, rel, contents string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
