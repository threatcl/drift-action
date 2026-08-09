package diff

import (
	"strings"
	"testing"
)

func TestRenderOrdersByPathAndLabelsStatus(t *testing.T) {
	text, omitted := Render([]Change{
		{Path: "z.go", Status: "added", Patch: "@@ -0,0 +1 @@\n+package z"},
		{Path: "a.go", Status: "renamed", OldPath: "old/a.go", Patch: "@@ -1 +1 @@\n-x\n+y"},
	}, 0)

	if len(omitted) != 0 {
		t.Fatalf("omitted = %v, want none", omitted)
	}
	if strings.Index(text, "a.go") > strings.Index(text, "z.go") {
		t.Error("files are not in path order")
	}
	if !strings.Contains(text, "--- a.go (renamed from old/a.go) ---") {
		t.Errorf("rename not labelled:\n%s", text)
	}
	if !strings.Contains(text, "--- z.go (added) ---") {
		t.Errorf("status not labelled:\n%s", text)
	}
}

// A file GitHub returned without a patch is not an unchanged file, and the
// prompt has to say which it is.
func TestRenderMarksMissingPatch(t *testing.T) {
	text, _ := Render([]Change{{Path: "logo.png", Status: "modified"}}, 0)
	if !strings.Contains(text, "no patch") {
		t.Errorf("missing patch not called out:\n%s", text)
	}
}

// Over-budget files are reported, not dropped silently, and one oversized
// patch must not cost the review every file after it.
func TestRenderReportsWhatDidNotFit(t *testing.T) {
	big := strings.Repeat("x", 500)
	text, omitted := Render([]Change{
		{Path: "a-huge.go", Status: "modified", Patch: big},
		{Path: "b-small.go", Status: "modified", Patch: "+ok"},
	}, 200)

	if len(omitted) != 1 || omitted[0] != "a-huge.go" {
		t.Fatalf("omitted = %v, want [a-huge.go]", omitted)
	}
	if !strings.Contains(text, "b-small.go") {
		t.Errorf("a later small file was lost to an earlier large one:\n%s", text)
	}
	if len(text) > 200 {
		t.Errorf("rendered %d bytes, over the 200-byte budget", len(text))
	}
}

func TestPaths(t *testing.T) {
	got := Paths([]Change{{Path: "b.go"}, {Path: "a.go"}})
	if len(got) != 2 || got[0] != "b.go" || got[1] != "a.go" {
		t.Errorf("Paths = %v", got)
	}
}
