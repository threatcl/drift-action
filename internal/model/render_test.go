package model

import (
	"strings"
	"testing"
)

func TestRenderCitesLines(t *testing.T) {
	a, err := Load("../../testdata/simple.tm.hcl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out := a.Render()

	for _, want := range []string{
		`threat "credential stuffing" (../../testdata/simple.tm.hcl:12)`,
		`control "login rate limiting" implemented=true (../../testdata/simple.tm.hcl:17)`,
		`information_asset "user credentials" classification=Restricted`,
		`third_party_dependency "identity provider" uptime_dependency=degraded`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered assertions missing %q:\n%s", want, out)
		}
	}
	// Empty sections are stated rather than omitted: the model saying nothing
	// about DFDs is itself information the reviewer needs.
	if !strings.Contains(out, "### Data flow diagrams\n(none)") {
		t.Errorf("expected an explicit empty DFD section:\n%s", out)
	}
}

func TestSummary(t *testing.T) {
	a, err := Load("../../testdata/simple.tm.hcl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s := a.Summary()
	if s.Threats != 1 || s.Controls != 1 || s.ImplementedControls != 1 {
		t.Errorf("summary counts = %+v", s)
	}
	if got := s.String(); !strings.Contains(got, "1 threat") || !strings.Contains(got, "1 control (1 implemented)") {
		t.Errorf("summary string = %q", got)
	}
}

func TestReferencedPaths(t *testing.T) {
	a := &Assertions{}
	// Exercise the extractor directly: it drives the diff filter, so a missed
	// path means changes to code the model talks about get filtered out.
	got := pathPattern.FindAllString(
		"Rate limiting middleware in internal/mw/rate.go, config at deploy/app.yaml, and prose about a thing.", -1)

	want := map[string]bool{"internal/mw/rate.go": true, "deploy/app.yaml": true}
	if len(got) != len(want) {
		t.Fatalf("matched %v, want %v", got, want)
	}
	for _, match := range got {
		if !want[match] {
			t.Errorf("unexpected match %q", match)
		}
	}
	if paths := a.ReferencedPaths(); len(paths) != 0 {
		t.Errorf("empty model should reference no paths, got %v", paths)
	}
}
