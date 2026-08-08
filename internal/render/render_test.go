package render

import (
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/findings"
)

func TestCommentCarriesStickyMarker(t *testing.T) {
	out := Comment(&findings.Report{NoDrift: true})
	if !strings.Contains(out, StickyMarker) {
		t.Fatalf("comment missing sticky marker: %q", out)
	}
	if !strings.Contains(out, "No drift detected") {
		t.Errorf("clean report should say so plainly: %q", out)
	}
}

func TestCheckSummary(t *testing.T) {
	conclusion, _ := CheckSummary(&findings.Report{NoDrift: true})
	if conclusion != "success" {
		t.Errorf("clean conclusion = %q, want success", conclusion)
	}
	conclusion, _ = CheckSummary(&findings.Report{Findings: []findings.Finding{{Title: "x"}}})
	if conclusion != "neutral" {
		t.Errorf("findings conclusion = %q, want neutral", conclusion)
	}
}
