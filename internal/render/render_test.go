package render

import (
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/findings"
)

func TestCommentCleanReport(t *testing.T) {
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{
		ModelPath:    "payments.tm.hcl",
		ModelSummary: "3 threats, 2 controls (1 implemented)",
		AnalysisMode: "deterministic checks only",
	})

	if !strings.Contains(out, StickyMarker) {
		t.Fatalf("comment missing sticky marker:\n%s", out)
	}
	if !strings.Contains(out, "No drift detected") {
		t.Errorf("clean report should say so plainly:\n%s", out)
	}
	if !strings.Contains(out, "payments.tm.hcl") {
		t.Errorf("context block should name the model:\n%s", out)
	}
}

// A report with no findings that is not a clean result must never read as
// clean — that is the failure mode that gets a security bot uninstalled.
func TestCommentUnassessedIsNotClean(t *testing.T) {
	out := Comment(&findings.Report{
		NoDrift: false,
		Summary: "The threat model makes no falsifiable claims about the code.",
	}, ContextInfo{})

	if strings.Contains(out, "No drift detected") {
		t.Errorf("unassessed report must not claim no drift:\n%s", out)
	}
	if !strings.Contains(out, "no falsifiable claims") {
		t.Errorf("unassessed report should carry its summary:\n%s", out)
	}
}

func TestCommentRendersFinding(t *testing.T) {
	out := Comment(&findings.Report{
		Summary: "1 phantom control.",
		Findings: []findings.Finding{{
			Category:     findings.CategoryPhantomControl,
			Severity:     findings.SeverityActionRequired,
			Title:        `Phantom control: "rate limiting on login"`,
			ModelExcerpt: findings.ModelExcerpt{File: "payments.tm.hcl", Line: 84, Quote: "implemented = true"},
			Evidence: []findings.Evidence{
				{File: "internal/mw/rate.go", Line: 12, Note: "middleware deleted"},
			},
			Relevance:    findings.Relevance{Rating: "strong", Justification: "only implementation removed"},
			SuggestedFix: "set implemented = false",
			AgentPrompt:  "Update payments.tm.hcl: ...",
		}},
	}, ContextInfo{})

	for _, want := range []string{
		"Action required",
		"`payments.tm.hcl:84`",
		"`internal/mw/rate.go:12`",
		"Agent prompt",
		"🧟 Phantom controls (1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("comment missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Review recommended") {
		t.Errorf("empty severity section should be omitted:\n%s", out)
	}
}

// A line number the engine could not determine must not render as ":0".
func TestLocationOmitsUnknownLine(t *testing.T) {
	if got := location("payments.tm.hcl", 0); got != "`payments.tm.hcl`" {
		t.Errorf("location with unknown line = %q", got)
	}
	if got := location("payments.tm.hcl", 84); got != "`payments.tm.hcl:84`" {
		t.Errorf("location = %q", got)
	}
}

func TestCheckConclusion(t *testing.T) {
	clean := &findings.Report{NoDrift: true}
	if conclusion, _ := CheckConclusion(clean, config.FailNever); conclusion != "success" {
		t.Errorf("clean conclusion = %q, want success", conclusion)
	}

	// No findings but partial coverage must not show a green check: that would
	// assert a clean bill of health the comment deliberately does not give.
	partial := &findings.Report{NoDrift: false, Summary: "only dependency checks ran"}
	conclusion, title := CheckConclusion(partial, config.FailNever)
	if conclusion != "neutral" {
		t.Errorf("partial-coverage conclusion = %q, want neutral", conclusion)
	}
	if strings.Contains(title, "No threat model drift detected") {
		t.Errorf("partial-coverage title overclaims: %q", title)
	}

	actionRequired := &findings.Report{Findings: []findings.Finding{
		{Severity: findings.SeverityActionRequired},
	}}
	if conclusion, _ := CheckConclusion(actionRequired, config.FailNever); conclusion != "neutral" {
		t.Errorf("default conclusion = %q, want neutral", conclusion)
	}
	if conclusion, _ := CheckConclusion(actionRequired, config.FailOnActionRequired); conclusion != "failure" {
		t.Errorf("opt-in fail conclusion = %q, want failure", conclusion)
	}

	reviewOnly := &findings.Report{Findings: []findings.Finding{
		{Severity: findings.SeverityReviewRecommended},
	}}
	if conclusion, _ := CheckConclusion(reviewOnly, config.FailOnActionRequired); conclusion != "neutral" {
		t.Errorf("review-only under fail-on-action-required = %q, want neutral", conclusion)
	}
}
