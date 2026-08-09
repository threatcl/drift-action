package deps

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/model"
)

// MaxFindings caps how many dependency findings one run reports. A large
// manifest refresh would otherwise bury every other category. The overflow
// count is returned rather than dropped silently.
const MaxFindings = 10

// ModelDeps is the model's side of the comparison.
type ModelDeps struct {
	// Path is the threat model file, cited when a finding is about something
	// the model fails to mention.
	Path string
	// AnchorLine is where a reader should look to add a missing block.
	AnchorLine int
	Assertions []model.DependencyAssertion
}

// Analyze compares manifest changes in the diff against the model's
// third_party_dependency blocks. It returns the findings plus the number
// suppressed by MaxFindings.
func Analyze(changes []diff.Change, m ModelDeps) ([]findings.Finding, int) {
	var found []findings.Finding

	for _, change := range changes {
		if !IsManifest(change.Path) || change.Patch == "" {
			continue
		}
		for _, delta := range Deltas(change.Path, change.Patch) {
			if finding, ok := assess(delta, m); ok {
				found = append(found, finding)
			}
		}
	}

	if len(found) > MaxFindings {
		return found[:MaxFindings], len(found) - MaxFindings
	}
	return found, 0
}

func assess(delta Delta, m ModelDeps) (findings.Finding, bool) {
	assertion, documented := matchAssertion(delta.Name, m.Assertions)

	switch {
	case delta.Added() && !documented:
		return undocumentedDependency(delta, m), true

	case delta.Removed() && documented:
		return orphanAssertion(delta, m, assertion), true

	case delta.MajorBump() && documented && assertion.Uptime == "operational":
		return operationalMajorBump(delta, m, assertion), true
	}
	return findings.Finding{}, false
}

func undocumentedDependency(delta Delta, m ModelDeps) findings.Finding {
	return findings.Finding{
		Category: findings.CategoryDependencyDrift,
		Severity: findings.SeverityReviewRecommended,
		Title:    fmt.Sprintf("Undocumented dependency added: %s", delta.Name),
		ModelExcerpt: findings.ModelExcerpt{
			File:  m.Path,
			Line:  m.AnchorLine,
			Quote: fmt.Sprintf("no third_party_dependency block covers %q", delta.Name),
		},
		Evidence: []findings.Evidence{{
			File: delta.File,
			Line: delta.Line,
			Note: fmt.Sprintf("%s %s added to %s", delta.Name, delta.NewVersion, delta.File),
		}},
		Relevance: findings.Relevance{
			Rating: "strong",
			Justification: "the manifest change is unambiguous; whether the dependency " +
				"warrants a threat model entry is a judgement call",
		},
		SuggestedFix: fmt.Sprintf("add a third_party_dependency block for %q", delta.Name),
		AgentPrompt: fmt.Sprintf(
			"Update %s: this PR adds the dependency %s (%s) in %s, and no "+
				"third_party_dependency block covers it. Add one — set uptime_dependency "+
				"according to what breaks if the dependency is unavailable, and describe "+
				"what data flows to it. If the dependency does not warrant modelling, say "+
				"so in the PR rather than adding a block.",
			m.Path, delta.Name, delta.NewVersion, delta.File),
	}
}

func orphanAssertion(delta Delta, m ModelDeps, assertion model.DependencyAssertion) findings.Finding {
	return findings.Finding{
		Category: findings.CategoryDependencyDrift,
		Severity: findings.SeverityReviewRecommended,
		Title:    fmt.Sprintf("Model still documents removed dependency: %q", assertion.Name),
		ModelExcerpt: findings.ModelExcerpt{
			File:  m.Path,
			Line:  assertion.Line,
			Quote: fmt.Sprintf("third_party_dependency %q uptime_dependency=%s", assertion.Name, assertion.Uptime),
		},
		Evidence: []findings.Evidence{{
			File: delta.File,
			Line: delta.Line,
			Note: fmt.Sprintf("%s removed from %s in this PR", delta.Name, delta.File),
		}},
		Relevance: findings.Relevance{
			Rating:        "moderate",
			Justification: "the manifest entry is gone; the dependency may still be reached another way",
		},
		SuggestedFix: fmt.Sprintf("remove the obsolete third_party_dependency block for %q, or correct its description", assertion.Name),
		AgentPrompt: fmt.Sprintf(
			"Update %s: the third_party_dependency block %q at line %d describes a "+
				"dependency whose manifest entry (%s) was removed from %s in this PR. "+
				"Confirm the dependency is genuinely gone, then remove the block. If it is "+
				"still reached some other way, update the description to say how.",
			m.Path, assertion.Name, assertion.Line, delta.Name, delta.File),
	}
}

func operationalMajorBump(delta Delta, m ModelDeps, assertion model.DependencyAssertion) findings.Finding {
	return findings.Finding{
		Category: findings.CategoryDependencyDrift,
		Severity: findings.SeverityReviewRecommended,
		Title: fmt.Sprintf("Major version bump of operational dependency: %q (%s to %s)",
			assertion.Name, delta.OldVersion, delta.NewVersion),
		ModelExcerpt: findings.ModelExcerpt{
			File:  m.Path,
			Line:  assertion.Line,
			Quote: fmt.Sprintf("third_party_dependency %q uptime_dependency=\"operational\"", assertion.Name),
		},
		Evidence: []findings.Evidence{{
			File: delta.File,
			Line: delta.Line,
			Note: fmt.Sprintf("%s bumped %s to %s", delta.Name, delta.OldVersion, delta.NewVersion),
		}},
		Relevance: findings.Relevance{
			Rating: "moderate",
			Justification: "the model marks this dependency operational, so a major " +
				"version change can alter behaviour the model relies on",
		},
		SuggestedFix: fmt.Sprintf("re-check the assumptions recorded against %q for the new major version", assertion.Name),
		AgentPrompt: fmt.Sprintf(
			"Review %s: the third_party_dependency %q at line %d is marked "+
				"uptime_dependency = \"operational\", and this PR bumps %s from %s to %s — "+
				"a major version change. Check whether the block's description and uptime "+
				"notes still hold for the new major version, and update them if not.",
			m.Path, assertion.Name, assertion.Line, delta.Name, delta.OldVersion, delta.NewVersion),
	}
}

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)

func normalize(s string) string {
	return nonAlphanumeric.ReplaceAllString(strings.ToLower(s), "")
}

// matchAssertion joins a manifest entry to a third_party_dependency block.
// Model blocks carry human names ("Sentry") while manifests carry module paths
// ("github.com/getsentry/sentry-go"), so matching is by normalised substring,
// with short names excluded — a two-character name matches almost anything.
func matchAssertion(dependency string, assertions []model.DependencyAssertion) (model.DependencyAssertion, bool) {
	haystack := normalize(dependency)
	segments := strings.FieldsFunc(strings.ToLower(dependency), func(r rune) bool {
		return r == '/' || r == '.' || r == '-' || r == '_' || r == '@'
	})

	for _, assertion := range assertions {
		needle := normalize(assertion.Name)
		if len(needle) < 3 {
			continue
		}
		if strings.Contains(haystack, needle) {
			return assertion, true
		}
		for _, segment := range segments {
			if normalize(segment) == needle {
				return assertion, true
			}
		}
	}
	return model.DependencyAssertion{}, false
}
