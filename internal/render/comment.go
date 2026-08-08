// Package render turns a drift report into the PR-facing surfaces: the
// sticky comment and the check-run summary. Only this package (never LLM
// output directly) decides what lands on the PR.
package render

import (
	"fmt"
	"strings"

	"github.com/threatcl/drift-action/internal/findings"
)

// StickyMarker identifies the action's PR comment for in-place updates. It is
// a compatibility contract: changing it orphans the comments on existing PRs.
const StickyMarker = "<!-- threatcl-drift-action -->"

const heading = "## Threat Drift Review by Threatcl"

// Comment renders the sticky PR comment for a report.
func Comment(r *findings.Report) string {
	var b strings.Builder
	b.WriteString(StickyMarker + "\n\n" + heading + "\n\n")
	switch {
	case r.NoDrift:
		b.WriteString("No drift detected. The threat model is consistent with this change.\n")
	case len(r.Findings) == 0:
		// e.g. "model too vague to assess" — the summary carries the story
		b.WriteString(r.Summary + "\n")
	default:
		b.WriteString(r.Summary + "\n\n")
		fmt.Fprintf(&b, "%d finding(s) — full comment rendering not implemented yet.\n", len(r.Findings))
	}
	return b.String()
}

// CheckSummary maps a report to a check-run conclusion. Findings default to
// neutral; failing is a fail-mode opt-in applied by the caller.
func CheckSummary(r *findings.Report) (conclusion, summary string) {
	if r.NoDrift || len(r.Findings) == 0 {
		return "success", "No threat model drift detected"
	}
	return "neutral", fmt.Sprintf("%d drift finding(s)", len(r.Findings))
}
