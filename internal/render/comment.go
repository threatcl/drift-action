// Package render turns a drift report into the PR-facing surfaces: the
// sticky comment and the check-run conclusion. Only this package (never LLM
// output directly) decides what lands on the PR.
package render

import (
	"fmt"
	"strings"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/findings"
)

// StickyMarker identifies the action's PR comment for in-place updates. It is
// a compatibility contract: changing it orphans the comments on existing PRs.
const StickyMarker = "<!-- threatcl-drift-action -->"

const heading = "## Threat Drift Review by Threatcl"

// ContextInfo describes what the run actually looked at. It is rendered on
// every comment: findings are only as trustworthy as the context behind them,
// and a reader cannot calibrate without seeing what was skipped.
type ContextInfo struct {
	ModelPath     string
	ModelSummary  string
	FilesChanged  int
	FilesReviewed int
	// NoiseDropped counts documentation, lock files, vendored and generated
	// content removed before review.
	NoiseDropped int
	// Narrowed and NarrowedOut report that the diff was too large to review
	// whole and was cut to security-relevant paths — a coverage gap the
	// reader has to see.
	Narrowed     bool
	NarrowedOut  int
	PatchOmitted int
	// NothingReviewed means every changed file was filtered away, so no
	// finding could have been produced regardless of the model's accuracy.
	NothingReviewed bool
	DiffTruncated   bool
	AnalysisMode    string
	Notes           []string
}

var categoryLabels = map[findings.Category]struct{ Icon, Name string }{
	findings.CategoryPhantomControl:   {"🧟", "Phantom controls"},
	findings.CategoryStaleAssertion:   {"📜", "Stale assertions"},
	findings.CategoryUnmodeledSurface: {"🆕", "Unmodeled surface"},
	findings.CategoryDFDDrift:         {"🗺", "DFD drift"},
	findings.CategoryDependencyDrift:  {"📦", "Dependency drift"},
	findings.CategoryUnclassifiedData: {"🔎", "Unclassified data"},
}

var severitySections = []struct {
	Severity findings.Severity
	Title    string
}{
	{findings.SeverityActionRequired, "Action required"},
	{findings.SeverityReviewRecommended, "Review recommended"},
}

// Comment renders the sticky PR comment for a report.
func Comment(report *findings.Report, info ContextInfo) string {
	var b strings.Builder
	b.WriteString(StickyMarker + "\n\n" + heading + "\n\n")

	writeCounts(&b, report)
	writeVerdict(&b, report)
	writeContext(&b, info)
	writeFindings(&b, report)

	return b.String()
}

func writeCounts(b *strings.Builder, report *findings.Report) {
	counts := map[findings.Category]int{}
	for _, finding := range report.Findings {
		counts[finding.Category]++
	}

	cells := make([]string, 0, len(findings.Categories))
	for _, category := range findings.Categories {
		label := categoryLabels[category]
		cells = append(cells, fmt.Sprintf("%s %s (%d)", label.Icon, label.Name, counts[category]))
	}
	// Two rows of three keeps the header readable on a phone.
	fmt.Fprintf(b, "%s\n%s\n\n", strings.Join(cells[:3], " · "), strings.Join(cells[3:], " · "))
}

func writeVerdict(b *strings.Builder, report *findings.Report) {
	switch {
	case report.NoDrift:
		b.WriteString("✅ No drift detected. The threat model is consistent with this change.\n\n")
	case len(report.Findings) == 0:
		// The model could not be assessed — a vague threat model, a refused
		// request, a diff over the cap. Say so; never imply a clean result.
		summary := strings.TrimSpace(report.Summary)
		if summary == "" {
			summary = "No findings were produced, and this run could not confirm the model is consistent with the change."
		}
		fmt.Fprintf(b, "⚠️ %s\n\n", summary)
	default:
		if summary := strings.TrimSpace(report.Summary); summary != "" {
			fmt.Fprintf(b, "%s\n\n", summary)
		}
	}
}

func writeContext(b *strings.Builder, info ContextInfo) {
	b.WriteString("<details>\n<summary>Context used</summary>\n\n")

	if info.ModelPath != "" {
		fmt.Fprintf(b, "- ✅ Threat model: `%s`", info.ModelPath)
		if info.ModelSummary != "" {
			fmt.Fprintf(b, " — %s", info.ModelSummary)
		}
		b.WriteString("\n")
	}
	if info.FilesChanged > 0 {
		fmt.Fprintf(b, "- 📄 Diff: %d of %d changed files reviewed",
			info.FilesReviewed, info.FilesChanged)
		if info.NoiseDropped > 0 {
			fmt.Fprintf(b, " (%d skipped as docs, lock files, vendored or generated)", info.NoiseDropped)
		}
		b.WriteString("\n")
	}
	if info.Narrowed {
		fmt.Fprintf(b, "- ⚠️ Diff was too large to review whole: narrowed to security-relevant paths, leaving %d file(s) unreviewed\n",
			info.NarrowedOut)
	}
	if info.NothingReviewed {
		b.WriteString("- ⚠️ No changed file was reviewed, so this run could not have found drift regardless of the code\n")
	}
	if info.PatchOmitted > 0 {
		fmt.Fprintf(b, "- ⚠️ %d file(s) returned without a patch by the GitHub API (too large or binary) and were not analysed\n",
			info.PatchOmitted)
	}
	if info.DiffTruncated {
		b.WriteString("- ⚠️ Diff exceeded the configured size limit. Run `/threat-drift` locally with the threatcl claude-plugin for full coverage.\n")
	}
	if info.AnalysisMode != "" {
		fmt.Fprintf(b, "- 🤖 Analysis: %s\n", info.AnalysisMode)
	}
	for _, note := range info.Notes {
		fmt.Fprintf(b, "- ℹ️ %s\n", note)
	}

	b.WriteString("\n</details>\n")
}

func writeFindings(b *strings.Builder, report *findings.Report) {
	index := 0
	for _, section := range severitySections {
		matching := bySeverity(report.Findings, section.Severity)
		if len(matching) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n### %s\n\n", section.Title)
		for _, finding := range matching {
			index++
			writeFinding(b, index, finding)
		}
	}
}

func bySeverity(all []findings.Finding, severity findings.Severity) []findings.Finding {
	var matching []findings.Finding
	for _, finding := range all {
		if finding.Severity == severity {
			matching = append(matching, finding)
		}
	}
	return matching
}

func writeFinding(b *strings.Builder, index int, finding findings.Finding) {
	label := categoryLabels[finding.Category]

	b.WriteString("<details>\n")
	fmt.Fprintf(b, "<summary><b>%d. %s</b> — %s %s</summary>\n\n",
		index, finding.Title, label.Icon, label.Name)

	if finding.ModelExcerpt.Quote != "" {
		fmt.Fprintf(b, "**Model excerpt** — %s\n\n", location(finding.ModelExcerpt.File, finding.ModelExcerpt.Line))
		fmt.Fprintf(b, "> %s\n\n", strings.ReplaceAll(strings.TrimSpace(finding.ModelExcerpt.Quote), "\n", "\n> "))
	}

	if len(finding.Evidence) > 0 {
		b.WriteString("**Code evidence**\n\n")
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(b, "- %s — %s\n", location(evidence.File, evidence.Line), evidence.Note)
		}
		b.WriteString("\n")
	}

	if finding.Relevance.Rating != "" {
		fmt.Fprintf(b, "**Relevance:** %s", finding.Relevance.Rating)
		if finding.Relevance.Justification != "" {
			fmt.Fprintf(b, " — %s", finding.Relevance.Justification)
		}
		b.WriteString("\n\n")
	}

	if finding.SuggestedFix != "" {
		fmt.Fprintf(b, "**Suggested fix:** %s\n\n", finding.SuggestedFix)
	}

	if finding.AgentPrompt != "" {
		b.WriteString("<details>\n<summary>Agent prompt</summary>\n\n")
		fmt.Fprintf(b, "```text\n%s\n```\n\n", finding.AgentPrompt)
		b.WriteString("</details>\n\n")
	}

	b.WriteString("</details>\n\n")
}

// location renders a file:line reference, omitting a line number the engine
// could not determine rather than printing a misleading ":0".
func location(file string, line int) string {
	if file == "" {
		return "_unknown location_"
	}
	if line <= 0 {
		return fmt.Sprintf("`%s`", file)
	}
	return fmt.Sprintf("`%s:%d`", file, line)
}

// CheckConclusion maps a report to a check-run conclusion. Findings are
// neutral by default; failing is opt-in through fail mode.
//
// Success is reserved for a run that actually assessed the model and found it
// consistent. A run that produced no findings because coverage was partial —
// inference disabled, a refused request, a diff over the cap — reports neutral:
// a green check is a claim, and the check run must not make one the comment
// explicitly declines to make.
func CheckConclusion(report *findings.Report, failMode string) (conclusion, title string) {
	if len(report.Findings) == 0 {
		if report.NoDrift {
			return "success", "No threat model drift detected"
		}
		return "neutral", "No findings — see the comment for what was assessed"
	}

	actionRequired := len(bySeverity(report.Findings, findings.SeverityActionRequired))
	title = fmt.Sprintf("%d drift finding(s), %d action required",
		len(report.Findings), actionRequired)

	if failMode == config.FailOnActionRequired && actionRequired > 0 {
		return "failure", title
	}
	return "neutral", title
}
