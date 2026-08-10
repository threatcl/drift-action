package llm

import (
	"fmt"
	"strconv"
	"strings"
)

// Sections renders the data half of the prompt: the input sections
// prompts/drift-ci.md declares the engine will supply, in a fixed order.
//
// The order is stable content first, volatile content last. The model
// assertions change when the repo's .tm.hcl changes; the diff changes on every
// push. Providers put Prompt ahead of this and cache the boundary, so the
// cheapest thing to re-read sits at the end.
func (r ReviewRequest) Sections() string {
	var b strings.Builder

	fmt.Fprintf(&b, "=== THREAT MODEL ASSERTIONS ===\n\n%s\n",
		orNone(r.ModelAssertions, "(the threat model parsed to no assertions)"))

	if len(r.Categories) > 0 {
		// Without this the categories config setting is a silent no-op: the
		// prompt describes all six and the model would assess all six.
		fmt.Fprintf(&b, "\n=== ENABLED CATEGORIES ===\n\n"+
			"This repository restricts the review to these drift categories: %s.\n"+
			"Report nothing in any other category.\n",
			strings.Join(r.Categories, ", "))
	}

	fmt.Fprintf(&b, "\n=== DEPENDENCY MANIFEST CHANGES ===\n\n%s\n",
		orNone(r.ManifestFacts, "No dependency manifest changed in this pull request."))

	b.WriteString("\n=== CONTEXT FILES ===\n\n")
	if len(r.ContextFiles) == 0 {
		b.WriteString("(none: no file this pull request touches is referenced by the threat model's prose)\n")
	}
	for _, file := range r.ContextFiles {
		fmt.Fprintf(&b, "--- %s ---\n%s\n\n", file.Path, numberLines(file.Contents))
	}

	fmt.Fprintf(&b, "\n=== DIFF ===\n\n%s\n",
		orNone(r.Diff, "(no file survived filtering; nothing here can be assessed)"))

	return b.String()
}

func orNone(value, fallback string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return fallback
}

// numberLines prefixes every line of a context file with its 1-based line
// number. Evidence citations into context files were observed landing a few
// lines off the real construct — the model was doing arithmetic from diff
// hunk headers. Printed numbers replace arithmetic; the prompt tells the
// model to cite them directly.
func numberLines(contents string) string {
	lines := strings.Split(strings.TrimRight(contents, "\n"), "\n")
	width := len(strconv.Itoa(len(lines)))

	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%*d→%s", width, i+1, line)
	}
	return b.String()
}
