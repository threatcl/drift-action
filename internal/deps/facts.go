package deps

import (
	"fmt"
	"strings"

	"github.com/threatcl/drift-action/internal/diff"
)

// Facts extracts every dependency change from the manifests in a diff.
//
// This package states what changed and stops there. Whether an undocumented
// dependency is worth a finding — whether "Sentry" in the model means
// github.com/getsentry/sentry-go, whether a major bump of an operational
// dependency actually matters here — is judgement, and belongs to the model
// that reads code. Deterministic extraction, semantic judgement.
func Facts(changes []diff.Change) []Delta {
	var facts []Delta
	for _, change := range changes {
		if !IsManifest(change.Path) || change.Patch == "" {
			continue
		}
		facts = append(facts, Deltas(change.Path, change.Patch)...)
	}
	return facts
}

// Render writes the deltas as the body of the prompt's dependency-manifest
// section; the caller supplies the section header. Line numbers come from the
// diff's post-image, so a finding built on one of these facts can cite
// evidence the reader can actually open.
func Render(facts []Delta) string {
	var b strings.Builder

	if len(facts) == 0 {
		// Say so explicitly. Silence invites the model to infer dependency
		// drift from unrelated code changes.
		b.WriteString("No dependency manifest changed in this pull request.\n")
		return b.String()
	}

	for _, fact := range facts {
		switch {
		case fact.Added():
			fmt.Fprintf(&b, "- added: %s %s%s\n", fact.Name, fact.NewVersion, location(fact))
		case fact.Removed():
			fmt.Fprintf(&b, "- removed: %s %s (%s)\n", fact.Name, fact.OldVersion, fact.File)
		default:
			fmt.Fprintf(&b, "- changed: %s from %s to %s%s%s\n",
				fact.Name, fact.OldVersion, fact.NewVersion,
				majorNote(fact), location(fact))
		}
	}
	return b.String()
}

func majorNote(fact Delta) string {
	if fact.MajorBump() {
		return " (major version change)"
	}
	return ""
}

func location(fact Delta) string {
	if fact.Line <= 0 {
		return fmt.Sprintf(" (%s)", fact.File)
	}
	return fmt.Sprintf(" (%s:%d)", fact.File, fact.Line)
}
