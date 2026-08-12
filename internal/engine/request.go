package engine

import (
	"slices"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/deps"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
	"github.com/threatcl/drift-action/internal/model"
	"github.com/threatcl/drift-action/prompts"
)

// FilterChanges reduces a pull request's changes to the review set. The extra
// patterns are what survives narrowing on top of the security-relevant
// defaults: paths the threat model's prose names, and the repo's configured
// trigger_paths.
//
// slices.Concat rather than append: appending to cfg.TriggerPaths would write
// through to its backing array whenever it has spare capacity.
func FilterChanges(cfg config.Config, assertions *model.Assertions, changes []diff.Change) diff.Result {
	return diff.Filter(changes, diff.Options{
		ExtraPatterns: slices.Concat(cfg.TriggerPaths, assertions.ReferencedPaths()),
		NarrowAbove:   cfg.NarrowAbove,
	})
}

// RequestInput is what assembling a review request needs beyond the config:
// the checkout to read context files from, the parsed threat model, the
// surviving changes, and the manifest deltas already extracted from them.
type RequestInput struct {
	Workspace     string
	Assertions    *model.Assertions
	Kept          []diff.Change
	ManifestFacts []deps.Delta
}

// Assembly is a built review request plus what building it had to leave out.
// Both omissions are coverage statements, so callers are handed them rather
// than having them logged away here: the action turns them into comment notes
// the reader has to see, and the corpus fails the case outright.
type Assembly struct {
	Request llm.ReviewRequest
	// TooLarge lists files whose patch exceeded max_patch_bytes and were not
	// sent for review.
	TooLarge []string
	// Skipped lists context files that were selected but could not be sent
	// whole — over budget, unreadable, or not text.
	Skipped []string
	// ContextBytes is the total size of the context files that were sent.
	ContextBytes int
}

// AssembleRequest builds the review request for one pull request. This is the
// single definition of what the engine sends to a model: every field the
// prompt declares is set here, so a new one cannot reach production while the
// corpus keeps measuring a request without it.
func AssembleRequest(cfg config.Config, in RequestInput) Assembly {
	diffText, tooLarge := diff.Render(in.Kept, cfg.MaxPatchBytes)

	selection := llm.SelectContext(in.Workspace, in.Assertions.ReferencedPaths(),
		diff.Paths(in.Kept), cfg.MaxContextBytes)

	return Assembly{
		Request: llm.ReviewRequest{
			Prompt:          prompts.DriftCI,
			ModelAssertions: in.Assertions.Render(),
			ManifestFacts:   deps.Render(in.ManifestFacts),
			Categories:      cfg.Categories,
			ContextFiles:    selection.Files,
			Diff:            diffText,
			Schema:          findings.SchemaJSON,
		},
		TooLarge:     tooLarge,
		Skipped:      selection.Skipped,
		ContextBytes: selection.Bytes,
	}
}
