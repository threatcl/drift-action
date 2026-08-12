// Package llm defines the provider abstraction the drift engine runs
// inference through. Anthropic is implemented; OpenAI is configurable and
// lands behind this same interface, with Vertex after it. Constructing a
// provider from config is internal/engine's job, not this package's — the
// implementations import it, so it cannot import them.
package llm

import (
	"context"
	"fmt"

	"github.com/threatcl/drift-action/internal/findings"
)

// ReviewRequest carries everything a provider needs for one drift review.
// Diff and ContextFiles are attacker-controlled PR content: providers must
// embed them as data in the prompt, never as instructions.
type ReviewRequest struct {
	// Prompt is the CI drift prompt (prompts.DriftCI). It is the stable
	// prefix — providers put it first and cache it; everything else in this
	// struct varies per pull request.
	Prompt string
	// ModelAssertions is the rendered threat model assertion set.
	ModelAssertions string
	// ManifestFacts is the rendered dependency-manifest delta set
	// (deps.Render). Deterministic code states what changed; judging whether
	// it is drift is the model's job.
	ManifestFacts string
	// Categories restricts the review to a subset of the six drift
	// categories. Empty means all six.
	Categories []string
	// ContextFiles are repo files sent whole — targeted context stuffing for
	// controls and threats plausibly backed by touched files.
	ContextFiles []ContextFile
	// Diff is the rendered, filtered unified diff.
	Diff string
	// Schema is the forced output schema (findings.SchemaJSON).
	Schema []byte
}

// ReviewResult is one completed review, plus what it took to produce it.
type ReviewResult struct {
	// Report is the validated model output.
	Report *findings.Report
	// Model is the model that actually answered. It differs from the
	// requested model when a server-side fallback served the review, which
	// the comment has to disclose: a review is only interpretable if the
	// reader knows what produced it.
	Model string
	// Fallback reports that the requested model declined and a fallback
	// answered in its place.
	Fallback bool
	// Notes are remarks about how this review was produced rather than about
	// the code — that it was replayed from a recording, say. They reach the
	// comment: a reader judging findings has to know where they came from.
	Notes []string
	// Token counts, for the run log.
	InputTokens     int64
	OutputTokens    int64
	CacheReadTokens int64
}

// Refusal reports that the provider's safety classifiers declined the request
// outright. It is an outcome, not a transport failure: the request succeeded
// and the model chose not to answer.
//
// It must never be rendered as "no drift". We send security-relevant diffs and
// ask what attack surface they introduce, which is exactly the benign-but-
// cyber-adjacent shape that trips false positives, so this is a live path and
// not a theoretical one.
type Refusal struct {
	// Model is the model that declined.
	Model string
	// Category is the policy category that triggered the refusal, when the
	// provider reports one.
	Category string
	// Explanation is the provider's human-readable reason, when there is one.
	// It is not guaranteed to be present or stable.
	Explanation string
}

func (r *Refusal) Error() string {
	message := "the model declined to review this pull request"
	if r.Category != "" {
		message += fmt.Sprintf(" (policy category %q)", r.Category)
	}
	if r.Explanation != "" {
		message += ": " + r.Explanation
	}
	return message
}

// Provider is one LLM backend. Implementations must force JSON-schema output
// and return the parsed report without acting on its content — inference
// output influences nothing but the report body.
type Provider interface {
	Review(ctx context.Context, req ReviewRequest) (*ReviewResult, error)
}
