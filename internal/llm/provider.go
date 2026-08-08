// Package llm defines the provider abstraction the drift engine runs
// inference through. v0 ships Anthropic only; OpenAI and Vertex come later
// behind the same interface.
package llm

import (
	"context"

	"github.com/threatcl/drift-action/internal/findings"
)

// ReviewRequest carries everything a provider needs for one drift review.
// Diff and ContextFiles are attacker-controlled PR content: providers must
// embed them as data in the prompt, never as instructions.
type ReviewRequest struct {
	// Prompt is the CI drift prompt (prompts.DriftCI).
	Prompt string
	// ModelAssertions is the rendered threat model assertion set.
	ModelAssertions string
	// Diff is the filtered unified diff.
	Diff string
	// ContextFiles maps repo paths to their current contents — targeted
	// context stuffing for controls/threats plausibly backed by touched files.
	ContextFiles map[string]string
	// Schema is the forced output schema (findings.SchemaJSON).
	Schema []byte
}

// Provider is one LLM backend. Implementations must force JSON-schema output
// and return the parsed report without acting on its content — inference
// output influences nothing but the report body.
type Provider interface {
	Review(ctx context.Context, req ReviewRequest) (*findings.Report, error)
}
