// Package engine holds the steps the action and the finding-quality corpus
// both perform: choosing an LLM provider, and turning a filtered diff into a
// review request.
//
// It exists because those two callers drifted. The corpus assembled its own
// llm.ReviewRequest and stopped matching the one the action sends — it omitted
// Categories, so the ENABLED CATEGORIES prompt section was never exercised by
// a single recording, and it filtered without cfg.TriggerPaths. A corpus that
// measures a different prompt than the action ships measures nothing.
//
// It sits above internal/llm rather than inside it: internal/llm/anthropic
// imports internal/llm, so the provider constructors cannot live there.
package engine

import (
	"fmt"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/llm"
	"github.com/threatcl/drift-action/internal/llm/anthropic"
)

// NewProvider builds the live provider cfg names. Record and replay wrap the
// result — that is the caller's business, not this function's: the action
// wraps on env vars and the corpus wraps per case, and neither belongs in a
// provider factory.
//
// An unknown provider is rejected at config time (config.knownProvider), so
// reaching the default here means a caller built a Config by hand.
func NewProvider(cfg config.Config, apiKey string) (llm.Provider, error) {
	switch cfg.Provider {
	case "anthropic", "":
		return anthropic.New(anthropic.Options{
			Model:     cfg.Model,
			APIKey:    apiKey,
			Effort:    cfg.Effort,
			MaxTokens: cfg.MaxTokens,
		}), nil
	default:
		return nil, fmt.Errorf("unknown llm provider %q; v0 supports anthropic only", cfg.Provider)
	}
}
