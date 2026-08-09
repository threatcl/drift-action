// Package anthropic runs the drift review against the Anthropic Messages API
// with forced JSON-schema output.
package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

var _ llm.Provider = (*Client)(nil)

// DefaultMaxTokens caps thinking plus response text together. Thinking is on
// by default on the models this action targets, so a budget sized for the
// findings array alone truncates mid-JSON.
const DefaultMaxTokens = 32_000

// Options configures the provider.
type Options struct {
	// Model is the model id, e.g. claude-opus-5.
	Model string
	// APIKey authenticates the request. Empty falls back to the SDK's own
	// credential resolution.
	APIKey string
	// Effort is low | medium | high | xhigh | max. Empty leaves the API
	// default in place.
	Effort string
	// MaxTokens caps thinking plus output. Zero means DefaultMaxTokens.
	MaxTokens int
	// BaseURL overrides the API host. Tests set it; production leaves it
	// empty.
	BaseURL string
}

type Client struct {
	api       sdk.Client
	model     string
	effort    string
	maxTokens int64
}

func New(opts Options) *Client {
	var requestOptions []option.RequestOption
	if opts.APIKey != "" {
		requestOptions = append(requestOptions, option.WithAPIKey(opts.APIKey))
	}
	if opts.BaseURL != "" {
		requestOptions = append(requestOptions, option.WithBaseURL(opts.BaseURL))
	}

	maxTokens := int64(opts.MaxTokens)
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}

	return &Client{
		api:       sdk.NewClient(requestOptions...),
		model:     opts.Model,
		effort:    opts.Effort,
		maxTokens: maxTokens,
	}
}

func (c *Client) Review(ctx context.Context, req llm.ReviewRequest) (*llm.ReviewResult, error) {
	schema := json.RawMessage(req.Schema)
	if len(schema) == 0 {
		schema = json.RawMessage(findings.SchemaJSON)
	}

	params := sdk.BetaMessageNewParams{
		Model:     sdk.Model(c.model),
		MaxTokens: c.maxTokens,
		// The prompt is the stable prefix and carries the cache breakpoint.
		// Everything that varies per pull request follows it in the user turn.
		System: []sdk.BetaTextBlockParam{{
			Text:         req.Prompt,
			CacheControl: sdk.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: []sdk.BetaMessageParam{
			sdk.NewBetaUserMessage(sdk.NewBetaTextBlock(req.Sections())),
		},
		OutputConfig: sdk.BetaOutputConfigParam{
			Effort: sdk.BetaOutputConfigEffort(c.effort),
			Format: sdk.BetaJSONOutputFormatParam{Schema: schema},
		},
		// Adaptive thinking, set explicitly rather than left to the per-model
		// default, which differs between model generations. Never set
		// temperature, top_p or top_k: current models reject them outright.
		Thinking: sdk.BetaThinkingConfigParamUnion{
			OfAdaptive: &sdk.BetaThinkingConfigAdaptiveParam{},
		},
		// Cyber-adjacent refusals are a live risk for this workload, so let
		// the API re-serve a declined request on a fallback model rather than
		// returning a review that assessed nothing. "default" routes by
		// refusal category, so there is no fallback model list to maintain.
		// The result records which model actually answered.
		Fallbacks: sdk.BetaFallbacksParamOfDefault(),
		Betas:     []sdk.AnthropicBeta{sdk.AnthropicBetaServerSideFallback2026_07_01},
	}

	// Stream rather than block: max_tokens covers thinking as well as output,
	// so a request generous enough to finish the report is long enough to hit
	// HTTP timeouts unstreamed.
	stream := c.api.Beta.Messages.NewStreaming(ctx, params)
	var message sdk.BetaMessage
	for stream.Next() {
		if err := message.Accumulate(stream.Current()); err != nil {
			return nil, fmt.Errorf("accumulating the model's response: %w", err)
		}
	}
	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}

	// Check the stop reason before touching Content. A refusal arrives as a
	// successful response, and one that fires before any output has an empty
	// content array — indexing it would panic, and reporting it as "no drift"
	// would be a lie the reader has no way to catch.
	switch message.StopReason {
	case sdk.BetaStopReasonRefusal:
		return nil, &llm.Refusal{
			Model:       string(message.Model),
			Category:    string(message.StopDetails.Category),
			Explanation: message.StopDetails.Explanation,
		}
	case sdk.BetaStopReasonMaxTokens:
		return nil, fmt.Errorf(
			"the model reached its %d-token output cap before finishing the report; raise llm.max_tokens",
			c.maxTokens)
	case sdk.BetaStopReasonModelContextWindowExceeded:
		return nil, errors.New(
			"the prompt exceeded the model's context window; lower limits.max_patch_bytes or limits.max_context_bytes")
	}

	text := responseText(message)
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("the model returned no output (stop reason %q)", message.StopReason)
	}

	report, err := findings.Parse([]byte(text))
	if err != nil {
		return nil, err
	}

	return &llm.ReviewResult{
		Report:          report,
		Model:           string(message.Model),
		Fallback:        servedByFallback(message.Usage),
		InputTokens:     message.Usage.InputTokens,
		OutputTokens:    message.Usage.OutputTokens,
		CacheReadTokens: message.Usage.CacheReadInputTokens,
	}, nil
}

// responseText concatenates the text blocks, skipping thinking blocks and
// anything else the model emitted alongside the report.
func responseText(message sdk.BetaMessage) string {
	var b strings.Builder
	for _, block := range message.Content {
		if text, ok := block.AsAny().(sdk.BetaTextBlock); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// servedByFallback reports whether a fallback model answered. The fallback
// content block only marks a switch mid-response, so a request routed to the
// fallback from the start carries none; the usage iterations do.
func servedByFallback(usage sdk.BetaUsage) bool {
	for _, iteration := range usage.Iterations {
		if iteration.Type == "fallback_message" {
			return true
		}
	}
	return false
}
