// Package openai runs the drift review against the OpenAI Responses API with
// forced JSON-schema output.
//
// It is the sibling of internal/llm/anthropic and deliberately mirrors its
// shape. Four things genuinely differ, and each is commented where it lands:
// strict mode constrains the schema, a refusal is signalled two different
// ways rather than by a stop reason, reasoning effort is its own parameter,
// and there is no server-side fallback — so ReviewResult.Fallback is never
// set here, rather than being faked from something that only resembles one.
package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	sdk "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

var _ llm.Provider = (*Client)(nil)

// DefaultMaxTokens caps reasoning plus response text together, exactly as the
// Anthropic provider's does: max_output_tokens on this API is documented to
// include reasoning tokens, so a budget sized for the findings array alone
// truncates mid-JSON.
const DefaultMaxTokens = 32_000

// schemaName labels the forced output schema. The API constrains it to
// [A-Za-z0-9_-]{1,64}; it is not the schema's identity, only a handle.
const schemaName = "threatcl_drift_findings"

// promptCacheKey buckets this action's requests together for prompt caching.
// The stable prefix is the drift prompt, sent as Instructions; everything that
// varies per pull request follows it in the input.
const promptCacheKey = "threatcl-drift-action"

// Options configures the provider.
type Options struct {
	// Model is the model id. There is no default: forced-JSON support is
	// model-specific, so config requires this to be set explicitly rather
	// than shipping an unverified guess.
	Model string
	// APIKey authenticates the request. Empty falls back to the SDK's own
	// credential resolution.
	APIKey string
	// Effort is low | medium | high | xhigh | max. Empty leaves the API
	// default in place.
	Effort string
	// MaxTokens caps reasoning plus output. Zero means DefaultMaxTokens.
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
	raw := req.Schema
	if len(raw) == 0 {
		raw = findings.SchemaJSON
	}
	schema, err := strictSchema(raw)
	if err != nil {
		return nil, err
	}

	params := responses.ResponseNewParams{
		Model: shared.ResponsesModel(c.model),
		// Instructions is the stable prefix: the same drift prompt on every
		// run, so it is what prompt caching can actually reuse.
		Instructions: sdk.String(req.Prompt),
		Input: responses.ResponseNewParamsInputUnion{
			OfString: sdk.String(req.Sections()),
		},
		MaxOutputTokens: sdk.Int(c.maxTokens),
		PromptCacheKey:  sdk.String(promptCacheKey),
		// Never set temperature or top_p alongside reasoning effort: the
		// reasoning models this targets reject them.
		Reasoning: shared.ReasoningParam{
			Effort: shared.ReasoningEffort(c.effort),
		},
		Text: responses.ResponseTextConfigParam{
			Format: responses.ResponseFormatTextConfigUnionParam{
				OfJSONSchema: &responses.ResponseFormatTextJSONSchemaConfigParam{
					Name:   schemaName,
					Schema: schema,
					// Without this the schema is a suggestion. The whole
					// forced-JSON contract depends on it being true.
					Strict: sdk.Bool(true),
				},
			},
		},
	}

	// Stream for the same reason the Anthropic provider does: the token cap
	// covers reasoning, so a request generous enough to finish the report runs
	// long enough to hit HTTP timeouts unstreamed.
	stream := c.api.Responses.NewStreaming(ctx, params)
	var final responses.Response
	var terminal bool
	for stream.Next() {
		event := stream.Current()
		switch event.Type {
		case "response.completed", "response.incomplete", "response.failed":
			final, terminal = event.Response, true
		}
	}
	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("openai request failed: %w", err)
	}
	if !terminal {
		return nil, fmt.Errorf("the response stream ended without a terminal event")
	}

	// Every terminal condition is checked before the output is touched. A
	// refusal is a successful HTTP response whose output carries no report,
	// and reading it as an empty review would render "no drift" for a request
	// the model declined — the one failure this provider must never produce.
	if refusal, ok := refusalText(final); ok {
		return nil, &llm.Refusal{Model: final.Model, Explanation: refusal}
	}
	switch final.IncompleteDetails.Reason {
	case "content_filter":
		// The other way a refusal arrives: filtered before any refusal
		// message was produced, so there is nothing to quote.
		return nil, &llm.Refusal{Model: final.Model, Category: "content_filter"}
	case "max_output_tokens":
		return nil, fmt.Errorf(
			"the model reached its %d-token output cap before finishing the report; raise llm.max_tokens",
			c.maxTokens)
	}
	if final.Status == responses.ResponseStatusFailed {
		return nil, fmt.Errorf("the model failed to generate a response: %s", failureText(final))
	}

	text := final.OutputText()
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("the model returned no output (status %q)", final.Status)
	}

	report, err := findings.Parse([]byte(text))
	if err != nil {
		return nil, err
	}

	return &llm.ReviewResult{
		Report: report,
		Model:  final.Model,
		// No Fallback: this API has no server-side fallback equivalent, and
		// inventing a signal that resembles one would misreport which model
		// answered — the thing the field exists to keep honest.
		InputTokens:     final.Usage.InputTokens,
		OutputTokens:    final.Usage.OutputTokens,
		CacheReadTokens: final.Usage.InputTokensDetails.CachedTokens,
	}, nil
}

// refusalText returns the model's refusal message, if it produced one. A
// refusal is a content part alongside the text parts rather than a status, so
// it has to be looked for explicitly.
func refusalText(resp responses.Response) (string, bool) {
	var b strings.Builder
	for _, item := range resp.Output {
		for _, content := range item.Content {
			if content.Type == "refusal" {
				if b.Len() > 0 {
					b.WriteString(" ")
				}
				b.WriteString(content.Refusal)
			}
		}
	}
	return b.String(), b.Len() > 0
}

// failureText describes a failed response without assuming the error object
// was populated.
func failureText(resp responses.Response) string {
	if resp.Error.Message != "" {
		return resp.Error.Message
	}
	return "the API reported no reason"
}

// strictSchema translates the shared findings schema into the subset strict
// structured outputs accepts. The shared schema is left alone: it is the
// validation source of truth and the Anthropic provider sends it verbatim, so
// the translation belongs to the provider that needs it.
//
// The schema is already strict-shaped in every expensive way — every object
// sets additionalProperties:false and lists all its properties as required —
// so this is deliberately a narrow rewrite rather than a general converter. It
// does two things, and anything else it silently passes through:
//
//   - const is not in the accepted subset, so a const becomes a single-value
//     enum, which is exactly equivalent and is accepted.
//   - a property given only a const carries no type, which strict mode
//     requires, so the type is taken from the constant itself.
//
// $schema is dropped: it describes the schema's own dialect rather than the
// instance, so it is meaningless to the API and only risks being rejected as
// an unrecognised keyword.
func strictSchema(raw []byte) (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("the findings schema is not valid JSON: %w", err)
	}
	delete(root, "$schema")
	return rewrite(root), nil
}

func rewrite(node map[string]any) map[string]any {
	if value, ok := node["const"]; ok {
		delete(node, "const")
		node["enum"] = []any{value}
		if _, typed := node["type"]; !typed {
			if name := jsonTypeOf(value); name != "" {
				node["type"] = name
			}
		}
	}

	for key, child := range node {
		switch typed := child.(type) {
		case map[string]any:
			node[key] = rewrite(typed)
		case []any:
			for i, element := range typed {
				if object, ok := element.(map[string]any); ok {
					typed[i] = rewrite(object)
				}
			}
		}
	}
	return node
}

// jsonTypeOf names the JSON type of a decoded constant. Numbers decode to
// float64 whether or not they were written with a fraction, so an integer
// const is reported as "number" — the wider of the two, and never wrong.
func jsonTypeOf(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return ""
}
