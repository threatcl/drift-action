// Package gemini runs the drift review against the Gemini Developer API
// (generativelanguage.googleapis.com, authenticated by API key) with forced
// JSON-schema output.
//
// This is the Gemini API, not Vertex AI: the backend is pinned to
// BackendGeminiAPI so a GOOGLE_GENAI_USE_VERTEXAI=1 in a runner's environment
// cannot silently reroute a review to a project the workflow never named.
// Vertex, if it comes, is its own provider with its own credential story.
//
// It is the third sibling of internal/llm/anthropic and internal/llm/openai
// and mirrors their shape. What genuinely differs is commented where it lands:
// the accepted schema subset (shared with OpenAI via llm.PortableSchema),
// reasoning effort as a thinking level, and a refusal that arrives in two
// shapes — a blocked prompt with no candidates at all, or a candidate whose
// finish reason is a safety category — neither of which is a stop reason to
// read from one place. There is no server-side fallback, so
// ReviewResult.Fallback is never set here.
package gemini

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/genai"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

var _ llm.Provider = (*Client)(nil)

// DefaultMaxTokens caps thinking plus response text together, exactly as the
// sibling providers' do: maxOutputTokens on this API includes thought tokens,
// so a budget sized for the findings array alone truncates mid-JSON.
const DefaultMaxTokens = 32_000

// retryAttempts is the total number of tries per request, including the
// first. The Anthropic and OpenAI SDKs retry 429s and 5xx twice by default;
// this SDK retries nothing unless asked, so parity has to be requested.
const retryAttempts = 3

// Options configures the provider.
type Options struct {
	// Model is the model id. There is no default: forced-JSON support and
	// thinking-level support are both model-specific, so config requires this
	// to be set explicitly until a corpus recording has verified one.
	Model string
	// APIKey authenticates the request. Empty falls back to the SDK's own
	// resolution (GOOGLE_API_KEY, then GEMINI_API_KEY); with neither set the
	// SDK refuses to build a client, which New reports.
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
	api           *genai.Client
	model         string
	thinkingLevel genai.ThinkingLevel
	maxTokens     int32
}

// New builds the provider. Unlike its siblings it can fail: the SDK validates
// its credentials at construction rather than at the first request.
func New(opts Options) (*Client, error) {
	// The context only matters to the SDK for Application Default Credentials
	// discovery, which the Gemini API backend never performs — an API key is
	// the whole credential — so there is nothing for a caller's context to
	// bound here.
	api, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey: opts.APIKey,
		// Explicit, never inferred from the environment: see the package doc.
		Backend: genai.BackendGeminiAPI,
		HTTPOptions: genai.HTTPOptions{
			BaseURL:      opts.BaseURL,
			RetryOptions: &genai.HTTPRetryOptions{Attempts: genai.Ptr(int32(retryAttempts))},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("building the gemini client: %w", err)
	}

	maxTokens := int32(opts.MaxTokens)
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}

	return &Client{
		api:           api,
		model:         opts.Model,
		thinkingLevel: thinkingLevel(opts.Effort),
		maxTokens:     maxTokens,
	}, nil
}

// thinkingLevel maps the config's five effort levels onto the API's four. The
// top three collapse onto HIGH: the API has nothing above it, and refusing
// xhigh or max for this provider alone would make llm.effort mean different
// things in different .threatcl-ci.hcl files. Empty stays empty, which leaves
// the model's own default in place rather than choosing one for it.
func thinkingLevel(effort string) genai.ThinkingLevel {
	switch effort {
	case "low":
		return genai.ThinkingLevelLow
	case "medium":
		return genai.ThinkingLevelMedium
	case "high", "xhigh", "max":
		return genai.ThinkingLevelHigh
	}
	return ""
}

func (c *Client) Review(ctx context.Context, req llm.ReviewRequest) (*llm.ReviewResult, error) {
	raw := req.Schema
	if len(raw) == 0 {
		raw = findings.SchemaJSON
	}
	// responseJsonSchema accepts a subset of JSON Schema, and the shared
	// schema's const is outside it. Whether an unsupported keyword is rejected
	// or ignored, the result is a review that fails after the diff has been
	// fetched, so the translation is done here rather than found out there.
	schema, err := llm.PortableSchema(raw)
	if err != nil {
		return nil, err
	}

	config := &genai.GenerateContentConfig{
		// The prompt is the stable prefix, sent as the system instruction so
		// implicit caching has an unchanging head to match on. Everything
		// that varies per pull request follows it in the user turn.
		SystemInstruction: genai.NewContentFromText(req.Prompt, genai.RoleUser),
		MaxOutputTokens:   c.maxTokens,
		// Both are required together: the MIME type turns JSON mode on and
		// the schema constrains it. Without the schema the output is merely
		// JSON-shaped, and the whole forced-JSON contract depends on it.
		ResponseMIMEType:   "application/json",
		ResponseJsonSchema: schema,
		// Never set temperature, top_p or top_k: the models this targets are
		// documented to degrade off their defaults, and the siblings leave
		// them alone too.
	}
	if c.thinkingLevel != "" {
		config.ThinkingConfig = &genai.ThinkingConfig{ThinkingLevel: c.thinkingLevel}
	}

	// Stream for the same reason the siblings do: the token cap covers
	// thinking, so a request generous enough to finish the report runs long
	// enough to hit HTTP timeouts unstreamed.
	var acc accumulator
	for chunk, err := range c.api.Models.GenerateContentStream(ctx, c.model, genai.Text(req.Sections()), config) {
		if err != nil {
			return nil, fmt.Errorf("gemini request failed: %w", err)
		}
		acc.add(chunk)
	}

	// Every terminal condition is checked before the output is touched. A
	// refusal here is a successful HTTP response whose output carries no
	// report, and reading it as an empty review would render "no drift" for a
	// request the model declined — the one failure this provider must never
	// produce.
	model := acc.model
	if model == "" {
		model = c.model
	}
	// Neither refusal below carries an explanation on this backend:
	// blockReasonMessage and finishMessage are Vertex-only fields, and the
	// SDK drops them from Gemini API responses. The category is the whole
	// signal, so it is what the comment gets.
	if acc.blocked() {
		// The prompt itself was blocked: no candidate was ever generated, so
		// the finish reason below never arrives and this is the only signal.
		return nil, &llm.Refusal{
			Model:       model,
			Category:    string(acc.blockReason),
			Explanation: acc.blockMessage,
		}
	}
	if !acc.sawCandidate {
		return nil, fmt.Errorf("the model returned no candidates and reported no block reason")
	}
	switch acc.finishReason {
	case genai.FinishReasonSafety, genai.FinishReasonBlocklist,
		genai.FinishReasonProhibitedContent, genai.FinishReasonSPII,
		genai.FinishReasonRecitation:
		// The other refusal shape: the model started answering and a
		// classifier stopped it. Recitation belongs here too — it is the
		// model declining to emit content, not a transport failure, and
		// whatever text preceded the stop is not a report.
		return nil, &llm.Refusal{
			Model:       model,
			Category:    string(acc.finishReason),
			Explanation: acc.finishMessage,
		}
	case genai.FinishReasonMaxTokens:
		return nil, fmt.Errorf(
			"the model reached its %d-token output cap before finishing the report; raise llm.max_tokens",
			c.maxTokens)
	case genai.FinishReasonStop:
		// A natural end. The text decides from here.
	case "", genai.FinishReasonUnspecified:
		// The API names a reason on the last chunk of every completed
		// response, so a stream that never carried one ended early — a
		// connection closed cleanly mid-answer looks exactly like this. What
		// arrived is not a judgement, and it must not be parsed as one.
		return nil, fmt.Errorf("the response stream ended without a finish reason")
	default:
		return nil, fmt.Errorf("the model stopped before finishing the report (finish reason %q%s)",
			acc.finishReason, detail(acc.finishMessage))
	}

	text := acc.text.String()
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("the model returned no output (finish reason %q)", acc.finishReason)
	}

	report, err := findings.Parse([]byte(text))
	if err != nil {
		return nil, err
	}

	return &llm.ReviewResult{
		Report: report,
		Model:  model,
		// No Fallback: this API has no server-side fallback equivalent, and
		// inventing a signal that resembles one would misreport which model
		// answered — the thing the field exists to keep honest.
		InputTokens: int64(acc.usage.PromptTokenCount),
		// Thoughts are counted apart from candidates here, where the siblings
		// fold reasoning into output. Summing keeps the run log's "output"
		// meaning the same thing whichever provider produced it.
		OutputTokens:    int64(acc.usage.CandidatesTokenCount) + int64(acc.usage.ThoughtsTokenCount),
		CacheReadTokens: int64(acc.usage.CachedContentTokenCount),
	}, nil
}

// accumulator folds a stream of chunks into one response. Chunks carry their
// text incrementally and everything else — finish reason, usage, model
// version — cumulatively or only on the last chunk, so the last value seen
// for each of those is the one that counts.
type accumulator struct {
	text          strings.Builder
	sawCandidate  bool
	finishReason  genai.FinishReason
	finishMessage string
	blockReason   genai.BlockedReason
	blockMessage  string
	model         string
	usage         genai.GenerateContentResponseUsageMetadata
}

func (a *accumulator) add(chunk *genai.GenerateContentResponse) {
	if chunk == nil {
		return
	}
	if chunk.ModelVersion != "" {
		a.model = chunk.ModelVersion
	}
	if chunk.UsageMetadata != nil {
		a.usage = *chunk.UsageMetadata
	}
	if feedback := chunk.PromptFeedback; feedback != nil && feedback.BlockReason != "" {
		a.blockReason = feedback.BlockReason
		a.blockMessage = feedback.BlockReasonMessage
	}
	if len(chunk.Candidates) == 0 || chunk.Candidates[0] == nil {
		return
	}
	// Only the first candidate: candidateCount is left at its default of one,
	// and a second would be a second review to reconcile, not more evidence.
	candidate := chunk.Candidates[0]
	a.sawCandidate = true
	if candidate.FinishReason != "" {
		a.finishReason = candidate.FinishReason
	}
	if candidate.FinishMessage != "" {
		a.finishMessage = candidate.FinishMessage
	}
	if candidate.Content == nil {
		return
	}
	for _, part := range candidate.Content.Parts {
		// Thought parts are the model's reasoning, not the report, exactly as
		// the Anthropic provider skips thinking blocks.
		if part == nil || part.Thought {
			continue
		}
		a.text.WriteString(part.Text)
	}
}

// blocked reports whether the prompt was refused before any candidate was
// generated. The unspecified value is the enum's zero and carries no
// judgement.
func (a *accumulator) blocked() bool {
	return a.blockReason != "" && a.blockReason != genai.BlockedReasonUnspecified
}

func detail(message string) string {
	if message == "" {
		return ""
	}
	return ": " + message
}
