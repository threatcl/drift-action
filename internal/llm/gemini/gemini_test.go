package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

// report is a schema-valid drift report, marshalled from the same structs the
// renderer consumes.
func report(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(findings.Report{
		SchemaVersion: "0.1",
		Summary:       "1 finding: a phantom control.",
		Findings: []findings.Finding{{
			Category:     findings.CategoryPhantomControl,
			Severity:     findings.SeverityActionRequired,
			Title:        "Rate limiting is no longer implemented",
			ModelExcerpt: findings.ModelExcerpt{File: "payments.tm.hcl", Line: 84, Quote: `control "rate limiting"`},
			Evidence:     []findings.Evidence{{File: "internal/mw/rate.go", Line: 1, Note: "deleted in this PR"}},
			Relevance:    findings.Relevance{Rating: "strong", Justification: "the middleware was removed"},
			AgentPrompt:  "Update payments.tm.hcl: set implemented = false",
			SuggestedFix: "set implemented = false",
		}},
	})
	if err != nil {
		t.Fatalf("marshalling the fixture report: %v", err)
	}
	return string(raw)
}

// captured is what the fake server saw of the one request a test makes.
type captured struct {
	path   string
	apiKey string
	body   string
}

// serve runs a fake Gemini API that answers every request with the given
// status and body, and returns a client pointed at it plus what it received.
func serve(t *testing.T, status int, body string) (*Client, *captured) {
	t.Helper()
	var got captured

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = captured{path: r.URL.Path, apiKey: r.Header.Get("x-goog-api-key"), body: string(raw)}
		if status == http.StatusOK {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{
		Model:   "test-model",
		APIKey:  "test-key",
		Effort:  "high",
		BaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}
	return client, &got
}

// stream is serve with a 200 and an SSE body.
func stream(t *testing.T, chunks ...string) (*Client, *captured) {
	t.Helper()
	return serve(t, http.StatusOK, strings.Join(chunks, ""))
}

// chunk renders one SSE data event as the API streams it.
func chunk(t *testing.T, response map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshalling a chunk: %v", err)
	}
	return "data: " + string(raw) + "\n\n"
}

// textChunk is a mid-stream chunk carrying one text part and nothing else.
func textChunk(t *testing.T, text string) string {
	t.Helper()
	return chunk(t, map[string]any{
		"candidates": []any{map[string]any{
			"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}},
			"index":   0,
		}},
		"modelVersion": "test-model-001",
	})
}

// finalChunk is the terminal chunk: the finish reason, the usage totals, and
// optionally the last of the text.
func finalChunk(t *testing.T, reason, text string) string {
	t.Helper()
	candidate := map[string]any{"finishReason": reason, "index": 0}
	if text != "" {
		candidate["content"] = map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}}
	}
	return chunk(t, map[string]any{
		"candidates":   []any{candidate},
		"modelVersion": "test-model-001",
		"usageMetadata": map[string]any{
			"promptTokenCount":        100,
			"candidatesTokenCount":    150,
			"thoughtsTokenCount":      50,
			"cachedContentTokenCount": 40,
			"totalTokenCount":         300,
		},
	})
}

func review(t *testing.T, client *Client) (*llm.ReviewResult, error) {
	t.Helper()
	return client.Review(context.Background(), llm.ReviewRequest{
		Prompt:          "drift prompt",
		ModelAssertions: "assertions",
		Diff:            "diff",
		Schema:          findings.SchemaJSON,
	})
}

func TestReviewParsesReport(t *testing.T) {
	// A runner with Vertex selected in its environment must make no
	// difference: the backend is pinned, not inferred.
	t.Setenv("GOOGLE_GENAI_USE_VERTEXAI", "1")

	full := report(t)
	split := len(full) / 2
	client, got := stream(t,
		// A thought part streams first and must not reach the report.
		chunk(t, map[string]any{
			"candidates": []any{map[string]any{
				"content": map[string]any{"role": "model", "parts": []any{
					map[string]any{"text": "Let me think about the diff.", "thought": true},
				}},
				"index": 0,
			}},
		}),
		textChunk(t, full[:split]),
		finalChunk(t, "STOP", full[split:]),
	)

	result, err := review(t, client)
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if len(result.Report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Report.Findings))
	}
	if result.Model != "test-model-001" {
		t.Errorf("model = %q, want the version the API reported", result.Model)
	}
	if result.Fallback {
		t.Error("Fallback must never be set: this API has no server-side fallback")
	}
	// Output counts thoughts as well as candidates, as the siblings' do.
	if result.InputTokens != 100 || result.OutputTokens != 200 || result.CacheReadTokens != 40 {
		t.Errorf("usage = %d/%d/%d", result.InputTokens, result.OutputTokens, result.CacheReadTokens)
	}

	// The request went to the Gemini API, not Vertex, whatever the env said.
	if !strings.HasSuffix(got.path, "/models/test-model:streamGenerateContent") {
		t.Errorf("request path = %q, want the Gemini API streaming endpoint", got.path)
	}
	if strings.Contains(got.path, "projects/") {
		t.Errorf("request was routed to Vertex: %s", got.path)
	}
	if got.apiKey != "test-key" {
		t.Errorf("x-goog-api-key = %q", got.apiKey)
	}

	// The forced-JSON contract: JSON mode and the schema, together.
	if !strings.Contains(got.body, `"responseMimeType":"application/json"`) {
		t.Error("request did not turn JSON mode on")
	}
	if !strings.Contains(got.body, `"responseJsonSchema"`) {
		t.Error("request did not carry the findings schema")
	}
	// const is not in the accepted subset; it must have been rewritten on
	// the way out.
	if strings.Contains(got.body, `"const"`) {
		t.Error("request sent a const, which responseJsonSchema does not accept")
	}
	if !strings.Contains(got.body, `"thinkingLevel":"HIGH"`) {
		t.Errorf("request did not carry the configured effort as a thinking level: %s", got.body)
	}
	if !strings.Contains(got.body, `"maxOutputTokens":32000`) {
		t.Error("request did not carry the default token cap")
	}
	if !strings.Contains(got.body, `"systemInstruction"`) || !strings.Contains(got.body, "drift prompt") {
		t.Error("the prompt was not sent as the system instruction")
	}
	for _, forbidden := range []string{`"temperature"`, `"topP"`, `"topK"`} {
		if strings.Contains(got.body, forbidden) {
			t.Errorf("request set %s, which must be left at the model default", forbidden)
		}
	}
}

// A blocked prompt is a successful response with no candidates at all.
// Rendering it as an empty review would put "no drift" in front of a reader
// for a request the model declined.
func TestReviewSurfacesBlockedPromptAsRefusal(t *testing.T) {
	client, _ := stream(t, chunk(t, map[string]any{
		"promptFeedback": map[string]any{"blockReason": "PROHIBITED_CONTENT"},
		"usageMetadata":  map[string]any{"promptTokenCount": 100, "totalTokenCount": 100},
	}))

	_, err := review(t, client)
	var refusal *llm.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a *llm.Refusal, got %v", err)
	}
	if refusal.Category != "PROHIBITED_CONTENT" {
		t.Errorf("refusal category = %q", refusal.Category)
	}
	if refusal.Model != "test-model" {
		t.Errorf("a refusal with no model version must fall back to the configured model, got %q", refusal.Model)
	}
}

// The other refusal shape: the model started answering and a classifier
// stopped it. Whatever text preceded the stop is not a report — even text
// that happens to be a complete, valid one.
func TestReviewSurfacesSafetyFinishAsRefusal(t *testing.T) {
	client, _ := stream(t,
		textChunk(t, report(t)),
		chunk(t, map[string]any{
			"candidates": []any{map[string]any{
				"finishReason": "SAFETY",
				"index":        0,
			}},
		}),
	)

	_, err := review(t, client)
	var refusal *llm.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a *llm.Refusal, got %v", err)
	}
	if refusal.Category != "SAFETY" {
		t.Errorf("refusal category = %q", refusal.Category)
	}
	if refusal.Model != "test-model-001" {
		t.Errorf("refusal should name the model version the API reported, got %q", refusal.Model)
	}
}

// Hitting the cap truncates the report mid-JSON. That is an error, never a
// rendered half-review — and not a refusal either.
func TestReviewRejectsTruncatedOutput(t *testing.T) {
	client, _ := stream(t,
		textChunk(t, `{"schema_version":"0.1","findings":[`),
		finalChunk(t, "MAX_TOKENS", ""),
	)

	_, err := review(t, client)
	if err == nil {
		t.Fatal("a truncated report must be an error")
	}
	if !strings.Contains(err.Error(), "max_tokens") {
		t.Errorf("error should point at the setting to raise: %v", err)
	}
	var refusal *llm.Refusal
	if errors.As(err, &refusal) {
		t.Error("truncation is not a refusal")
	}
}

// A stop the provider does not recognise is neither a refusal nor a report.
func TestReviewRejectsUnexpectedFinishReason(t *testing.T) {
	client, _ := stream(t, finalChunk(t, "LANGUAGE", report(t)))

	_, err := review(t, client)
	if err == nil {
		t.Fatal("an unexpected finish reason must be an error even when text is present")
	}
	if !strings.Contains(err.Error(), "LANGUAGE") {
		t.Errorf("error should name the finish reason: %v", err)
	}
	var refusal *llm.Refusal
	if errors.As(err, &refusal) {
		t.Error("an unsupported-language stop is not a safety refusal")
	}
}

// Output that does not match the findings schema must be reported as invalid
// model output, which the engine replaces with its own wording rather than
// quoting into a pull request comment.
func TestReviewRejectsOffSchemaOutput(t *testing.T) {
	client, _ := stream(t, finalChunk(t, "STOP", `{"schema_version":"0.1","no_drift":true}`))

	_, err := review(t, client)
	if !errors.Is(err, findings.ErrInvalidOutput) {
		t.Fatalf("expected findings.ErrInvalidOutput, got %v", err)
	}
}

// A stream that ends without ever producing a candidate has produced no
// judgement, and must not be mistaken for one that found nothing.
func TestReviewRejectsEmptyStream(t *testing.T) {
	client, _ := stream(t)

	_, err := review(t, client)
	if err == nil {
		t.Fatal("an empty stream must be an error")
	}
	var refusal *llm.Refusal
	if errors.As(err, &refusal) {
		t.Error("an empty stream is not a refusal: nothing reported a block")
	}
}

// A stream that carries text but never a finish reason ended early. It has
// produced no judgement, and must not be mistaken for one — even when the
// text so far happens to be a complete report.
func TestReviewRejectsStreamWithNoFinishReason(t *testing.T) {
	client, _ := stream(t, textChunk(t, report(t)))

	_, err := review(t, client)
	if err == nil {
		t.Fatal("a stream with no finish reason must be an error")
	}
	if !strings.Contains(err.Error(), "finish reason") {
		t.Errorf("error should say the stream ended early: %v", err)
	}
	if errors.Is(err, findings.ErrInvalidOutput) {
		t.Error("an early-ended stream is a transport outcome, not invalid model output")
	}
	var refusal *llm.Refusal
	if errors.As(err, &refusal) {
		t.Error("an early-ended stream is not a refusal")
	}
}

// A candidate that finishes cleanly with no text is not a clean review.
func TestReviewRejectsEmptyOutput(t *testing.T) {
	client, _ := stream(t, finalChunk(t, "STOP", ""))

	_, err := review(t, client)
	if err == nil {
		t.Fatal("empty output must be an error")
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Errorf("error = %v", err)
	}
}

// An API error is a transport failure, surfaced as one. 400 rather than 429
// or 5xx so the SDK's retries do not slow the test down.
func TestReviewSurfacesAPIErrors(t *testing.T) {
	client, _ := serve(t, http.StatusBadRequest,
		`{"error":{"code":400,"message":"Invalid JSON payload","status":"INVALID_ARGUMENT"}}`)

	_, err := review(t, client)
	if err == nil {
		t.Fatal("an API error must be an error")
	}
	if !strings.Contains(err.Error(), "Invalid JSON payload") {
		t.Errorf("error should carry the API's message: %v", err)
	}
	var refusal *llm.Refusal
	if errors.As(err, &refusal) {
		t.Error("an API error is not a refusal")
	}
}

// The SDK validates credentials at construction, so a client with no key is
// refused up front rather than at the first request.
func TestNewRejectsMissingKey(t *testing.T) {
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")

	if _, err := New(Options{Model: "test-model"}); err == nil {
		t.Fatal("a client with no API key must not be built")
	}
}

// The SDK's own env-var fallback is preserved, so a locally exported key
// works without being threaded through Options.
func TestNewFallsBackToEnvKey(t *testing.T) {
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "from-env")

	if _, err := New(Options{Model: "test-model"}); err != nil {
		t.Fatalf("GEMINI_API_KEY should satisfy the SDK: %v", err)
	}
}

func TestThinkingLevel(t *testing.T) {
	tests := map[string]string{
		"":       "",
		"low":    "LOW",
		"medium": "MEDIUM",
		"high":   "HIGH",
		// The API has nothing above HIGH; the top of config's scale collapses
		// onto it rather than being rejected for this provider alone.
		"xhigh": "HIGH",
		"max":   "HIGH",
	}
	for effort, want := range tests {
		if got := string(thinkingLevel(effort)); got != want {
			t.Errorf("thinkingLevel(%q) = %q, want %q", effort, got, want)
		}
	}
}

// Empty effort must leave thinking config off the wire entirely, so the
// model's own default applies rather than an explicit unspecified level.
func TestReviewOmitsThinkingConfigWithoutEffort(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, finalChunk(t, "STOP", report(t)))
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{Model: "test-model", APIKey: "test-key", BaseURL: server.URL})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}
	if _, err := review(t, client); err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if strings.Contains(body, "thinkingConfig") {
		t.Errorf("thinkingConfig was sent with no effort configured: %s", body)
	}
}
