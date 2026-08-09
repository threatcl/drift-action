package anthropic

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

// stream serves a recorded SSE response and captures the request body, so a
// test can assert on what was actually sent without a live API call.
func stream(t *testing.T, events string) (*Client, *string) {
	t.Helper()
	var body string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, events)
	}))
	t.Cleanup(server.Close)

	return New(Options{
		Model:   "claude-opus-5",
		APIKey:  "test-key",
		Effort:  "high",
		BaseURL: server.URL,
	}), &body
}

func event(name, data string) string {
	return "event: " + name + "\ndata: " + data + "\n\n"
}

func messageStart(content string) string {
	return event("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant",`+
		`"model":"claude-opus-5","content":`+content+`,"stop_reason":null,"stop_sequence":null,`+
		`"usage":{"input_tokens":1200,"output_tokens":1,"cache_read_input_tokens":800}}}`)
}

func textBlock(text string) string {
	quoted, _ := json.Marshal(text)
	return event("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) +
		event("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(quoted)+`}}`) +
		event("content_block_stop", `{"type":"content_block_stop","index":0}`)
}

func messageEnd(delta string) string {
	return event("message_delta", `{"type":"message_delta","delta":`+delta+`,"usage":{"output_tokens":900}}`) +
		event("message_stop", `{"type":"message_stop"}`)
}

var endTurn = `{"stop_reason":"end_turn","stop_sequence":null}`

func TestReviewParsesReport(t *testing.T) {
	client, body := stream(t, messageStart("[]")+textBlock(report(t))+messageEnd(endTurn))

	result, err := client.Review(context.Background(), llm.ReviewRequest{
		Prompt:          "PROMPT-SENTINEL",
		ModelAssertions: "ASSERTIONS-SENTINEL",
		Diff:            "DIFF-SENTINEL",
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}

	if got := len(result.Report.Findings); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}
	if result.Report.Findings[0].Category != findings.CategoryPhantomControl {
		t.Errorf("category = %q", result.Report.Findings[0].Category)
	}
	if result.Model != "claude-opus-5" {
		t.Errorf("model = %q", result.Model)
	}
	if result.Fallback {
		t.Error("Fallback = true, want false")
	}
	if result.InputTokens != 1200 || result.CacheReadTokens != 800 || result.OutputTokens != 900 {
		t.Errorf("usage = %d in, %d cached, %d out", result.InputTokens, result.CacheReadTokens, result.OutputTokens)
	}

	// The request has to force the schema, ask for adaptive thinking, opt into
	// fallbacks, and never carry a sampling parameter.
	for _, want := range []string{
		"PROMPT-SENTINEL", "ASSERTIONS-SENTINEL", "DIFF-SENTINEL",
		`"cache_control"`, `"json_schema"`, `"stale_assertion"`, `"adaptive"`,
		`"fallbacks":"default"`, `"effort":"high"`,
	} {
		if !strings.Contains(*body, want) {
			t.Errorf("request body does not contain %s", want)
		}
	}
	for _, unwanted := range []string{`"temperature"`, `"top_p"`, `"top_k"`} {
		if strings.Contains(*body, unwanted) {
			t.Errorf("request body contains %s; current models reject it", unwanted)
		}
	}
}

// A refusal arrives as a successful response with an empty content array. It
// must surface as a refusal, never as an empty (and therefore clean-looking)
// report.
func TestReviewReportsRefusal(t *testing.T) {
	client, _ := stream(t, messageStart("[]")+messageEnd(
		`{"stop_reason":"refusal","stop_sequence":null,`+
			`"stop_details":{"type":"refusal","category":"cyber","explanation":"declined"}}`))

	_, err := client.Review(context.Background(), llm.ReviewRequest{})

	var refusal *llm.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want *llm.Refusal", err)
	}
	if refusal.Category != "cyber" {
		t.Errorf("category = %q, want cyber", refusal.Category)
	}
	if !strings.Contains(refusal.Error(), "declined") {
		t.Errorf("Error() = %q", refusal.Error())
	}
}

// Truncated output is a half-written report, not a short one: it must fail
// loudly rather than reach the renderer.
func TestReviewRejectsTruncatedOutput(t *testing.T) {
	client, _ := stream(t, messageStart("[]")+textBlock(`{"schema_version":"0.1","findings":[`)+
		messageEnd(`{"stop_reason":"max_tokens","stop_sequence":null}`))

	_, err := client.Review(context.Background(), llm.ReviewRequest{})
	if err == nil || !strings.Contains(err.Error(), "max_tokens") {
		t.Fatalf("err = %v, want a max_tokens error", err)
	}
}

func TestReviewRejectsOffSchemaOutput(t *testing.T) {
	client, _ := stream(t, messageStart("[]")+
		textBlock(`{"schema_version":"0.1","no_drift":true,"summary":"fine","findings":[{"category":"invented_category"}]}`)+
		messageEnd(endTurn))

	_, err := client.Review(context.Background(), llm.ReviewRequest{})
	if err == nil || !strings.Contains(err.Error(), "findings schema") {
		t.Fatalf("err = %v, want a schema validation error", err)
	}
}

// When a fallback model serves the review, the result says so — the comment
// has to disclose which model actually answered.
func TestReviewReportsFallback(t *testing.T) {
	client, _ := stream(t, messageStart("[]")+textBlock(report(t))+
		event("message_delta", `{"type":"message_delta","delta":`+endTurn+`,"usage":{"output_tokens":900,`+
			`"iterations":[{"type":"message","model":"claude-opus-5","input_tokens":10,"output_tokens":0},`+
			`{"type":"fallback_message","model":"claude-opus-4-8","input_tokens":1200,"output_tokens":900}]}}`)+
		event("message_stop", `{"type":"message_stop"}`))

	result, err := client.Review(context.Background(), llm.ReviewRequest{})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !result.Fallback {
		t.Error("Fallback = false, want true")
	}
}

func TestNewDefaultsMaxTokens(t *testing.T) {
	if got := New(Options{}).maxTokens; got != DefaultMaxTokens {
		t.Errorf("maxTokens = %d, want %d", got, DefaultMaxTokens)
	}
	if got := New(Options{MaxTokens: 8000}).maxTokens; got != 8000 {
		t.Errorf("maxTokens = %d, want 8000", got)
	}
}
