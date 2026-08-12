package openai

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
		_, _ = io.WriteString(w, events)
	}))
	t.Cleanup(server.Close)

	return New(Options{
		Model:   "test-model",
		APIKey:  "test-key",
		Effort:  "high",
		BaseURL: server.URL,
	}), &body
}

func event(name, data string) string {
	return "event: " + name + "\ndata: " + data + "\n\n"
}

// completed builds a terminal response.completed event carrying one output
// message whose single content part is the report.
func completed(text string) string {
	message, _ := json.Marshal(map[string]any{
		"type":            "response.completed",
		"sequence_number": 1,
		"response": map[string]any{
			"id":         "resp_1",
			"object":     "response",
			"created_at": 1,
			"status":     "completed",
			"model":      "test-model",
			"output": []any{map[string]any{
				"id":     "msg_1",
				"type":   "message",
				"role":   "assistant",
				"status": "completed",
				"content": []any{map[string]any{
					"type":        "output_text",
					"text":        text,
					"annotations": []any{},
				}},
			}},
			"usage": map[string]any{
				"input_tokens":          100,
				"output_tokens":         200,
				"total_tokens":          300,
				"input_tokens_details":  map[string]any{"cached_tokens": 40},
				"output_tokens_details": map[string]any{"reasoning_tokens": 50},
			},
		},
	})
	return event("response.completed", string(message))
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
	client, body := stream(t, completed(report(t)))

	result, err := review(t, client)
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if len(result.Report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Report.Findings))
	}
	if result.Model != "test-model" {
		t.Errorf("model = %q", result.Model)
	}
	if result.Fallback {
		t.Error("Fallback must never be set: this API has no server-side fallback")
	}
	if result.InputTokens != 100 || result.OutputTokens != 200 || result.CacheReadTokens != 40 {
		t.Errorf("usage = %d/%d/%d", result.InputTokens, result.OutputTokens, result.CacheReadTokens)
	}

	// The forced-JSON contract: strict must be on, or the schema is advisory.
	if !strings.Contains(*body, `"strict":true`) {
		t.Error("request did not force strict schema adherence")
	}
	if !strings.Contains(*body, `"reasoning"`) || !strings.Contains(*body, `"high"`) {
		t.Errorf("request did not carry the configured reasoning effort: %s", *body)
	}
	// const is not in strict mode's accepted subset; it must have been
	// rewritten on the way out.
	if strings.Contains(*body, `"const"`) {
		t.Error("request sent a const, which strict structured outputs rejects")
	}
}

// A refusal is a successful response. Rendering it as an empty review would
// put "no drift" in front of a reader for a request the model declined.
func TestReviewSurfacesRefusalContent(t *testing.T) {
	message, _ := json.Marshal(map[string]any{
		"type":            "response.completed",
		"sequence_number": 1,
		"response": map[string]any{
			"id": "resp_1", "object": "response", "created_at": 1,
			"status": "completed", "model": "test-model",
			"output": []any{map[string]any{
				"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
				"content": []any{map[string]any{
					"type":    "refusal",
					"refusal": "I can't help with that.",
				}},
			}},
		},
	})
	client, _ := stream(t, event("response.completed", string(message)))

	_, err := review(t, client)
	var refusal *llm.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a *llm.Refusal, got %v", err)
	}
	if !strings.Contains(refusal.Explanation, "can't help") {
		t.Errorf("refusal did not carry the model's explanation: %+v", refusal)
	}
}

// The other refusal shape: filtered before any refusal message existed, so
// there is nothing to quote and only the reason distinguishes it.
func TestReviewSurfacesContentFilterAsRefusal(t *testing.T) {
	message, _ := json.Marshal(map[string]any{
		"type":            "response.incomplete",
		"sequence_number": 1,
		"response": map[string]any{
			"id": "resp_1", "object": "response", "created_at": 1,
			"status": "incomplete", "model": "test-model",
			"incomplete_details": map[string]any{"reason": "content_filter"},
			"output":             []any{},
		},
	})
	client, _ := stream(t, event("response.incomplete", string(message)))

	_, err := review(t, client)
	var refusal *llm.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a *llm.Refusal, got %v", err)
	}
	if refusal.Category != "content_filter" {
		t.Errorf("refusal category = %q", refusal.Category)
	}
}

// Hitting the cap truncates the report mid-JSON. That is an error, never a
// rendered half-review.
func TestReviewRejectsTruncatedOutput(t *testing.T) {
	message, _ := json.Marshal(map[string]any{
		"type":            "response.incomplete",
		"sequence_number": 1,
		"response": map[string]any{
			"id": "resp_1", "object": "response", "created_at": 1,
			"status": "incomplete", "model": "test-model",
			"incomplete_details": map[string]any{"reason": "max_output_tokens"},
			"output": []any{map[string]any{
				"id": "msg_1", "type": "message", "role": "assistant", "status": "incomplete",
				"content": []any{map[string]any{
					"type": "output_text", "text": `{"schema_version":"0.1","findings":[`,
					"annotations": []any{},
				}},
			}},
		},
	})
	client, _ := stream(t, event("response.incomplete", string(message)))

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

// Output that does not match the findings schema must be reported as invalid
// model output, which the engine replaces with its own wording rather than
// quoting into a pull request comment.
func TestReviewRejectsOffSchemaOutput(t *testing.T) {
	client, _ := stream(t, completed(`{"schema_version":"0.1","no_drift":true}`))

	_, err := review(t, client)
	if !errors.Is(err, findings.ErrInvalidOutput) {
		t.Fatalf("expected findings.ErrInvalidOutput, got %v", err)
	}
}

// A stream that ends without a terminal event has produced no judgement, and
// must not be mistaken for one that found nothing.
func TestReviewRejectsStreamWithNoTerminalEvent(t *testing.T) {
	client, _ := stream(t, event("response.created",
		`{"type":"response.created","sequence_number":0,"response":{"id":"resp_1","object":"response","created_at":1,"status":"in_progress","model":"test-model","output":[]}}`))

	if _, err := review(t, client); err == nil {
		t.Fatal("a stream with no terminal event must be an error")
	}
}

func TestStrictSchemaRewritesConst(t *testing.T) {
	schema, err := strictSchema(findings.SchemaJSON)
	if err != nil {
		t.Fatalf("translating the schema: %v", err)
	}

	if _, ok := schema["$schema"]; ok {
		t.Error("$schema should be dropped: it describes the dialect, not the instance")
	}

	properties, _ := schema["properties"].(map[string]any)
	version, _ := properties["schema_version"].(map[string]any)
	if version == nil {
		t.Fatalf("schema_version property missing: %v", properties)
	}
	if _, ok := version["const"]; ok {
		t.Error("const survived the translation")
	}
	enum, _ := version["enum"].([]any)
	if len(enum) != 1 || enum[0] != "0.1" {
		t.Errorf("const did not become an equivalent single-value enum: %v", version)
	}
	if version["type"] != "string" {
		t.Errorf("a const-only property must gain a type for strict mode: %v", version)
	}

	// The properties the real schema already gets right must survive intact.
	if schema["additionalProperties"] != false {
		t.Error("additionalProperties:false was lost")
	}
	if required, ok := schema["required"].([]any); !ok || len(required) != 4 {
		t.Errorf("required list was lost: %v", schema["required"])
	}
}

// Every object in the translated schema must satisfy strict mode's two
// structural rules, so a future schema edit that breaks them fails here rather
// than at the API.
func TestStrictSchemaIsStructurallyStrict(t *testing.T) {
	schema, err := strictSchema(findings.SchemaJSON)
	if err != nil {
		t.Fatalf("translating the schema: %v", err)
	}

	var check func(node map[string]any, path string)
	check = func(node map[string]any, path string) {
		if node["type"] == "object" {
			properties, _ := node["properties"].(map[string]any)
			required, _ := node["required"].([]any)
			if node["additionalProperties"] != false {
				t.Errorf("%s: additionalProperties must be false", path)
			}
			if len(required) != len(properties) {
				t.Errorf("%s: strict mode requires every property listed in required (%d properties, %d required)",
					path, len(properties), len(required))
			}
		}
		if _, ok := node["const"]; ok {
			t.Errorf("%s: const is not in strict mode's accepted subset", path)
		}
		for key, child := range node {
			switch typed := child.(type) {
			case map[string]any:
				check(typed, path+"/"+key)
			case []any:
				for _, element := range typed {
					if object, ok := element.(map[string]any); ok {
						check(object, path+"/"+key)
					}
				}
			}
		}
	}
	check(schema, "(root)")
}
