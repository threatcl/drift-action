package findings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validReport(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(Report{
		SchemaVersion: "0.1",
		NoDrift:       false,
		Summary:       "1 finding.",
		Findings: []Finding{{
			Category:     CategoryStaleAssertion,
			Severity:     SeverityReviewRecommended,
			Title:        "Hashing moved off BCrypt",
			ModelExcerpt: ModelExcerpt{File: "app.tm.hcl", Line: 12, Quote: "passwords are hashed with BCrypt"},
			Evidence:     []Evidence{{File: "internal/auth/hash.go", Line: 40, Note: "now argon2id"}},
			Relevance:    Relevance{Rating: "strong", Justification: "the diff changes the hash"},
			AgentPrompt:  "Update app.tm.hcl…",
			SuggestedFix: "point the threat description at argon2id",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAcceptsValidReport(t *testing.T) {
	report, err := Parse(validReport(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Category != CategoryStaleAssertion {
		t.Fatalf("report = %+v", report)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]struct{ raw, want string }{
		"not json":  {`not json at all`, "not valid JSON"},
		"truncated": {`{"schema_version":"0.1","findings":[`, "not valid JSON"},
		"wrong schema version": {
			`{"schema_version":"0.2","no_drift":true,"summary":"s","findings":[]}`,
			"findings schema",
		},
		"missing required field": {
			`{"no_drift":true,"summary":"s","findings":[]}`,
			"findings schema",
		},
		"unknown severity": {
			`{"schema_version":"0.1","no_drift":false,"summary":"s","findings":[{"category":"dfd_drift",` +
				`"severity":"catastrophic","title":"t","model_excerpt":{"file":"f","line":1,"quote":"q"},` +
				`"evidence":[],"relevance":{"rating":"weak","justification":"j"},"agent_prompt":"a","suggested_fix":"s"}]}`,
			"findings schema",
		},
		"extra property": {
			`{"schema_version":"0.1","no_drift":true,"summary":"s","findings":[],"exec":"rm -rf /"}`,
			"findings schema",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if err == nil {
				t.Fatal("Parse succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			// Callers branch on the sentinel, never on the message: the
			// validator quotes the offending output, which the pull request's
			// own diff shaped.
			if !errors.Is(err, ErrInvalidOutput) {
				t.Errorf("err = %v, want it to wrap ErrInvalidOutput", err)
			}
		})
	}
}

// An empty findings array is valid: it is how the model reports no drift, and
// how it reports a threat model too vague to drift.
func TestParseAcceptsEmptyFindings(t *testing.T) {
	report, err := Parse([]byte(`{"schema_version":"0.1","no_drift":true,"summary":"consistent","findings":[]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !report.NoDrift {
		t.Error("NoDrift = false, want true")
	}
}
