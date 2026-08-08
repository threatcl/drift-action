package findings

import (
	"encoding/json"
	"testing"
)

// The Go enums and the embedded JSON schema must agree — the schema drives
// the LLM's output and the Go types parse it.
func TestSchemaEnumsMatchGoConsts(t *testing.T) {
	var schema struct {
		Properties struct {
			Findings struct {
				Items struct {
					Properties struct {
						Category struct {
							Enum []string `json:"enum"`
						} `json:"category"`
						Severity struct {
							Enum []string `json:"enum"`
						} `json:"severity"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"findings"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(SchemaJSON, &schema); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}

	gotCategories := schema.Properties.Findings.Items.Properties.Category.Enum
	if len(gotCategories) != len(Categories) {
		t.Fatalf("schema categories = %v, Go consts = %v", gotCategories, Categories)
	}
	want := map[string]bool{}
	for _, c := range Categories {
		want[string(c)] = true
	}
	for _, c := range gotCategories {
		if !want[c] {
			t.Errorf("schema category %q has no Go const", c)
		}
	}

	gotSeverities := schema.Properties.Findings.Items.Properties.Severity.Enum
	if len(gotSeverities) != len(Severities) {
		t.Fatalf("schema severities = %v, Go consts = %v", gotSeverities, Severities)
	}
}

func TestSanitizeDropsEvidencelessFindings(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{Title: "no evidence"},
			{Title: "cited", Evidence: []Evidence{{File: "auth.go", Line: 10, Note: "middleware removed"}}},
		},
	}
	dropped := Sanitize(r)
	if len(dropped) != 1 || dropped[0].Title != "no evidence" {
		t.Fatalf("dropped = %+v", dropped)
	}
	if len(r.Findings) != 1 || r.Findings[0].Title != "cited" {
		t.Fatalf("kept = %+v", r.Findings)
	}
}
