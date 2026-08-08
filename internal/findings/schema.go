package findings

import _ "embed"

// SchemaJSON is the single source of truth for the report format: sent as the
// forced structured-output schema at inference time, and used to validate the
// parsed response.
//
//go:embed schema/findings-v0.schema.json
var SchemaJSON []byte

// Sanitize enforces the evidence rule — "a drift finding without a code
// reference is a guess" — as a deterministic backstop the LLM cannot bypass:
// findings with no evidence are removed before rendering. Returns the dropped
// findings.
func Sanitize(r *Report) []Finding {
	kept := r.Findings[:0]
	var dropped []Finding
	for _, f := range r.Findings {
		if len(f.Evidence) == 0 {
			dropped = append(dropped, f)
			continue
		}
		kept = append(kept, f)
	}
	r.Findings = kept
	return dropped
}
