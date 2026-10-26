package findings

import _ "embed"

// SchemaJSON is the single source of truth for the report format: sent as the
// forced structured-output schema at inference time, and used to validate the
// parsed response.
//
//go:embed schema/findings-v0.schema.json
var SchemaJSON []byte

// CloudSchemaJSON is the cloud-connected variant: findings-v0 plus one
// required array per finding, library_refs, naming the ORG LIBRARY entries a
// finding corresponds to. It is a separate document rather than a change to
// v0 because every property is required (OpenAI strict mode insists), so
// adding the field to v0 would invalidate every recording made against it.
// Local mode keeps sending v0 unchanged.
//
//go:embed schema/findings-v0-cloud.schema.json
var CloudSchemaJSON []byte

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

// PruneLibraryRefs enforces the library rule the same way Sanitize enforces
// the evidence rule: a finding may cite only reference ids that were in the
// ORG LIBRARY section the model was sent. Any other ref is dropped — a
// hallucinated ref written into a threat model is worse than none — and the
// renderer prints the name from our index, never the model's spelling of it.
// With no library (local mode) every ref is dropped, which is what the v0
// schema already guarantees. Returns how many refs were dropped.
func PruneLibraryRefs(r *Report, known func(string) bool) int {
	dropped := 0
	for i := range r.Findings {
		refs := r.Findings[i].LibraryRefs
		kept := refs[:0]
		seen := map[string]bool{}
		for _, ref := range refs {
			if known != nil && known(ref) && !seen[ref] {
				seen[ref] = true
				kept = append(kept, ref)
				continue
			}
			dropped++
		}
		r.Findings[i].LibraryRefs = kept
	}
	return dropped
}
