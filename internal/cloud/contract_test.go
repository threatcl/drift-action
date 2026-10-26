package cloud

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// canonical re-encodes JSON with sorted keys and no insignificant whitespace,
// so two documents compare by content rather than by formatting.
func canonical(t *testing.T, raw []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestContractGoldens is this repo's half of the schema 1 contract. The
// request goldens must survive a decode and re-encode through this package's
// types byte-for-byte in content — a field this side forgets, renames or
// retypes shows up as a difference — and the response golden must decode
// into every field the renderer reads.
func TestContractGoldens(t *testing.T) {
	t.Run("context request", func(t *testing.T) {
		raw := mustRead(t, "testdata/context_request.v1.json")
		var req ContextRequest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			t.Fatalf("golden has a field this client does not know: %v", err)
		}
		if err := validateContextRequest(req); err != nil {
			t.Errorf("the golden request fails local validation: %v", err)
		}
		out, _ := json.Marshal(req)
		if canonical(t, out) != canonical(t, raw) {
			t.Errorf("re-encoded request differs from the golden:\n got %s\nwant %s", canonical(t, out), canonical(t, raw))
		}
	})

	t.Run("review request", func(t *testing.T) {
		raw := mustRead(t, "testdata/review_request.v1.json")
		var rec ReviewRecord
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("golden has a field this client does not know: %v", err)
		}
		if err := rec.Validate(); err != nil {
			t.Errorf("the golden record fails local validation: %v", err)
		}
		out, _ := json.Marshal(rec)
		if canonical(t, out) != canonical(t, raw) {
			t.Errorf("re-encoded record differs from the golden:\n got %s\nwant %s", canonical(t, out), canonical(t, raw))
		}
	})

	t.Run("context response", func(t *testing.T) {
		raw := mustRead(t, "testdata/context_response.v1.json")
		var resp ContextResponse
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("golden has a field this client does not know: %v", err)
		}
		if resp.Schema != SchemaV1 || resp.Org.Tier != "team" {
			t.Errorf("header decoded wrongly: %+v", resp.Org)
		}
		by := map[string]ContextModel{}
		for _, m := range resp.Models {
			by[m.Slug] = m
		}
		for slug, state := range map[string]string{
			"payments": StateAligned, "checkout": StateAhead, "ledger": StateBehind,
			"refunds": StateConflict, "reporting": StateUnsynced, "settlement": StateConflict,
			"ledger-v2": StateNotInCloud,
		} {
			if by[slug].Alignment.State != state {
				t.Errorf("%s: state = %q, want %q", slug, by[slug].Alignment.State, state)
			}
		}
		ledger := by["ledger"]
		if ledger.Alignment.Delta == nil || len(ledger.Alignment.Delta["controls"].Removed) != 1 ||
			ledger.Alignment.Delta["controls"].Removed[0] != "brute force login::lockout" {
			t.Errorf("ledger delta decoded wrongly: %+v", ledger.Alignment.Delta)
		}
		if len(ledger.Alignment.Segments) != 2 || ledger.Alignment.Segments[1].State != StateBehind {
			t.Errorf("ledger segments decoded wrongly: %+v", ledger.Alignment.Segments)
		}
		if by["payments"].Alignment.Delta != nil {
			t.Errorf("aligned model should carry a nil delta, got %+v", by["payments"].Alignment.Delta)
		}
		if by["settlement"].Policy != nil || !by["settlement"].HasNote(NoteHeadParseError) {
			t.Errorf("settlement should have null policy and head_parse_error: %+v", by["settlement"])
		}
		if by["ledger-v2"].ID != nil || by["ledger-v2"].Version != nil {
			t.Errorf("not_in_cloud model should have null id and version: %+v", by["ledger-v2"])
		}
		if by["checkout"].Policy == nil || by["checkout"].Policy.Blocking != 1 {
			t.Errorf("checkout policy decoded wrongly: %+v", by["checkout"].Policy)
		}
		if !by["checkout"].HasNote("unplaced_file:threatmodels/stray.tm.hcl") {
			t.Errorf("checkout notes = %v", by["checkout"].Notes)
		}
		if !resp.Library.Truncated || len(resp.Library.Controls) != 2 {
			t.Errorf("library decoded wrongly: %+v", resp.Library)
		}
	})
}

// TestReviewRecordHasNoFreeText walks the write-back type: every string field,
// at any depth, must carry an enum or a pattern tag. Finding titles, excerpts,
// file paths and summaries are model output shaped by source code, and this
// is what keeps them out of the ledger when a field is added.
func TestReviewRecordHasNoFreeText(t *testing.T) {
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			name := prefix + field.Name
			if stringField(field.Type) {
				if field.Tag.Get("enum") == "" && field.Tag.Get("pattern") == "" {
					t.Errorf("%s is a string with neither an enum nor a pattern tag — the write-back is counts only", name)
				}
				continue
			}
			walk(field.Type, name+".")
		}
	}
	walk(reflect.TypeOf(ReviewRecord{}), "")
}

// TestImportsNothingThatCarriesCode is the structural half of "cloud never
// receives source or diffs": this package imports nothing from the module, so
// it cannot be handed a diff.Change, an llm.ReviewRequest or a findings.Report
// to serialise. cloudtest is held to the same rule.
func TestImportsNothingThatCarriesCode(t *testing.T) {
	for _, dir := range []string{".", "cloudtest"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				spec := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(spec, "github.com/threatcl/drift-action/") {
					t.Errorf("%s imports %s; internal/cloud must import nothing from this module", filepath.Join(dir, name), spec)
				}
			}
		}
	}
}

func TestValidateReviewRecord(t *testing.T) {
	good := reviewRecord()
	if err := good.Validate(); err != nil {
		t.Fatalf("a valid record failed: %v", err)
	}
	for _, tt := range []struct {
		name   string
		mutate func(*ReviewRecord)
		want   string
	}{
		{"bad repository", func(r *ReviewRecord) { r.Repository = "acme payments" }, "repository"},
		{"bad provider", func(r *ReviewRecord) { r.Provider = ptr("vertex") }, "provider"},
		{"bad model version", func(r *ReviewRecord) { r.Models[0].Version = ptr("v 1") }, "models[0].version"},
		{"bad alignment", func(r *ReviewRecord) { r.Models[0].Alignment = "drifted" }, "alignment"},
		{"bad action version", func(r *ReviewRecord) { r.ActionVersion = ptr(strings.Repeat("v", 40)) }, "action_version"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := reviewRecord()
			tt.mutate(&rec)
			err := rec.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to name %s", err, tt.want)
			}
		})
	}
	// Optional fields left nil pass.
	rec := reviewRecord()
	rec.Models = []ReviewModel{{Alignment: StateNotInCloud}}
	if err := rec.Validate(); err != nil {
		t.Errorf("nil id and version for not_in_cloud should pass: %v", err)
	}
}
