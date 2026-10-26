package findings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func cloudReport(t *testing.T, refs []string) []byte {
	t.Helper()
	var report Report
	if err := json.Unmarshal(validReport(t), &report); err != nil {
		t.Fatal(err)
	}
	report.Findings[0].LibraryRefs = refs
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// omitempty drops an empty list; the model is required to send one.
	if len(refs) == 0 {
		raw = []byte(strings.Replace(string(raw), `"suggested_fix":`, `"library_refs":[],"suggested_fix":`, 1))
	}
	return raw
}

// Output is checked against the schema it was generated under. A cloud
// answer carries library_refs, which v0 forbids; a local answer lacks it,
// which the cloud schema requires. Neither may pass under the other.
func TestParseWithHoldsOutputToTheSchemaSent(t *testing.T) {
	cloud := cloudReport(t, []string{"T-001"})
	local := validReport(t)

	if _, err := ParseWith(CloudSchemaJSON, cloud); err != nil {
		t.Errorf("cloud output under the cloud schema: %v", err)
	}
	if _, err := ParseWith(SchemaJSON, local); err != nil {
		t.Errorf("local output under v0: %v", err)
	}
	if _, err := ParseWith(SchemaJSON, cloud); !errors.Is(err, ErrInvalidOutput) {
		t.Errorf("cloud output under v0 = %v, want ErrInvalidOutput", err)
	}
	if _, err := ParseWith(CloudSchemaJSON, local); !errors.Is(err, ErrInvalidOutput) {
		t.Errorf("local output under the cloud schema = %v, want ErrInvalidOutput", err)
	}
	// An empty refs list is the normal cloud answer and is valid.
	if _, err := ParseWith(CloudSchemaJSON, cloudReport(t, nil)); err != nil {
		t.Errorf("empty library_refs under the cloud schema: %v", err)
	}
	// An empty schema means v0, so Parse and ParseWith(nil) agree.
	if _, err := ParseWith(nil, local); err != nil {
		t.Errorf("ParseWith(nil) should mean v0: %v", err)
	}
}

// The cloud schema is v0 plus library_refs and nothing else, so the enum
// checks that hold v0 to the Go constants hold it too.
func TestCloudSchemaIsV0PlusLibraryRefs(t *testing.T) {
	var v0, cloud map[string]any
	if err := json.Unmarshal(SchemaJSON, &v0); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(CloudSchemaJSON, &cloud); err != nil {
		t.Fatal(err)
	}
	items := func(s map[string]any) map[string]any {
		return s["properties"].(map[string]any)["findings"].(map[string]any)["items"].(map[string]any)
	}
	cloudItems := items(cloud)
	props := cloudItems["properties"].(map[string]any)
	if _, ok := props["library_refs"]; !ok {
		t.Fatal("cloud schema has no library_refs")
	}
	required := cloudItems["required"].([]any)
	found := false
	for _, r := range required {
		if r == "library_refs" {
			found = true
		}
	}
	if !found {
		t.Error("library_refs is not required; OpenAI strict mode would reject the schema")
	}

	// Strip the addition and the two must agree.
	delete(props, "library_refs")
	var rest []any
	for _, r := range required {
		if r != "library_refs" {
			rest = append(rest, r)
		}
	}
	cloudItems["required"] = rest
	cloud["title"] = v0["title"]
	a, _ := json.Marshal(v0)
	b, _ := json.Marshal(cloud)
	if string(a) != string(b) {
		t.Errorf("cloud schema differs from v0 beyond library_refs:\n v0   %s\n cloud %s", a, b)
	}
}

func TestPruneLibraryRefs(t *testing.T) {
	known := func(ref string) bool { return ref == "T-001" || ref == "C-002" }
	r := &Report{Findings: []Finding{
		{Title: "a", LibraryRefs: []string{"T-001", "T-999", "T-001"}},
		{Title: "b", LibraryRefs: []string{"made-up"}},
		{Title: "c"},
	}}
	if dropped := PruneLibraryRefs(r, known); dropped != 3 {
		t.Errorf("dropped = %d, want 3 (one unknown, one duplicate, one made up)", dropped)
	}
	if got := r.Findings[0].LibraryRefs; len(got) != 1 || got[0] != "T-001" {
		t.Errorf("finding a refs = %v", got)
	}
	if got := r.Findings[1].LibraryRefs; len(got) != 0 {
		t.Errorf("finding b refs = %v, want none", got)
	}

	// Local mode: no library, every ref goes.
	r = &Report{Findings: []Finding{{LibraryRefs: []string{"T-001"}}}}
	if dropped := PruneLibraryRefs(r, nil); dropped != 1 || len(r.Findings[0].LibraryRefs) != 0 {
		t.Errorf("with no library: dropped=%d refs=%v", dropped, r.Findings[0].LibraryRefs)
	}
}
