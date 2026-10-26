package fixture

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

// A cloud-mode answer carries library_refs — an empty array in the common
// case, which a re-serialisation of the parsed struct would drop through
// omitempty and so fail the cloud schema on replay. The recorder keeps the
// provider's raw output, and the player validates it against the schema the
// replaying request carries.
func TestCloudRecordingRoundTripsRawOutput(t *testing.T) {
	raw := []byte(`{"schema_version":"0.1","no_drift":false,"summary":"1 finding.","findings":[{` +
		`"category":"dfd_drift","severity":"review_recommended","title":"Missing flow",` +
		`"model_excerpt":{"file":"app.tm.hcl","line":9,"quote":"flow"},` +
		`"evidence":[{"file":"server.go","line":3,"note":"new call"}],` +
		`"relevance":{"rating":"moderate","justification":"j"},` +
		`"agent_prompt":"a","suggested_fix":"s","library_refs":[]}]}`)
	report, err := findings.ParseWith(findings.CloudSchemaJSON, raw)
	if err != nil {
		t.Fatal(err)
	}

	cloudReq := llm.ReviewRequest{ModelAssertions: "a", Library: "Threats:\nT-001 | x", Schema: findings.CloudSchemaJSON}
	path := filepath.Join(t.TempDir(), "cloud.json")
	recorder := NewRecorder(stub{result: &llm.ReviewResult{Report: report, Raw: raw, Model: "m"}}, path, "src")
	if _, err := recorder.Review(context.Background(), cloudReq); err != nil {
		t.Fatal(err)
	}

	result, err := NewPlayer(path).Review(context.Background(), cloudReq)
	if err != nil {
		t.Fatalf("replay under the cloud schema: %v", err)
	}
	if result.Report.Findings[0].LibraryRefs == nil || len(result.Report.Findings[0].LibraryRefs) != 0 {
		t.Errorf("library_refs = %v, want an empty, present list", result.Report.Findings[0].LibraryRefs)
	}
	// MarshalIndent re-indents the raw message on the way to disk, so compare
	// content rather than bytes.
	if !strings.Contains(string(result.Raw), `"library_refs"`) {
		t.Errorf("Raw was not carried through the replay: %s", result.Raw)
	}

	// The same recording replayed into a local-mode request is refused: v0
	// has no library_refs, and a fixture is never trusted past the schema.
	localReq := llm.ReviewRequest{ModelAssertions: "a", Schema: findings.SchemaJSON}
	if _, err := NewPlayer(path).Review(context.Background(), localReq); !errors.Is(err, findings.ErrInvalidOutput) {
		t.Errorf("cloud recording under v0 = %v, want ErrInvalidOutput", err)
	}
}

// Every committed local-mode recording predates Raw and carries a report with
// no library_refs; it must keep replaying under v0 and be refused under the
// cloud schema.
func TestLocalRecordingIsRefusedUnderCloudSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.json")
	recorder := NewRecorder(stub{result: &llm.ReviewResult{Report: sampleReport()}}, path, "src")
	if _, err := recorder.Review(context.Background(), request("DIFF")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPlayer(path).Review(context.Background(), request("DIFF")); err != nil {
		t.Errorf("local recording under v0: %v", err)
	}
	cloudReq := request("DIFF")
	cloudReq.Schema = findings.CloudSchemaJSON
	_, err := NewPlayer(path).Review(context.Background(), cloudReq)
	if !errors.Is(err, findings.ErrInvalidOutput) || !strings.Contains(err.Error(), "library_refs") {
		t.Errorf("local recording under the cloud schema = %v, want a library_refs schema failure", err)
	}
}
