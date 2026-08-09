package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

type stub struct {
	result *llm.ReviewResult
	err    error
}

func (s stub) Review(context.Context, llm.ReviewRequest) (*llm.ReviewResult, error) {
	return s.result, s.err
}

func sampleReport() *findings.Report {
	return &findings.Report{
		SchemaVersion: "0.1",
		Summary:       "1 finding.",
		Findings: []findings.Finding{{
			Category:     findings.CategoryDFDDrift,
			Severity:     findings.SeverityReviewRecommended,
			Title:        "Missing flow",
			ModelExcerpt: findings.ModelExcerpt{File: "app.tm.hcl", Line: 9, Quote: "flow"},
			Evidence:     []findings.Evidence{{File: "server.go", Line: 3, Note: "new call"}},
			Relevance:    findings.Relevance{Rating: "moderate", Justification: "j"},
			AgentPrompt:  "a",
			SuggestedFix: "s",
		}},
	}
}

func request(diff string) llm.ReviewRequest {
	return llm.ReviewRequest{ModelAssertions: "assertions", Diff: diff}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "recording.json")
	req := request("DIFF")

	recorder := NewRecorder(stub{result: &llm.ReviewResult{
		Report: sampleReport(), Model: "claude-opus-5",
	}}, path, "owner/repo#1@abc123")
	if _, err := recorder.Review(context.Background(), req); err != nil {
		t.Fatalf("record: %v", err)
	}

	result, err := NewPlayer(path).Review(context.Background(), req)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(result.Report.Findings) != 1 || result.Report.Findings[0].Title != "Missing flow" {
		t.Fatalf("report = %+v", result.Report)
	}
	if result.Model != "claude-opus-5" {
		t.Errorf("model = %q", result.Model)
	}
	// A recording that still matches the diff needs no warning: the caller
	// already discloses that the run was replayed.
	if len(result.Notes) != 0 {
		t.Errorf("notes = %v, want none", result.Notes)
	}
}

// Replaying against a diff the recording was not made from is the whole
// footgun of this feature, so it has to be visible in the comment.
func TestPlayerFlagsAStaleRecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recording.json")

	recorder := NewRecorder(stub{result: &llm.ReviewResult{Report: sampleReport()}}, path, "owner/repo#1@abc123")
	if _, err := recorder.Review(context.Background(), request("ORIGINAL DIFF")); err != nil {
		t.Fatal(err)
	}

	result, err := NewPlayer(path).Review(context.Background(), request("A DIFFERENT DIFF"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "different diff") {
		t.Fatalf("notes = %v, want a staleness warning", result.Notes)
	}
	if !strings.Contains(result.Notes[0], "owner/repo#1@abc123") {
		t.Errorf("staleness warning does not name the source: %q", result.Notes[0])
	}
}

// A hand-written recording has no fingerprint. Say so rather than implying the
// match was checked.
func TestPlayerFlagsAnUnfingerprintedRecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recording.json")
	report, _ := json.Marshal(sampleReport())
	raw, _ := json.Marshal(Recording{Model: "claude-opus-5", Report: report})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := NewPlayer(path).Review(context.Background(), request("DIFF"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "no request fingerprint") {
		t.Fatalf("notes = %v", result.Notes)
	}
}

// A fixture on disk is not trusted more than a live response: it goes through
// the same schema check.
func TestPlayerValidatesTheRecordedReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recording.json")
	raw := `{"model":"m","report":{"schema_version":"0.1","no_drift":true,"summary":"s",` +
		`"findings":[{"category":"invented_category"}]}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := NewPlayer(path).Review(context.Background(), request("DIFF"))
	if !errors.Is(err, findings.ErrInvalidOutput) {
		t.Fatalf("err = %v, want ErrInvalidOutput", err)
	}
}

// The review has already been paid for by the time the write happens, so a
// failed write costs a note and not the run.
func TestRecorderSurvivesAnUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recording.json")
	if err := os.WriteFile(path, []byte("taken"), 0o644); err != nil {
		t.Fatal(err)
	}

	recorder := NewRecorder(stub{result: &llm.ReviewResult{Report: sampleReport()}},
		filepath.Join(path, "impossible.json"), "")
	result, err := recorder.Review(context.Background(), request("DIFF"))
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "could not be saved") {
		t.Fatalf("notes = %v", result.Notes)
	}
}

func TestRecorderPassesErrorsThrough(t *testing.T) {
	sentinel := errors.New("boom")
	recorder := NewRecorder(stub{err: sentinel}, filepath.Join(t.TempDir(), "r.json"), "")
	if _, err := recorder.Review(context.Background(), request("DIFF")); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the inner error", err)
	}
}
