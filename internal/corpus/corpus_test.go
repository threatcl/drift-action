// Package corpus runs the finding-quality corpus: paired threat models and
// synthetic diffs with known expected findings, one case per drift category
// plus a clean case. This is the suite that says whether the engine is any
// good — everything else in the repo only says whether it runs.
//
// Expectations assert category and cited file, deliberately nothing else:
// severity and exact line numbers both proved unstable across runs of the
// same review.
//
// TestCorpusAssembles always runs and is free — it proves every case parses
// and assembles into a review request. TestCorpus runs inference and is
// gated on THREATCL_DRIFT_CORPUS:
//
//	THREATCL_DRIFT_CORPUS=live   ANTHROPIC_API_KEY=… go test ./internal/corpus -v -timeout 60m
//	THREATCL_DRIFT_CORPUS=record ANTHROPIC_API_KEY=… go test ./internal/corpus -v -timeout 60m
//	THREATCL_DRIFT_CORPUS=replay go test ./internal/corpus -v
//
// record writes each case's review to <case>/recording.<provider>.json;
// replay asserts against those recordings without paying for inference. In
// replay mode a case with no recording fails — this suite is CI's quality
// gate, so it must never pass by having measured nothing.
package corpus

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/deps"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/engine"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
	"github.com/threatcl/drift-action/internal/llm/fixture"
	"github.com/threatcl/drift-action/internal/model"
)

// modeEnv selects how TestCorpus reviews: live, record, or replay. Unset
// skips inference entirely, so `go test ./...` never costs money.
const modeEnv = "THREATCL_DRIFT_CORPUS"

// TestRepoThreatModel guards this repository's own dogfooding: the root
// threat model must always load through the engine, and every file its prose
// references must exist — those references are what context stuffing and
// narrowing survival hang off, so a rename that orphans one quietly weakens
// the action's review of its own PRs.
func TestRepoThreatModel(t *testing.T) {
	root := filepath.Join("..", "..")
	assertions, err := model.Load(filepath.Join(root, "threatcl-drift-action.tm.hcl"))
	if err != nil {
		t.Fatalf("the repo's own threat model does not load: %v", err)
	}

	summary := assertions.Summary()
	if summary.Threats == 0 || summary.Controls == 0 {
		t.Errorf("summary came back empty: %s", summary)
	}

	refs := assertions.ReferencedPaths()
	t.Logf("prose-referenced paths (context-stuffing triggers): %v", refs)
	if len(refs) == 0 {
		t.Error("the model's prose references no files, so context stuffing can never engage on this repo")
	}
	for _, ref := range refs {
		if _, err := os.Stat(filepath.Join(root, ref)); err != nil {
			t.Errorf("the model references %s, which does not exist — update the threat model alongside the rename", ref)
		}
	}
}

// expectation is one case's expected.json.
type expectation struct {
	Description string            `json:"description"`
	NoDrift     bool              `json:"no_drift"`
	Findings    []expectedFinding `json:"findings"`
	// ContextFiles lists workspace files the assembled request must send
	// whole. Cases that hinge on context stuffing (phantom controls above
	// all) declare it, so a prompt-assembly regression that stops sending
	// the file fails the free test instead of silently weakening the case.
	ContextFiles []string `json:"context_files"`
}

// expectedFinding names the one stable thing a finding must get right: what
// kind of drift it is, and which file proves it.
type expectedFinding struct {
	Category     string `json:"category"`
	EvidenceFile string `json:"evidence_file"`
}

// changeSpec is one entry in a case's changes.json. The patch lives in a
// sibling file rather than a JSON string so it stays readable and editable.
type changeSpec struct {
	Path      string `json:"path"`
	OldPath   string `json:"old_path"`
	Status    string `json:"status"`
	PatchFile string `json:"patch_file"`
}

func corpusDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "corpus")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("corpus directory: %v", err)
	}
	return dir
}

func caseNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(corpusDir(t))
	if err != nil {
		t.Fatalf("reading corpus: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("corpus holds no cases")
	}
	return names
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
}

func readChanges(t *testing.T, dir string) []diff.Change {
	t.Helper()
	var specs []changeSpec
	readJSON(t, filepath.Join(dir, "changes.json"), &specs)

	changes := make([]diff.Change, 0, len(specs))
	for _, spec := range specs {
		change := diff.Change{Path: spec.Path, OldPath: spec.OldPath, Status: spec.Status}
		if spec.PatchFile != "" {
			raw, err := os.ReadFile(filepath.Join(dir, spec.PatchFile))
			if err != nil {
				t.Fatalf("reading patch for %s: %v", spec.Path, err)
			}
			change.Patch = string(raw)
		}
		changes = append(changes, change)
	}
	return changes
}

// assemble builds the review request for one case through the same code the
// action runs: engine.FilterChanges and engine.AssembleRequest. Reproducing
// either here is how the corpus previously came to measure a request the
// action does not send.
func assemble(t *testing.T, dir string) llm.ReviewRequest {
	t.Helper()
	cfg := config.Default()
	workspace := filepath.Join(dir, "workspace")

	paths, err := model.Resolve(workspace, nil)
	if err != nil {
		t.Fatalf("resolving the threat model: %v", err)
	}
	assertions, err := model.LoadIn(workspace, paths[0])
	if err != nil {
		t.Fatalf("loading the threat model: %v", err)
	}

	changes := readChanges(t, dir)
	filtered := engine.FilterChanges(cfg, assertions, changes)
	if len(filtered.Kept) == 0 {
		t.Fatalf("the filter kept none of the case's %d change(s); the review would assess nothing", len(changes))
	}

	assembly := engine.AssembleRequest(cfg, engine.RequestInput{
		Workspace:     workspace,
		Assertions:    assertions,
		Kept:          filtered.Kept,
		ManifestFacts: deps.Facts(filtered.Kept),
	})
	// The action turns both of these into comment notes and reviews what is
	// left. A corpus case is a fixed input that is supposed to fit, so either
	// one means the case itself needs fixing.
	if len(assembly.TooLarge) > 0 {
		t.Fatalf("case exceeds the patch budget: %s", strings.Join(assembly.TooLarge, ", "))
	}
	if len(assembly.Skipped) > 0 {
		t.Fatalf("context files could not be read: %s", strings.Join(assembly.Skipped, ", "))
	}
	return assembly.Request
}

func readExpectation(t *testing.T, dir string) expectation {
	t.Helper()
	var expected expectation
	readJSON(t, filepath.Join(dir, "expected.json"), &expected)

	for _, want := range expected.Findings {
		if !slices.Contains(findings.Categories, findings.Category(want.Category)) {
			t.Fatalf("expected.json names unknown category %q", want.Category)
		}
		if want.EvidenceFile == "" {
			t.Fatalf("expected.json has a finding with no evidence_file")
		}
	}
	if expected.NoDrift && len(expected.Findings) > 0 {
		t.Fatal("expected.json claims no_drift but lists findings")
	}
	if !expected.NoDrift && len(expected.Findings) == 0 {
		t.Fatal("expected.json expects drift but lists no findings")
	}
	return expected
}

// TestCorpusAssembles is the free half: every case must parse, filter to a
// non-empty review set, and assemble into a request whose diff carries the
// files the expectations will demand citations from. It runs in ordinary
// `go test ./...`, so a broken case fails CI rather than the next paid run.
func TestCorpusAssembles(t *testing.T) {
	for _, name := range caseNames(t) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(corpusDir(t), name)
			expected := readExpectation(t, dir)
			request := assemble(t, dir)

			if request.ModelAssertions == "" {
				t.Error("assembled request carries no model assertions")
			}
			for _, want := range expected.Findings {
				if !strings.Contains(request.Diff, want.EvidenceFile) {
					t.Errorf("the rendered diff never mentions %s, but the case expects a citation of it",
						want.EvidenceFile)
				}
			}
			for _, want := range expected.ContextFiles {
				if !slices.ContainsFunc(request.ContextFiles, func(f llm.ContextFile) bool {
					return f.Path == want
				}) {
					t.Errorf("context stuffing did not send %s, which this case depends on", want)
				}
			}
		})
	}
}

// TestCorpus is the paid half: it reviews every case and asserts the expected
// findings came back. Cases run sequentially — parallel reviews would race
// the provider's rate limits, and a corpus run is about accuracy, not speed.
func TestCorpus(t *testing.T) {
	mode := os.Getenv(modeEnv)
	if mode == "" {
		t.Skipf("set %s=live|record|replay to run the finding-quality corpus (live and record pay for inference)", modeEnv)
	}
	if mode != "live" && mode != "record" && mode != "replay" {
		t.Fatalf("%s is %q, want live, record or replay", modeEnv, mode)
	}

	cfg := config.Default()
	if mode != "replay" && os.Getenv(cfg.APIKeyEnv) == "" {
		t.Fatalf("%s=%s needs %s set", modeEnv, mode, cfg.APIKeyEnv)
	}

	for _, name := range caseNames(t) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(corpusDir(t), name)
			expected := readExpectation(t, dir)
			request := assemble(t, dir)

			provider, err := newProvider(cfg, mode, dir, name)
			if err != nil {
				t.Fatalf("%v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			result, err := provider.Review(ctx, request)
			if err != nil {
				// A refusal lands here too, deliberately: corpus content that
				// trips the provider's safety classifiers is a case that needs
				// rewording, and it must not fail silently.
				t.Fatalf("review failed: %v", err)
			}

			for _, note := range result.Notes {
				// In replay mode this is where a stale recording announces
				// itself. The categories were asserted at record time; what a
				// stale replay no longer measures is the current prompt.
				t.Logf("note: %s", note)
			}

			report := result.Report
			if dropped := findings.Sanitize(report); len(dropped) > 0 {
				t.Logf("sanitize dropped %d finding(s) with no evidence", len(dropped))
			}

			assertExpectations(t, expected, report)
		})
	}
}

// recordingPath names one case's recording for one provider. Recordings are
// per provider because each provider has to earn its place on the same seven
// cases under its own recordings, and adding one must leave the Anthropic
// baseline untouched.
func recordingPath(dir, provider string) string {
	return filepath.Join(dir, "recording."+provider+".json")
}

// newProvider builds the provider for one case in the given mode. Record and
// replay wrap the live provider here rather than in engine.NewProvider: which
// case is being recorded is the corpus's business.
//
// A missing recording in replay mode is an error, never a skip. ci.yml runs
// replay as the finding-quality gate, and a skipped case makes a green run
// that measured nothing — deleting every recording would have passed CI.
func newProvider(cfg config.Config, mode, dir, name string) (llm.Provider, error) {
	recording := recordingPath(dir, cfg.Provider)
	if mode == "replay" {
		if _, err := os.Stat(recording); err != nil {
			return nil, fmt.Errorf("no %s recording for %s; run once with %s=record to create it",
				cfg.Provider, name, modeEnv)
		}
		return fixture.NewPlayer(recording), nil
	}

	live, err := engine.NewProvider(cfg, os.Getenv(cfg.APIKeyEnv))
	if err != nil {
		return nil, err
	}
	if mode == "record" {
		return fixture.NewRecorder(live, recording, "corpus/"+name), nil
	}
	return live, nil
}

func assertExpectations(t *testing.T, expected expectation, report *findings.Report) {
	t.Helper()

	if expected.NoDrift {
		if len(report.Findings) > 0 || !report.NoDrift {
			t.Errorf("clean case produced findings — the cries-wolf failure mode: %s", describe(report))
		}
		return
	}

	if report.NoDrift {
		t.Errorf("drift case came back no_drift=true: %s", report.Summary)
	}
	for _, want := range expected.Findings {
		if !hasFinding(report, want) {
			t.Errorf("no %s finding cites %s; the review produced: %s",
				want.Category, want.EvidenceFile, describe(report))
		}
	}
	// Extra findings are logged, never failed: over-reporting an adjacent
	// category is judgement, not error, and worth eyeballing rather than
	// gating on.
	if len(report.Findings) > len(expected.Findings) {
		t.Logf("review produced %d finding(s) beyond the %d expected: %s",
			len(report.Findings)-len(expected.Findings), len(expected.Findings), describe(report))
	}
}

func hasFinding(report *findings.Report, want expectedFinding) bool {
	for _, finding := range report.Findings {
		if string(finding.Category) != want.Category {
			continue
		}
		for _, evidence := range finding.Evidence {
			if evidence.File == want.EvidenceFile {
				return true
			}
		}
	}
	return false
}

// describe summarises a report for failure messages: every finding as
// "category @ cited files".
func describe(report *findings.Report) string {
	if len(report.Findings) == 0 {
		return "no findings"
	}
	parts := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		files := make([]string, 0, len(finding.Evidence))
		for _, evidence := range finding.Evidence {
			files = append(files, evidence.File)
		}
		parts = append(parts, fmt.Sprintf("%s @ %s", finding.Category, strings.Join(files, ", ")))
	}
	return strings.Join(parts, "; ")
}
