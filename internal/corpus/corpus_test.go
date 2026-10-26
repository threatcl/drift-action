// Package corpus runs the finding-quality corpus: paired threat models and
// synthetic diffs with known expected findings, one case per drift category
// plus a clean case, and a case whose threat model is a set split across
// files. This is the suite that says whether the engine is any good —
// everything else in the repo only says whether it runs.
//
// Expectations assert category and cited code file — plus, where a case names
// one, the model file the finding's excerpt cites — and deliberately nothing
// else: severity and exact line numbers both proved unstable across runs of
// the same review.
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
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/cloud/cloudtest"
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

// providerEnv and modelEnv point the corpus at a provider other than the
// default. A new provider earns its place by passing these same cases under
// its own recordings, so the harness has to be able to run any of them
// — recordings are per provider and do not collide.
//
// modelEnv exists because a provider need not have a default model yet: a
// newly added one deliberately has none until a recording has verified it,
// and recording is how it gets verified. Every shipped provider now has one,
// so it is also how a different model is trialled against the corpus.
const (
	providerEnv = "THREATCL_DRIFT_CORPUS_PROVIDER"
	modelEnv    = "THREATCL_DRIFT_CORPUS_MODEL"
)

// corpusConfig builds the config for a corpus run, honouring the provider and
// model overrides. It goes through config.WithProvider rather than assigning
// the field, so the corpus resolves a provider exactly as the action does.
func corpusConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()

	if provider := os.Getenv(providerEnv); provider != "" {
		var err error
		cfg, err = cfg.WithProvider(provider)
		if err != nil {
			t.Fatalf("%s: %v", providerEnv, err)
		}
	}
	if model := os.Getenv(modelEnv); model != "" {
		cfg.Model = model
	}
	if cfg.Model == "" {
		t.Fatalf("provider %q has no default model; set %s", cfg.Provider, modelEnv)
	}
	return cfg
}

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
//
// ModelFile, when set, also pins which threat model file the finding's
// excerpt cites. Only a multi-file case has a wrong answer to that — citing a
// child for a block its parent declares sends the fix to a file that does not
// contain it — so single-file cases leave it empty.
type expectedFinding struct {
	Category     string `json:"category"`
	EvidenceFile string `json:"evidence_file"`
	ModelFile    string `json:"model_file"`
	// LibraryRefs, when present, pins the finding's library_refs: every id
	// listed must be cited, and an empty list means none may be. Absent
	// means not asserted, which is every local-mode case.
	LibraryRefs *[]string `json:"library_refs"`
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

// cloudFixture is a case's recorded Threatcl Cloud answer: cloud/context.json
// is the context response, and the optional cloud/status forces a failure
// instead ("401", "403 upgrade_required", "timeout"). A case without the
// directory runs local, exactly as the action does without a token.
type cloudFixture struct {
	body   []byte
	status int
	code   string
	hang   bool
}

func readCloudFixture(t *testing.T, dir string) *cloudFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "cloud", "context.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	fx := &cloudFixture{body: body}
	if raw, err := os.ReadFile(filepath.Join(dir, "cloud", "status")); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 && fields[0] == "timeout" {
			fx.hang = true
		} else if len(fields) > 0 {
			fx.status, err = strconv.Atoi(fields[0])
			if err != nil {
				t.Fatalf("cloud/status: %v", err)
			}
			if len(fields) > 1 {
				fx.code = fields[1]
			}
		}
	}
	return fx
}

// transport builds the fixture transport, which fails the test on any
// request it did not plan for — an unplanned call to cloud is a test failure,
// never a network call.
func (fx *cloudFixture) transport(t *testing.T) *cloudtest.Transport {
	t.Helper()
	tr := &cloudtest.Transport{Fail: t.Errorf}
	switch {
	case fx.hang:
		tr.Hang = true
	case fx.status != 0:
		tr.ContextStatus = fx.status
		tr.ContextBody = cloudtest.ErrorBody(fx.status, fx.code, "fixture")
	default:
		tr.ContextBody = fx.body
	}
	return tr
}

// cloudContext runs the engine's context call against the fixture, exactly
// as main does, with the base copy of each model file served from the
// workspace (the case is "aligned" unless its fixture says otherwise).
func cloudContext(t *testing.T, cfg config.Config, workspace string, assertions *model.Assertions, fx *cloudFixture) engine.CloudOutcome {
	t.Helper()
	if fx == nil {
		return engine.CloudContext(context.Background(), cfg, engine.CloudInput{Workspace: workspace, Assertions: assertions})
	}
	client, err := cloud.New(cloud.Options{BaseURL: "https://cloud.corpus.test", Token: "tcl_corpus", Version: "corpus", Transport: fx.transport(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if fx.hang {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
	}
	return engine.CloudContext(ctx, cfg, engine.CloudInput{
		Client: client, Workspace: workspace, Repository: "github.com/threatcl/corpus", Assertions: assertions,
		Base: func(_ context.Context, path string) ([]byte, bool, error) {
			raw, err := os.ReadFile(filepath.Join(workspace, path))
			if os.IsNotExist(err) {
				return nil, false, nil
			}
			return raw, err == nil, err
		},
	})
}

// assemble builds the review request for one case through the same code the
// action runs: engine.LoadModel, engine.FilterChanges, engine.CloudContext
// and engine.AssembleRequest. Reproducing any of them here is how the corpus
// previously came to measure a request the action does not send.
//
// A case may carry workspace/.threatcl-ci.hcl, read as the action reads a
// repo's. The multi-file case needs one: discovery refuses to guess between
// several models, so a set is only ever assessed through model_paths. A case
// may also carry cloud/ (see cloudFixture), and then it is a cloud-connected
// review.
func assemble(t *testing.T, dir string) llm.ReviewRequest {
	t.Helper()
	return assembleWith(t, dir, readCloudFixture(t, dir))
}

func assembleWith(t *testing.T, dir string, fx *cloudFixture) llm.ReviewRequest {
	t.Helper()
	workspace := filepath.Join(dir, "workspace")

	cfg, err := config.Default().LoadFile(filepath.Join(workspace, config.DefaultConfigPath))
	if err != nil {
		t.Fatalf("loading the case's config: %v", err)
	}
	assertions, err := engine.LoadModel(workspace, cfg)
	if err != nil {
		t.Fatalf("loading the threat model: %v", err)
	}
	if _, err := engine.CloudLink(cfg, assertions); err != nil {
		t.Fatalf("linking the threat model: %v", err)
	}

	changes := readChanges(t, dir)
	filtered := engine.FilterChanges(cfg, workspace, assertions, changes)
	if len(filtered.Kept) == 0 {
		t.Fatalf("the filter kept none of the case's %d change(s); the review would assess nothing", len(changes))
	}

	outcome := cloudContext(t, cfg, workspace, assertions, fx)
	if fx != nil && fx.status == 0 && !fx.hang && !outcome.Connected {
		t.Fatalf("the cloud fixture did not connect: %s", outcome.Degraded)
	}

	assembly := engine.AssembleRequest(cfg, engine.RequestInput{
		Workspace:     workspace,
		Assertions:    assertions,
		Kept:          filtered.Kept,
		ManifestFacts: deps.Facts(filtered.Kept),
		Library:       outcome.Library,
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
				if want.ModelFile != "" && !strings.Contains(request.ModelAssertions, "("+want.ModelFile+":") {
					t.Errorf("the rendered assertions never cite %s, but the case expects a finding to",
						want.ModelFile)
				}
			}
			for _, want := range expected.ContextFiles {
				if !slices.ContainsFunc(request.ContextFiles, func(f llm.ContextFile) bool {
					return f.Path == want
				}) {
					t.Errorf("context stuffing did not send %s, which this case depends on", want)
				}
			}

			// A cloud case sends the library, the addendum and the cloud
			// schema together; a local case sends none of the three. Half a
			// cloud request is the failure this guards against.
			if readCloudFixture(t, dir) != nil {
				if request.Library == "" || !strings.Contains(request.Prompt, "library_refs") ||
					string(request.Schema) != string(findings.CloudSchemaJSON) {
					t.Error("cloud case assembled without the library, the addendum or the cloud schema")
				}
				for _, want := range expected.Findings {
					if want.LibraryRefs == nil {
						continue
					}
					for _, ref := range *want.LibraryRefs {
						if !strings.Contains(request.Library, ref+" |") {
							t.Errorf("the library sent never lists %s, but the case expects it cited", ref)
						}
					}
				}
			} else if request.Library != "" || string(request.Schema) != string(findings.SchemaJSON) {
				t.Error("local case assembled a cloud request")
			}
		})
	}
}

// TestCorpusDegradedMatchesLocal: when the context call fails, the request is
// the local one to the byte — same digest, same prompt, same schema — so a
// degraded run cannot send a cloud prompt with a local schema or the reverse,
// and the local recordings stay valid for it. Free, and run on every case
// that has a cloud fixture.
func TestCorpusDegradedMatchesLocal(t *testing.T) {
	for _, name := range caseNames(t) {
		dir := filepath.Join(corpusDir(t), name)
		if readCloudFixture(t, dir) == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			local := assembleWith(t, dir, nil)
			for _, fx := range []*cloudFixture{
				{status: http.StatusUnauthorized, code: "token_invalid"},
				{status: http.StatusForbidden, code: "upgrade_required"},
				{status: http.StatusInternalServerError, code: "internal_error"},
				{hang: true},
			} {
				degraded := assembleWith(t, dir, fx)
				if fixture.Digest(degraded) != fixture.Digest(local) {
					t.Errorf("status %d hang=%t: degraded digest differs from local", fx.status, fx.hang)
				}
				if degraded.Prompt != local.Prompt || string(degraded.Schema) != string(local.Schema) {
					t.Errorf("status %d hang=%t: degraded prompt or schema differs from local", fx.status, fx.hang)
				}
			}
			connected := assemble(t, dir)
			if fixture.Digest(connected) == fixture.Digest(local) {
				t.Error("the connected request should differ from the local one")
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

	cfg := corpusConfig(t)
	if mode != "replay" && os.Getenv(cfg.APIKeyEnv) == "" {
		t.Fatalf("%s=%s needs %s set", modeEnv, mode, cfg.APIKeyEnv)
	}
	t.Logf("provider %s, model %s", cfg.Provider, cfg.Model)

	for _, name := range caseNames(t) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(corpusDir(t), name)
			expected := readExpectation(t, dir)
			request := assemble(t, dir)

			provider, err := newProvider(cfg, mode, dir, name)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if mode == "replay" {
				assertRecordingIsCurrent(t, dir, cfg.Provider, request)
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
// per provider because each provider has to earn its place on the same cases
// under its own recordings, and adding one must leave the Anthropic
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

// assertRecordingIsCurrent fails a replayed case whose recording was made
// from a different request than the engine now assembles.
//
// The player reports a mismatch as a note, which the loop logs. That was
// enough when a human was reading -v output and is not enough in CI, where
// nobody reads a passing job's log: a replay asserting against a request the
// engine no longer builds is the gate measuring something that stopped
// existing, while reporting success.
//
// This is narrower than it sounds. The fingerprint covers ReviewRequest's
// data sections and deliberately not its Prompt, so editing prompts/drift-ci.md
// stales nothing. What trips it is a change to how the request is assembled —
// internal/llm/sections.go, the line-number prefixes, deps.Render, context
// selection — or to a case's own inputs. Each of those changes what the model
// actually sees, so the old recording cannot speak to the new behaviour and
// re-recording is the measurement rather than a chore.
func assertRecordingIsCurrent(t *testing.T, dir, provider string, request llm.ReviewRequest) {
	t.Helper()

	raw, err := os.ReadFile(recordingPath(dir, provider))
	if err != nil {
		t.Fatalf("reading the recording: %v", err)
	}
	var recording fixture.Recording
	if err := json.Unmarshal(raw, &recording); err != nil {
		t.Fatalf("parsing the recording: %v", err)
	}

	if recording.RequestDigest == "" {
		t.Fatalf("the recording carries no request fingerprint, so it cannot be checked against the assembled request; re-record with %s=record",
			modeEnv)
	}
	if want := fixture.Digest(request); recording.RequestDigest != want {
		t.Fatalf("the recording was made from a different request (%s) than the engine now assembles, so replaying it measures the old one; re-record with %s=record\n  recorded: %s\n  assembled: %s",
			or(recording.Source, "source unrecorded"), modeEnv, recording.RequestDigest, want)
	}
}

func or(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
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
			cites := want.EvidenceFile
			if want.ModelFile != "" {
				cites += " with a model excerpt from " + want.ModelFile
			}
			t.Errorf("no %s finding cites %s; the review produced: %s",
				want.Category, cites, describe(report))
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
		if want.ModelFile != "" && finding.ModelExcerpt.File != want.ModelFile {
			continue
		}
		if want.LibraryRefs != nil && !refsMatch(finding.LibraryRefs, *want.LibraryRefs) {
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

// refsMatch: every expected ref is cited, and an empty expectation means
// nothing may be. Extra refs beyond a non-empty expectation are judgement and
// pass, as extra findings do.
func refsMatch(got, want []string) bool {
	if len(want) == 0 {
		return len(got) == 0
	}
	for _, ref := range want {
		if !slices.Contains(got, ref) {
			return false
		}
	}
	return true
}

// describe summarises a report for failure messages: every finding as
// "category @ cited files (model: excerpt file)".
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
		refs := ""
		if finding.LibraryRefs != nil {
			refs = fmt.Sprintf(" refs=%v", finding.LibraryRefs)
		}
		parts = append(parts, fmt.Sprintf("%s @ %s (model: %s)%s",
			finding.Category, strings.Join(files, ", "), or(finding.ModelExcerpt.File, "none"), refs))
	}
	return strings.Join(parts, "; ")
}
