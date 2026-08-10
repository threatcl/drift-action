package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/deps"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/gh"
	"github.com/threatcl/drift-action/internal/llm"
	"github.com/threatcl/drift-action/internal/llm/anthropic"
	"github.com/threatcl/drift-action/internal/llm/fixture"
	"github.com/threatcl/drift-action/internal/model"
	"github.com/threatcl/drift-action/internal/render"
	"github.com/threatcl/drift-action/prompts"
)

var version = "dev"

// Verdicts written to the action's `verdict` output.
const (
	verdictClean          = "clean"
	verdictFindings       = "findings"
	verdictActionRequired = "action-required"
	verdictUnassessed     = "unassessed"
	verdictSkipped        = "skipped"
	verdictError          = "error"
)

// Record and replay a review, so the GitHub half of the pipeline can be
// exercised repeatedly without paying for inference each time. Both are
// shell-friendly names, like DryRunEnv — they are set by hand during local
// testing, never by the action.
//
// A replayed run always says so in the comment. It is a testing affordance,
// not a way to produce a review.
const (
	recordEnv = "THREATCL_DRIFT_RECORD"
	replayEnv = "THREATCL_DRIFT_REPLAY"
)

// inferenceTimeout bounds one review. Adaptive thinking over a whole diff at
// high effort runs for minutes, so this is deliberately generous — a review
// cut short mid-thought costs the whole run.
const inferenceTimeout = 10 * time.Minute

func main() {
	log.SetFlags(0)
	log.SetPrefix("threatcl-drift: ")

	if err := run(context.Background()); err != nil {
		if errors.Is(err, errSkipped) {
			log.Printf("%v", err)
			writeOutputs(map[string]string{"verdict": verdictSkipped, "findings-count": "0", "action-required-count": "0"})
			return
		}
		log.Printf("error: %v", err)
		writeOutputs(map[string]string{"verdict": verdictError, "findings-count": "0", "action-required-count": "0"})
		os.Exit(1)
	}
}

// errSkipped marks the run as not-applicable rather than failed: no PR to
// review, or no threat model in the repo. Failing every PR in a repo that has
// not adopted threatcl yet would be hostile.
var errSkipped = errors.New("skipped")

func skip(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errSkipped, fmt.Sprintf(format, args...))
}

func run(ctx context.Context) error {
	log.Printf("threatcl drift-action %s", version)

	prCtx, err := gh.LoadContext()
	if errors.Is(err, gh.ErrNotPullRequest) {
		return skip("no pull request in this event; nothing to review")
	}
	if err != nil {
		return err
	}

	cfg, err := loadConfig(prCtx.Workspace)
	if err != nil {
		return err
	}

	assertions, err := loadModel(prCtx.Workspace, cfg)
	if err != nil {
		return err
	}
	summary := assertions.Summary()
	log.Printf("threat model: %s (%s)", summary.Path, summary)

	if cfg.DryRun {
		log.Printf("dry run: the diff will be fetched and the comment rendered, but nothing will be posted")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		// Needed even in a dry run: the diff comes from the compare API.
		return errors.New("GITHUB_TOKEN is empty; the action needs a token to read the pull request diff")
	}
	client := gh.New(token, prCtx)

	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	comparison, err := client.Compare(fetchCtx, prCtx.BaseSHA, prCtx.HeadSHA)
	if err != nil {
		return err
	}

	filtered := diff.Filter(comparison.Changes, diff.Options{
		ExtraPatterns: append(cfg.TriggerPaths, assertions.ReferencedPaths()...),
		NarrowAbove:   cfg.NarrowAbove,
	})
	log.Printf("diff: %d changed files, %d to review (%d noise, %d narrowed out)",
		len(comparison.Changes), len(filtered.Kept), filtered.Noise, filtered.NarrowedOut)

	manifestFacts := deps.Facts(filtered.Kept)
	log.Printf("dependency manifest changes: %d", len(manifestFacts))

	report, info := analyze(ctx, cfg, analysisInput{
		workspace:     prCtx.Workspace,
		source:        fmt.Sprintf("%s/%s#%d@%s", prCtx.Owner, prCtx.Repo, prCtx.Number, prCtx.HeadSHA),
		summary:       summary,
		assertions:    assertions,
		filtered:      filtered,
		comparison:    comparison,
		manifestFacts: manifestFacts,
	})

	if dropped := findings.Sanitize(report); len(dropped) > 0 {
		// The evidence rule is enforced here, not just in the prompt.
		log.Printf("dropped %d finding(s) with no code evidence", len(dropped))
		info.Notes = append(info.Notes,
			fmt.Sprintf("Evidence rule: %d finding(s) were discarded for citing no code evidence", len(dropped)))
		if len(report.Findings) == 0 && !report.NoDrift {
			// Otherwise the summary still counts findings that no longer
			// exist, and reads as if drift was confirmed.
			report.Summary = "Every finding this review produced was discarded for citing no code evidence, so nothing was confirmed."
		}
	}

	body := render.Comment(report, info)
	reportPath, err := writeReport(body)
	if err != nil {
		log.Printf("warning: could not write report file: %v", err)
	}

	conclusion, title := render.CheckConclusion(report, cfg.FailMode)

	if cfg.DryRun {
		// Print the comment rather than posting it, so a dry run is useful on
		// its own without hunting for the report file. The manifest facts go
		// with it: they are prompt input, and worth eyeballing before they
		// reach a model.
		fmt.Printf("\n### Dependency manifest changes\n\n%s\n%s\n",
			deps.Render(manifestFacts), body)
		log.Printf("dry run: would upsert a sticky comment on %s/%s#%d",
			prCtx.Owner, prCtx.Repo, prCtx.Number)
		log.Printf("dry run: would create check run %q with conclusion %q", title, conclusion)
	} else {
		postCtx, cancelPost := context.WithTimeout(ctx, 2*time.Minute)
		defer cancelPost()

		if err := client.UpsertStickyComment(postCtx, body); err != nil {
			return err
		}
		if err := client.CreateCheckRun(postCtx, prCtx.HeadSHA, conclusion, title, report.Summary); err != nil {
			// Fork PRs get a read-only token, so this is expected there. The
			// comment is already posted; do not fail over the check run.
			log.Printf("warning: %v", err)
		}
	}

	actionRequired := countSeverity(report, findings.SeverityActionRequired)
	writeOutputs(map[string]string{
		"findings-count":        fmt.Sprint(len(report.Findings)),
		"action-required-count": fmt.Sprint(actionRequired),
		"verdict":               verdict(report, actionRequired),
		"report-path":           reportPath,
	})

	log.Printf("%s (check run: %s)", title, conclusion)
	if conclusion == "failure" {
		os.Exit(1)
	}
	return nil
}

// loadConfig layers the config file over the defaults, then the action inputs
// over both — inputs are the highest-precedence layer.
func loadConfig(workspace string) (config.Config, error) {
	cfg, err := config.Default().FromEnv()
	if err != nil {
		return cfg, err
	}
	cfg, err = cfg.LoadFile(filepath.Join(workspace, cfg.ConfigPath))
	if err != nil {
		return cfg, err
	}
	return cfg.FromEnv()
}

func loadModel(workspace string, cfg config.Config) (*model.Assertions, error) {
	paths, err := model.Resolve(workspace, cfg.ModelPaths)
	if errors.Is(err, model.ErrNoModel) {
		return nil, skip("no threat model found in this repo; nothing to drift-check against")
	}
	if err != nil {
		return nil, err
	}
	if len(paths) > 1 {
		return nil, fmt.Errorf(
			"model_paths lists %d files; assessing multiple threat models in one run is not supported yet",
			len(paths))
	}
	return model.LoadIn(workspace, paths[0])
}

// analysisInput is everything the review needs that the run has already
// resolved.
type analysisInput struct {
	workspace string
	// source names the pull request under review, recorded alongside a
	// captured review so a stale recording is recognisable.
	source        string
	summary       model.Summary
	assertions    *model.Assertions
	filtered      diff.Result
	comparison    *gh.CompareResult
	manifestFacts []deps.Delta
}

// analyze assembles the report for this build: it runs the review when there
// is something to review and a key to review it with, and otherwise returns an
// empty report that says so.
//
// Every early return here leaves NoDrift false. A report that found nothing
// because it looked for nothing must never read as clean — only a model that
// actually ran and judged the change consistent may set that flag.
func analyze(ctx context.Context, cfg config.Config, in analysisInput) (*findings.Report, render.ContextInfo) {
	info := render.ContextInfo{
		ModelPath:     in.summary.Path,
		ModelSummary:  in.summary.String(),
		FilesChanged:  len(in.comparison.Changes),
		FilesReviewed: len(in.filtered.Kept),
		NoiseDropped:  in.filtered.Noise,
		Narrowed:      in.filtered.Narrowed,
		NarrowedOut:   in.filtered.NarrowedOut,
		PatchOmitted:  in.comparison.PatchOmitted,
		// Everything filtered away is a coverage statement, not a clean bill
		// of health — but a docs-only PR genuinely has no code to review.
		NothingReviewed: len(in.filtered.Kept) == 0 && len(in.comparison.Changes) > in.filtered.Noise,
	}

	if len(in.filtered.Kept) == 0 {
		info.AnalysisMode = "none — no changed file reached the review, so no drift category was assessed"
		return unassessed("No changed file was reviewed, so nothing was assessed. See the context below for why."), info
	}

	// The cap applies to what would be sent to inference, after filtering and
	// narrowing have already tried to make the diff fit. It is all-or-nothing:
	// reviewing the first N files of a larger set would read as a clean bill
	// for the rest.
	if cfg.MaxDiffFiles > 0 && len(in.filtered.Kept) > cfg.MaxDiffFiles {
		log.Printf("diff too large: %d file(s) to review, max_diff_files is %d; skipping inference",
			len(in.filtered.Kept), cfg.MaxDiffFiles)
		info.OverCap = cfg.MaxDiffFiles
		info.AnalysisMode = fmt.Sprintf(
			"none — %d file(s) needed review, over the max_diff_files cap of %d, so no drift category was assessed",
			len(in.filtered.Kept), cfg.MaxDiffFiles)
		return unassessed(fmt.Sprintf(
			"This diff is too large to review: %d file(s) needed review, over the configured cap of %d. Run `/threat-drift` locally with the threatcl claude-plugin to review it in full.",
			len(in.filtered.Kept), cfg.MaxDiffFiles)), info
	}

	var provider llm.Provider
	replaying := os.Getenv(replayEnv)
	if replaying != "" {
		log.Printf("replaying the review recorded at %s; no model will be called", replaying)
		provider = fixture.NewPlayer(replaying)
	} else {
		apiKey := os.Getenv(cfg.APIKeyEnv)
		if apiKey == "" {
			info.AnalysisMode = fmt.Sprintf(
				"none — %s is unset, so no drift category was assessed", cfg.APIKeyEnv)
			return unassessed(fmt.Sprintf(
				"No API key was supplied (%s is unset), so this pull request was not reviewed for drift.",
				cfg.APIKeyEnv)), info
		}

		live, err := newProvider(cfg, apiKey)
		if err != nil {
			log.Printf("error: %v", err)
			info.AnalysisMode = fmt.Sprintf("none — %v", err)
			return unassessed("This pull request was not reviewed for drift: the configured LLM provider could not be used."), info
		}
		provider = live

		if path := os.Getenv(recordEnv); path != "" {
			log.Printf("recording this review to %s", path)
			provider = fixture.NewRecorder(live, path, in.source)
		}
	}

	diffText, tooLarge := diff.Render(in.filtered.Kept, cfg.MaxPatchBytes)
	if len(tooLarge) > 0 {
		log.Printf("%d file(s) over the %d-byte patch budget were not sent: %s",
			len(tooLarge), cfg.MaxPatchBytes, strings.Join(tooLarge, ", "))
		info.Notes = append(info.Notes, fmt.Sprintf(
			"Patch budget: %d file(s) were too large to send and were not reviewed — %s",
			len(tooLarge), summarise(tooLarge)))
	}

	selection := llm.SelectContext(in.workspace, in.assertions.ReferencedPaths(),
		diff.Paths(in.filtered.Kept), cfg.MaxContextBytes)
	log.Printf("context files: %d sent (%d bytes), %d skipped",
		len(selection.Files), selection.Bytes, len(selection.Skipped))
	if len(selection.Skipped) > 0 {
		info.Notes = append(info.Notes, fmt.Sprintf(
			"Context files: %d file(s) the threat model references could not be sent whole, over budget or unreadable — %s",
			len(selection.Skipped), summarise(selection.Skipped)))
	}

	request := llm.ReviewRequest{
		Prompt:          prompts.DriftCI,
		ModelAssertions: in.assertions.Render(),
		ManifestFacts:   deps.Render(in.manifestFacts),
		Categories:      cfg.Categories,
		ContextFiles:    selection.Files,
		Diff:            diffText,
		Schema:          findings.SchemaJSON,
	}

	reviewCtx, cancel := context.WithTimeout(ctx, inferenceTimeout)
	defer cancel()

	if replaying == "" {
		log.Printf("reviewing %d file(s) with %s (effort %s)",
			len(in.filtered.Kept), cfg.Model, cfg.Effort)
	}
	result, err := provider.Review(reviewCtx, request)

	var refusal *llm.Refusal
	switch {
	case errors.As(err, &refusal):
		// A refusal is an outcome, not a crash: the request succeeded and the
		// model chose not to answer. It renders as "could not assess", never
		// as "no drift".
		log.Printf("%v", refusal)
		info.AnalysisMode = fmt.Sprintf("could not assess — %s declined this request%s",
			or(refusal.Model, cfg.Model), bracket(refusal.Category))
		return unassessed("The model declined to review this pull request, so it was not assessed for drift."), info

	case err != nil:
		// The full error goes to the run log only. A schema-validation failure
		// quotes the model's output, which the pull request's own diff shaped —
		// so it must not be echoed into a comment on that pull request.
		log.Printf("inference failed: %v", err)
		info.AnalysisMode = "could not assess — " + failureKind(err) + "; see the action log"
		return unassessed("Inference failed, so this pull request was not reviewed for drift."), info
	}

	report := result.Report
	if len(report.Findings) > 0 {
		// The model has contradicted itself. Believe the findings.
		report.NoDrift = false
	}

	log.Printf("%s: %d finding(s), no_drift=%t (tokens: %d in, %d cache read, %d out)",
		or(result.Model, "recording"), len(report.Findings), report.NoDrift,
		result.InputTokens, result.CacheReadTokens, result.OutputTokens)

	// A replayed review never passes for a live one, however it is rendered.
	if replaying != "" {
		info.Replayed = true
		info.AnalysisMode = fmt.Sprintf(
			"replayed from %s — no model ran in this build, so these findings were not produced from the current diff",
			displayPath(replaying, in.workspace))
	} else {
		info.AnalysisMode = fmt.Sprintf("%s at %s effort, over %d of %d changed file(s)",
			result.Model, cfg.Effort, len(in.filtered.Kept), len(in.comparison.Changes))
	}
	info.Notes = append(info.Notes, result.Notes...)

	if result.Fallback {
		// Which model answered changes how much weight the findings carry, so
		// a substitution can never be silent.
		info.Notes = append(info.Notes, fmt.Sprintf(
			"Fallback: %s declined this request, and %s served the review in its place",
			cfg.Model, result.Model))
	}
	return report, info
}

func newProvider(cfg config.Config, apiKey string) (llm.Provider, error) {
	switch cfg.Provider {
	case "anthropic", "":
		return anthropic.New(anthropic.Options{
			Model:     cfg.Model,
			APIKey:    apiKey,
			Effort:    cfg.Effort,
			MaxTokens: cfg.MaxTokens,
		}), nil
	default:
		return nil, fmt.Errorf("unknown llm provider %q; v0 supports anthropic only", cfg.Provider)
	}
}

// unassessed builds the report for a run that produced no judgement. NoDrift
// is false by construction: the check run stays neutral and the comment says
// plainly that nothing was assessed.
func unassessed(summary string) *findings.Report {
	return &findings.Report{SchemaVersion: "0.1", Summary: summary}
}

// summarise renders a path list for a PR comment without pasting hundreds of
// entries into it.
func summarise(paths []string) string {
	const limit = 10
	if len(paths) <= limit {
		return "`" + strings.Join(paths, "`, `") + "`"
	}
	return fmt.Sprintf("`%s` and %d more",
		strings.Join(paths[:limit], "`, `"), len(paths)-limit)
}

// failureKind describes an inference failure in the engine's own words. The
// underlying error text is never used: it can quote model output, and model
// output reaches the comment through the report body and nothing else.
func failureKind(err error) string {
	if errors.Is(err, findings.ErrInvalidOutput) {
		return "the model's output did not match the required schema"
	}
	return "the request to the model failed"
}

// displayPath renders a local path for the pull request comment. An absolute
// path would publish the runner's — or a developer's — filesystem layout into
// a comment on a possibly public repository, so only the repo-relative part
// travels. The full path stays in the run log.
func displayPath(path, workspace string) string {
	if rel, err := filepath.Rel(workspace, path); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(path)
}

func or(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func bracket(value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf(" (policy category %s)", value)
}

func countSeverity(report *findings.Report, severity findings.Severity) int {
	count := 0
	for _, finding := range report.Findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

// verdict maps a report to the action's `verdict` output. "clean" is reserved
// for a run that actually assessed the model and found it consistent — a run
// that produced no findings because it assessed nothing reports "unassessed",
// so a workflow gating on the output cannot mistake silence for safety.
func verdict(report *findings.Report, actionRequired int) string {
	switch {
	case actionRequired > 0:
		return verdictActionRequired
	case len(report.Findings) > 0:
		return verdictFindings
	case report.NoDrift:
		return verdictClean
	default:
		return verdictUnassessed
	}
}

// writeReport saves the rendered comment outside the checkout, so a run never
// leaves the working tree dirty.
func writeReport(body string) (string, error) {
	dir := os.Getenv("RUNNER_TEMP")
	if dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "threat-drift-report.md")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// writeOutputs appends key=value pairs to $GITHUB_OUTPUT when running under
// Actions; outside a runner it is a no-op.
func writeOutputs(outputs map[string]string) {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("warning: writing outputs: %v", err)
		return
	}
	defer f.Close()

	for key, value := range outputs {
		if value == "" {
			continue
		}
		if _, err := fmt.Fprintf(f, "%s=%s\n", key, value); err != nil {
			log.Printf("warning: writing output %s: %v", key, err)
			return
		}
	}
}
