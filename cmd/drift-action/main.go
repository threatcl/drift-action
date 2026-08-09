package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/deps"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/gh"
	"github.com/threatcl/drift-action/internal/model"
	"github.com/threatcl/drift-action/internal/render"
)

var version = "dev"

// Verdicts written to the action's `verdict` output.
const (
	verdictClean          = "clean"
	verdictFindings       = "findings"
	verdictActionRequired = "action-required"
	verdictSkipped        = "skipped"
	verdictError          = "error"
)

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

	// Facts the prompt will carry once inference lands. Extracted here so the
	// path is exercised, and printed under dry run for inspection.
	manifestFacts := deps.Facts(filtered.Kept)
	log.Printf("dependency manifest changes: %d", len(manifestFacts))

	report, info := analyze(cfg, summary, filtered, comparison)

	if dropped := findings.Sanitize(report); len(dropped) > 0 {
		// The evidence rule is enforced here, not just in the prompt.
		log.Printf("dropped %d finding(s) with no code evidence", len(dropped))
		info.Notes = append(info.Notes,
			fmt.Sprintf("%d finding(s) were discarded for citing no code evidence", len(dropped)))
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
		fmt.Printf("\n%s\n%s\n", deps.Render(manifestFacts), body)
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

// analyze assembles the report for this build. Inference is not wired up yet
// and nothing else produces findings, so the report is empty by construction —
// what matters is that it says so rather than implying coverage it never had.
func analyze(cfg config.Config, summary model.Summary,
	filtered diff.Result, comparison *gh.CompareResult) (*findings.Report, render.ContextInfo) {

	info := render.ContextInfo{
		ModelPath:     summary.Path,
		ModelSummary:  summary.String(),
		FilesChanged:  len(comparison.Changes),
		FilesReviewed: len(filtered.Kept),
		NoiseDropped:  filtered.Noise,
		Narrowed:      filtered.Narrowed,
		NarrowedOut:   filtered.NarrowedOut,
		PatchOmitted:  comparison.PatchOmitted,
		// Everything filtered away is a coverage statement, not a clean bill
		// of health — but a docs-only PR genuinely has no code to review.
		NothingReviewed: len(filtered.Kept) == 0 && len(comparison.Changes) > filtered.Noise,
		DiffTruncated:   len(comparison.Changes) > cfg.MaxDiffFiles,
		AnalysisMode:    "none — inference is not enabled in this build, so no drift category was assessed",
	}

	// NoDrift stays false. Nothing here assesses drift: the engine parses the
	// model, selects the diff, and extracts manifest facts for the prompt, but
	// judging any of the six categories is the model's job. A report that
	// found nothing because it looked for nothing must not read as clean.
	report := &findings.Report{SchemaVersion: "0.1"}
	if info.NothingReviewed {
		report.Summary = "No changed file was reviewed, so nothing was assessed. See the context below for why."
	} else {
		report.Summary = "Inference is not enabled in this build, so no drift category was assessed."
	}
	return report, info
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

func verdict(report *findings.Report, actionRequired int) string {
	switch {
	case actionRequired > 0:
		return verdictActionRequired
	case len(report.Findings) > 0:
		return verdictFindings
	default:
		return verdictClean
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
