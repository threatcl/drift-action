package main

import (
	"context"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/gh"
	"github.com/threatcl/drift-action/internal/render"
)

// Over max_diff_files the run must refuse before any provider is built: no
// API key is consulted, nothing is sent, and the report says to run locally.
func TestAnalyzeRefusesOverCap(t *testing.T) {
	cfg := config.Default()
	cfg.MaxDiffFiles = 2
	t.Setenv(replayEnv, "")
	t.Setenv(cfg.APIKeyEnv, "")

	kept := []diff.Change{{Path: "a.go"}, {Path: "b.go"}, {Path: "c.go"}}
	report, info := analyze(context.Background(), cfg, analysisInput{
		filtered:   diff.Result{Kept: kept},
		comparison: &gh.CompareResult{Changes: kept},
	})

	if info.OverCap != 2 {
		t.Errorf("OverCap = %d, want 2", info.OverCap)
	}
	if len(report.Findings) != 0 || report.NoDrift {
		t.Errorf("over-cap report must be unassessed: findings=%d no_drift=%t",
			len(report.Findings), report.NoDrift)
	}
	if !strings.Contains(report.Summary, "claude-plugin") {
		t.Errorf("over-cap summary should point at the local plugin: %q", report.Summary)
	}
	if got := verdict(report, 0); got != verdictUnassessed {
		t.Errorf("verdict = %q, want %q", got, verdictUnassessed)
	}
}

// A pull request touching only what the repo excluded has nothing to review,
// like a docs-only one: no coverage warning above the fold. But what was
// excluded is still named in the comment, because neither an ignore_paths
// entry nor a generated header shows in a file's path.
func TestAnalyzeNamesExcludedFiles(t *testing.T) {
	cfg := config.Default()
	t.Setenv(replayEnv, "")
	t.Setenv(cfg.APIKeyEnv, "")

	changes := []diff.Change{{Path: "gen/a.go"}, {Path: "db/queries.go"}, {Path: "README.md"}}
	report, info := analyze(context.Background(), cfg, analysisInput{
		filtered: diff.Result{
			Noise:     2,
			Generated: []string{"db/queries.go"},
			Ignored:   []string{"gen/a.go"},
		},
		comparison: &gh.CompareResult{Changes: changes},
	})

	if info.NothingReviewed {
		t.Error("NothingReviewed set for a pull request touching only noise and excluded files")
	}
	if info.Ignored != 1 {
		t.Errorf("Ignored = %d, want 1", info.Ignored)
	}
	body := render.Comment(report, info)
	for _, want := range []string{
		"(2 skipped as docs, lock files, vendored or generated; 1 excluded by `ignore_paths`)",
		"Ignored: 1 file(s) excluded by `ignore_paths` — `gen/a.go`",
		"Generated: 1 Go file(s) skipped for a `Code generated … DO NOT EDIT.` header — `db/queries.go`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("comment missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "No drift detected") {
		t.Errorf("a run that reviewed nothing must not read as clean:\n%s", body)
	}
}

// At the cap the review proceeds: the boundary is "more than", not "at least".
func TestAnalyzeAtCapProceeds(t *testing.T) {
	cfg := config.Default()
	cfg.MaxDiffFiles = 3
	t.Setenv(replayEnv, "")
	// With no key the run stops at the key check — past the cap check, which
	// is all this test cares about.
	t.Setenv(cfg.APIKeyEnv, "")

	kept := []diff.Change{{Path: "a.go"}, {Path: "b.go"}, {Path: "c.go"}}
	_, info := analyze(context.Background(), cfg, analysisInput{
		filtered:   diff.Result{Kept: kept},
		comparison: &gh.CompareResult{Changes: kept},
	})

	if info.OverCap != 0 {
		t.Errorf("OverCap = %d, want 0 at the cap", info.OverCap)
	}
	if !strings.Contains(info.AnalysisMode, cfg.APIKeyEnv) {
		t.Errorf("at-cap run should have reached the key check, got mode %q", info.AnalysisMode)
	}
}
