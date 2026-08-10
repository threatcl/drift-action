package main

import (
	"context"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/gh"
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
