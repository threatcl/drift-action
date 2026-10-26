package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/cloud/cloudtest"
	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/engine"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/gh"
	"github.com/threatcl/drift-action/internal/render"
)

func goldenResponse(t *testing.T) *cloud.ContextResponse {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "cloud", "testdata", "context_response.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var resp cloud.ContextResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	return &resp
}

func connectedOutcome(t *testing.T) engine.CloudOutcome {
	t.Helper()
	resp := goldenResponse(t)
	return engine.CloudOutcome{
		Connected: true,
		Response:  resp,
		Link: cloud.LinkResult{Models: []cloud.Linked{
			{Slug: "payments", Org: "acme", Files: []string{"payments.tm.hcl"}},
			{Slug: "ledger", Org: "acme", Files: []string{"ledger.tm.hcl"}},
		}},
		Library: "Threats:\nT-001 | Account takeover\n",
		Index:   map[string]string{"T-001": "Account takeover"},
	}
}

// Local mode renders nothing about cloud: the comment must not change by a
// byte for a repo that never configured it.
func TestCloudInfoNilInLocalMode(t *testing.T) {
	if info := cloudInfo(config.Default(), engine.CloudOutcome{}); info != nil {
		t.Errorf("cloudInfo = %+v, want nil", info)
	}
	degraded := cloudInfo(config.Default(), engine.CloudOutcome{Degraded: "not connected — x"})
	if degraded == nil || degraded.Degraded == "" || len(degraded.Models) != 0 {
		t.Errorf("degraded cloudInfo = %+v", degraded)
	}
}

// Answers pair with files by slug, and only linked models render.
func TestCloudInfoPairsBySlug(t *testing.T) {
	cfg := config.Default()
	cfg.Cloud.PolicyFailMode = config.PolicyFailOnEnforcedViolation
	info := cloudInfo(cfg, connectedOutcome(t))
	if info.Org != "acme" || len(info.Models) != 2 {
		t.Fatalf("info = %+v", info)
	}
	if info.Models[1].Context.Slug != "ledger" || info.Models[1].Files[0] != "ledger.tm.hcl" {
		t.Errorf("second model = %+v", info.Models[1])
	}
	if info.Library.Threats != 2 || !info.Library.Truncated || info.Library.Names["T-001"] != "Account takeover" {
		t.Errorf("library = %+v", info.Library)
	}
	if info.PolicyFailMode != config.PolicyFailOnEnforcedViolation {
		t.Errorf("policy fail mode not carried: %q", info.PolicyFailMode)
	}
}

// The write-back is built from the review and validates against the ledger's
// closed-set rules; its body carries counts and nothing a finding said.
func TestReviewRecordIsCountsOnly(t *testing.T) {
	prCtx := &gh.Context{Owner: "acme", Repo: "payments", Number: 412,
		HeadSHA: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", BaseSHA: "2c26b46b68ffc68ff99b453c1d30413413422d70"}
	outcome := connectedOutcome(t)
	cfg := config.Default()
	info := render.ContextInfo{FilesChanged: 14, FilesReviewed: 9, Cloud: cloudInfo(cfg, outcome)}
	report := &findings.Report{Summary: "SECRET SUMMARY", Findings: []findings.Finding{
		{Category: findings.CategoryStaleAssertion, Severity: findings.SeverityActionRequired, Title: "SECRET TITLE",
			ModelExcerpt: findings.ModelExcerpt{File: "payments.tm.hcl", Quote: "SECRET QUOTE"},
			Evidence:     []findings.Evidence{{File: "internal/secret/path.go", Note: "SECRET NOTE"}}},
		{Category: findings.CategoryUnmodeledSurface, Severity: findings.SeverityReviewRecommended, Title: "t2"},
		{Category: findings.CategoryUnmodeledSurface, Severity: findings.SeverityReviewRecommended, Title: "t3"},
	}}

	rec := reviewRecord(cfg, prCtx, outcome, report, info, "claude-opus-5")
	if err := rec.Validate(); err != nil {
		t.Fatalf("record does not validate: %v", err)
	}
	if rec.Repository != "github.com/acme/payments" || rec.PRNumber != 412 || rec.Verdict != "action-required" {
		t.Errorf("record header = %+v", rec)
	}
	if rec.Counts.StaleAssertion != 1 || rec.Counts.UnmodeledSurface != 2 || rec.ActionRequiredCount != 1 {
		t.Errorf("counts = %+v, action required %d", rec.Counts, rec.ActionRequiredCount)
	}
	if len(rec.Models) != 7 || rec.Models[0].Alignment != cloud.StateAligned || rec.Models[6].ID != nil {
		t.Errorf("models = %+v", rec.Models)
	}
	// Only the linked models (payments, ledger) contribute; ledger has no
	// verdict, so the totals are payments' alone.
	if rec.Policy == nil || rec.Policy.Evaluated != 2 || rec.Policy.Violated != 0 || rec.Policy.Blocking != 0 {
		t.Errorf("policy = %+v", rec.Policy)
	}
	if rec.Provider == nil || *rec.Provider != "anthropic" || rec.LLMModel == nil || *rec.LLMModel != "claude-opus-5" {
		t.Errorf("provider/model = %v/%v", rec.Provider, rec.LLMModel)
	}
	if rec.FilesChanged != 14 || rec.FilesReviewed != 9 {
		t.Errorf("files = %d/%d", rec.FilesChanged, rec.FilesReviewed)
	}

	// Send it through the client and read what crossed the wire.
	transport := &cloudtest.Transport{Fail: t.Errorf}
	client, err := cloud.New(cloud.Options{BaseURL: "https://cloud.test", Token: "tcl_x", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportReview(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	body := string(transport.ReviewRequests()[0])
	for _, secret := range []string{"SECRET", "secret/path", "payments.tm.hcl"} {
		if strings.Contains(body, secret) {
			t.Errorf("write-back carries %q:\n%s", secret, body)
		}
	}
	for _, want := range []string{`"verdict":"action-required"`, `"stale_assertion":1`, `"schema":1`, `"base_sha":"2c26b46b`} {
		if !strings.Contains(body, want) {
			t.Errorf("write-back missing %s:\n%s", want, body)
		}
	}
}

// GITHUB_SERVER_URL decides the host, so an Enterprise Server instance is not
// recorded as github.com.
func TestRepositoryName(t *testing.T) {
	prCtx := &gh.Context{Owner: "acme", Repo: "payments"}
	t.Setenv("GITHUB_SERVER_URL", "")
	if got := repositoryName(prCtx); got != "github.com/acme/payments" {
		t.Errorf("repositoryName = %q", got)
	}
	t.Setenv("GITHUB_SERVER_URL", "https://ghe.example.com")
	if got := repositoryName(prCtx); got != "ghe.example.com/acme/payments" {
		t.Errorf("repositoryName = %q", got)
	}
}

// Degraded cloud mode reaches the comment through analyze's early returns
// too: what cloud said is true whether or not a review ran.
func TestAnalyzeCarriesCloudInfoOnEarlyReturn(t *testing.T) {
	cfg := config.Default()
	t.Setenv(replayEnv, "")
	t.Setenv(cfg.APIKeyEnv, "")
	kept := []diff.Change{{Path: "a.go"}}
	_, info, _ := analyze(context.Background(), cfg, analysisInput{
		filtered:   diff.Result{Kept: kept},
		comparison: &gh.CompareResult{Changes: kept},
		cloud:      engine.CloudOutcome{Degraded: "not connected — the API token was rejected"},
	})
	if info.Cloud == nil || info.Cloud.Degraded == "" {
		t.Errorf("Cloud info lost on the no-key return: %+v", info.Cloud)
	}
	body := render.Comment(&findings.Report{}, info)
	if !strings.Contains(body, "Threatcl Cloud: not connected — the API token was rejected") {
		t.Errorf("comment missing the degradation note:\n%s", body)
	}
}
