package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/engine"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/gh"
	"github.com/threatcl/drift-action/internal/render"
)

// newCloudClient builds the Threatcl Cloud client when the run holds a token,
// and nothing otherwise: the token, and nothing else, is what turns
// cloud-connected mode on. A token with an unusable API URL is a hard error
// — config.Load has already validated the URL, so this fires only for a
// client the package itself refuses.
func newCloudClient(cfg config.Config) (*cloud.Client, error) {
	token := os.Getenv(config.CloudTokenEnv)
	if token == "" {
		return nil, nil
	}
	client, err := cloud.New(cloud.Options{BaseURL: cfg.CloudURL, Token: token, Version: version})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", config.CloudURLEnv, err)
	}
	log.Printf("threatcl cloud: connecting to %s", cfg.CloudURL)
	return client, nil
}

// repositoryName is the repository as the cloud ledger keys it:
// host/owner/repo, with the host from GITHUB_SERVER_URL so an Enterprise
// Server instance is not recorded as github.com.
func repositoryName(prCtx *gh.Context) string {
	host := "github.com"
	if raw := os.Getenv("GITHUB_SERVER_URL"); raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	return fmt.Sprintf("%s/%s/%s", host, prCtx.Owner, prCtx.Repo)
}

// baseFetcher reads a model file at the pull request's base commit through
// the GitHub contents API. The checkout holds the head only.
func baseFetcher(client *gh.Client, baseSHA string) engine.BaseFetcher {
	return func(ctx context.Context, path string) ([]byte, bool, error) {
		return client.FileAt(ctx, baseSHA, path)
	}
}

// cloudInfo turns the engine's outcome into what the renderer needs. Nil when
// cloud mode was neither attempted nor configured, so a local comment is
// unchanged by a byte.
func cloudInfo(cfg config.Config, outcome engine.CloudOutcome) *render.CloudInfo {
	if !outcome.Connected && outcome.Degraded == "" {
		return nil
	}
	info := &render.CloudInfo{
		Degraded:       outcome.Degraded,
		PolicyFailMode: cfg.Cloud.PolicyFailMode,
	}
	if !outcome.Connected {
		return info
	}
	resp := outcome.Response
	info.Org = resp.Org.Slug
	info.Unlinked = outcome.Link.Unlinked
	info.Library = render.LibraryInfo{
		Threats:   len(resp.Library.Threats),
		Controls:  len(resp.Library.Controls),
		Truncated: resp.Library.Truncated,
		Names:     outcome.Index,
	}
	// Answers come back in submission order, but match by slug so a server
	// that reorders cannot pair one model's files with another's verdict.
	bySlug := map[string]cloud.ContextModel{}
	for _, m := range resp.Models {
		bySlug[m.Slug] = m
	}
	for _, linked := range outcome.Link.Models {
		ctx, ok := bySlug[linked.Slug]
		if !ok {
			log.Printf("threatcl cloud: no answer for model %q", linked.Slug)
			continue
		}
		info.Models = append(info.Models, render.CloudModel{Files: linked.Files, Context: ctx})
	}
	return info
}

// versionPattern mirrors the ledger's action_version tag; a build stamp that
// does not fit is left out rather than failing the write-back.
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,32}$`)

// reviewRecord builds the counts-only write-back. Nothing here is free text:
// the type's tags bound every string, and no finding title, excerpt, path or
// summary has a field to land in.
func reviewRecord(cfg config.Config, prCtx *gh.Context, outcome engine.CloudOutcome,
	report *findings.Report, info render.ContextInfo, llmModel string) cloud.ReviewRecord {

	rec := cloud.ReviewRecord{
		Repository:    repositoryName(prCtx),
		PRNumber:      prCtx.Number,
		HeadSHA:       prCtx.HeadSHA,
		Models:        []cloud.ReviewModel{},
		FilesChanged:  info.FilesChanged,
		FilesReviewed: info.FilesReviewed,
	}
	if prCtx.BaseSHA != "" {
		base := prCtx.BaseSHA
		rec.BaseSHA = &base
	}

	for _, m := range outcome.Response.Models {
		rec.Models = append(rec.Models, cloud.ReviewModel{
			ID:             m.ID,
			Version:        m.Version,
			Alignment:      m.Alignment.State,
			VersionsBehind: m.Alignment.VersionsBehind,
		})
	}

	actionRequired := countSeverity(report, findings.SeverityActionRequired)
	rec.Verdict = verdict(report, actionRequired)
	rec.ActionRequiredCount = actionRequired
	for _, f := range report.Findings {
		switch f.Category {
		case findings.CategoryStaleAssertion:
			rec.Counts.StaleAssertion++
		case findings.CategoryPhantomControl:
			rec.Counts.PhantomControl++
		case findings.CategoryUnmodeledSurface:
			rec.Counts.UnmodeledSurface++
		case findings.CategoryDFDDrift:
			rec.Counts.DfdDrift++
		case findings.CategoryDependencyDrift:
			rec.Counts.DependencyDrift++
		case findings.CategoryUnclassifiedData:
			rec.Counts.UnclassifiedData++
		}
	}

	if info.Cloud != nil {
		if evaluated, totals := policyTotals(info.Cloud); evaluated {
			rec.Policy = &cloud.ReviewPolicy{Evaluated: totals.Evaluated, Violated: totals.Violated, Blocking: totals.Blocking}
		}
	}

	provider := cfg.Provider
	rec.Provider = &provider
	if llmModel != "" {
		rec.LLMModel = &llmModel
	}
	if versionPattern.MatchString(version) {
		v := version
		rec.ActionVersion = &v
	}
	return rec
}

// policyTotals sums the per-model verdicts; evaluated is false when no model
// returned one.
func policyTotals(c *render.CloudInfo) (evaluated bool, totals cloud.PolicyContext) {
	for _, m := range c.Models {
		if p := m.Context.Policy; p != nil {
			evaluated = true
			totals.Evaluated += p.Evaluated
			totals.Enforced += p.Enforced
			totals.Violated += p.Violated
			totals.Blocking += p.Blocking
		}
	}
	return evaluated, totals
}
