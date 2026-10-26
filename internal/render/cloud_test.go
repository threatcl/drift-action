package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/findings"
)

// goldenModels loads the contract golden's models by slug, so the renderer is
// exercised against every alignment state and note the server can send.
func goldenModels(t *testing.T) map[string]cloud.ContextModel {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "cloud", "testdata", "context_response.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var resp cloud.ContextResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	by := map[string]cloud.ContextModel{}
	for _, m := range resp.Models {
		by[m.Slug] = m
	}
	return by
}

func cloudInfo(models ...CloudModel) *CloudInfo {
	return &CloudInfo{
		Org:    "acme",
		Models: models,
		Library: LibraryInfo{Threats: 2, Controls: 2, Names: map[string]string{
			"T-001": "Account takeover", "C-001": "Multi-factor authentication",
		}},
	}
}

func one(by map[string]cloud.ContextModel, slug string, files ...string) CloudModel {
	return CloudModel{Files: files, Context: by[slug]}
}

// A local-mode comment must not change by a byte when Cloud is nil.
func TestCloudNilRendersNothing(t *testing.T) {
	report := &findings.Report{NoDrift: true}
	info := ContextInfo{ModelPaths: []string{"a.tm.hcl"}, AnalysisMode: "m"}
	out := Comment(report, info)
	for _, forbidden := range []string{"☁️", "📚", "⚖️", "Threatcl Cloud", "Model sync", "Policy"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("local comment mentions %q:\n%s", forbidden, out)
		}
	}
}

// Degraded: exactly one ℹ️ line, and nothing else cloud-shaped.
func TestCloudDegradedIsOneNote(t *testing.T) {
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{
		Cloud: &CloudInfo{Degraded: "not connected — the API token was rejected"},
	})
	if !strings.Contains(out, "- ℹ️ Threatcl Cloud: not connected — the API token was rejected\n") {
		t.Errorf("missing the degradation note:\n%s", out)
	}
	for _, forbidden := range []string{"☁️", "📚", "⚖️", "Model sync", "Policy violations"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("degraded comment renders %q:\n%s", forbidden, out)
		}
	}
	if strings.Count(out, "Threatcl Cloud") != 1 {
		t.Errorf("Threatcl Cloud mentioned more than once:\n%s", out)
	}
}

// Degraded while policy-gated is a warning above the fold.
func TestCloudDegradedWithPolicyGateWarns(t *testing.T) {
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{
		Cloud: &CloudInfo{Degraded: "not connected — Threatcl Cloud could not be reached", PolicyFailMode: config.PolicyFailOnEnforcedViolation},
	})
	fold := strings.Index(out, "<details>")
	at := strings.Index(out, "⚠️ Policy gate:")
	if at < 0 || at > fold {
		t.Errorf("policy-gate warning missing or below the fold:\n%s", out)
	}
}

func TestCloudAlignmentPhrases(t *testing.T) {
	by := goldenModels(t)
	tests := []struct {
		slug string
		want string
	}{
		{"payments", "☁️ Threatcl Cloud: acme — `payments` v1.0.6 (payments.tm.hcl): repo copy matches cloud v1.0.6"},
		{"checkout", "this PR changes the model; it becomes the next cloud version after v2.1.0"},
		{"ledger", "repo copy is 2 versions behind cloud v1.0.6 (last synced at v1.0.4) — see Model sync below"},
		{"refunds", "repo copy and cloud have both changed since v1.1.0 (cloud is now v1.2.0) — see Model sync below"},
		{"reporting", "no committed copy matches a cloud version (cloud is at v1.0.0)"},
		{"ledger-v2", "☁️ Threatcl Cloud: acme — `ledger-v2` (ledger-v2.tm.hcl): no model with this slug in the organisation"},
	}
	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: cloudInfo(one(by, tt.slug, tt.slug+".tm.hcl"))})
			if !strings.Contains(out, tt.want) {
				t.Errorf("missing %q:\n%s", tt.want, out)
			}
		})
	}
}

// Conflict with an empty, non-null delta is the PR syncing the repo copy:
// no warning and no Model sync block.
func TestCloudConflictWithEmptyDeltaIsSyncing(t *testing.T) {
	by := goldenModels(t)
	m := by["refunds"]
	m.Alignment.Delta = cloud.Delta{}
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: cloudInfo(CloudModel{Files: []string{"r.tm.hcl"}, Context: m})})
	if !strings.Contains(out, "repo copy was 3 versions behind; this PR brings it up to cloud v1.2.0") {
		t.Errorf("syncing phrase missing:\n%s", out)
	}
	if strings.Contains(out, "⚠️ Model sync") || strings.Contains(out, "<summary>Model sync") {
		t.Errorf("a syncing PR must not render as a conflict:\n%s", out)
	}
}

// Behind and conflict get a Model sync block with the delta in our words and
// a copy-paste prompt; conflict also warns above the fold.
func TestCloudModelSyncBlock(t *testing.T) {
	by := goldenModels(t)
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: cloudInfo(
		one(by, "ledger", "threatmodels/ledger.tm.hcl", "threatmodels/ledger-auth.tm.hcl"),
		one(by, "refunds", "refunds.tm.hcl"),
	)})

	for _, want := range []string{
		"<summary>Model sync — `threatmodels/ledger.tm.hcl`, `threatmodels/ledger-auth.tm.hcl` is 2 versions behind Threatcl Cloud `ledger` v1.0.6</summary>",
		`Cloud has, and this copy lacks: control "brute force login::lockout".`,
		`Modified in cloud: threat "brute force login".`,
		"Segments: `default` aligned at v1.0.6; `auth` behind at v1.0.4.",
		"<summary>Model sync — `refunds.tm.hcl` and Threatcl Cloud `refunds` have both changed since v1.1.0</summary>",
		`This copy has, and cloud lacks: control "refund approval::four eyes"; information asset "refund ledger".`,
		`Cloud has, and this copy lacks: control "refund approval::manual review".`,
		"Bring refunds.tm.hcl up to Threatcl Cloud model \"refunds\" version 1.2.0",
		"threatcl cloud export",
		"re-run /threat-drift",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}

	fold := strings.Index(out, "<details>")
	warning := "⚠️ Model sync: `refunds.tm.hcl` and Threatcl Cloud `refunds` have both changed since v1.1.0"
	if at := strings.Index(out, warning); at < 0 || at > fold {
		t.Errorf("conflict warning missing or below the fold:\n%s", out)
	}
	if strings.Contains(out, "⚠️ Model sync: `threatmodels/ledger") {
		t.Errorf("behind must not warn above the fold, only conflict does:\n%s", out)
	}
	// Model sync renders after the context block and before any findings.
	if sync, ctx := strings.Index(out, "<summary>Model sync"), strings.Index(out, "</details>"); sync < ctx {
		t.Errorf("Model sync renders before the context block closes:\n%s", out)
	}
}

// A head that did not parse on the server still gets its conflict named,
// without a delta it cannot have.
func TestCloudHeadParseErrorConflict(t *testing.T) {
	by := goldenModels(t)
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: cloudInfo(one(by, "settlement", "s.tm.hcl"))})
	for _, want := range []string{
		"⚠️ Model sync: `s.tm.hcl` and Threatcl Cloud `settlement` have both changed since v2.4.1",
		"What differs could not be listed: the pull request's copy did not parse on the server.",
		"did not parse on the server, so no delta or policy verdict is available",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestCloudNotes(t *testing.T) {
	by := goldenModels(t)
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: &CloudInfo{
		Org:      "acme",
		Models:   []CloudModel{one(by, "checkout", "c.tm.hcl"), one(by, "ledger", "l.tm.hcl"), one(by, "refunds", "r.tm.hcl"), one(by, "reporting", "rep.tm.hcl")},
		Unlinked: []string{"stray.tm.hcl"},
		Library:  LibraryInfo{Truncated: true, Threats: 500, Controls: 12},
	}})
	for _, want := range []string{
		"names a different organisation from the API token's",
		"declares repositories, and this repository is not among them",
		"`threatmodels/stray.tm.hcl` could not be placed in `checkout`",
		"the organisation has no enabled policies, so `ledger` was not policy-checked",
		"`refunds` has segments on cloud this repository did not submit",
		"policies could not be evaluated against `reporting`",
		"`stray.tm.hcl` declare no backend address and `cloud.model` is unset",
		"📚 Org library: 500 threats, 12 controls sent (truncated by the server; not every entry was sent)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}

	// An unknown note renders generically rather than being dropped.
	m := by["payments"]
	m.Notes = []string{"something_new"}
	out = Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: cloudInfo(CloudModel{Files: []string{"p.tm.hcl"}, Context: m})})
	if !strings.Contains(out, "Threatcl Cloud: `payments` — something_new") {
		t.Errorf("unknown note dropped:\n%s", out)
	}
}

func TestCloudEmptyLibraryAndNoModels(t *testing.T) {
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: &CloudInfo{Org: "acme"}})
	for _, want := range []string{
		"☁️ Threatcl Cloud: acme — no model linked; library and review record only",
		"📚 Org library: no referenceable entries, so none were sent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "⚖️") {
		t.Errorf("no policy row without a verdict:\n%s", out)
	}
}

// Policy results render straight from the server, escaped and capped, and the
// counts row gains its cell only when something was evaluated.
func TestCloudPolicyRendering(t *testing.T) {
	by := goldenModels(t)
	checkout := by["checkout"]
	checkout.Policy.Results[0].Message = "1 threat(s) have no controls defined. `*injected*` <b>" + strings.Repeat("x", 400)
	checkout.Policy.Results[0].PolicyName = "Controls *required*"
	out := Comment(&findings.Report{NoDrift: true}, ContextInfo{Cloud: cloudInfo(
		CloudModel{Files: []string{"c.tm.hcl"}, Context: checkout},
		one(by, "refunds", "r.tm.hcl"),
		one(by, "payments", "p.tm.hcl"),
	)})

	for _, want := range []string{
		"⚖️ Policy violations (2)\n",
		"⚖️ Policies: 4 evaluated, 2 enforced, 2 violated",
		"### Policy violations",
		"- ❌ **Controls \\*required\\*** on `checkout` (error, enforced) — `1 threat(s) have no controls defined. '*injected*' <b>",
		"- ⚠️ **STRIDE coverage** on `refunds` (warning) — `No threats cover Repudiation.`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, strings.Repeat("x", 300)) {
		t.Errorf("policy message was not capped:\n%s", out)
	}
	if strings.Contains(out, "Description present") {
		t.Errorf("a passed policy rendered as a violation:\n%s", out)
	}
	// Not gated: no above-the-fold policy warning.
	if strings.Contains(out, "⚠️ Policy:") {
		t.Errorf("ungated run warned about blocking violations:\n%s", out)
	}

	// Gated: the blocking count warns above the fold, and so does a model
	// with no verdict.
	info := ContextInfo{Cloud: cloudInfo(CloudModel{Files: []string{"c.tm.hcl"}, Context: checkout}, one(by, "reporting", "rep.tm.hcl"))}
	info.Cloud.PolicyFailMode = config.PolicyFailOnEnforcedViolation
	out = Comment(&findings.Report{NoDrift: true}, info)
	fold := strings.Index(out, "<details>")
	for _, want := range []string{
		"⚠️ Policy: 1 enforced policy violation(s) fail this check",
		"⚠️ Policy gate: `policy_fail_mode` is `on-enforced-violation`, but policies could not be evaluated for `reporting`",
	} {
		if at := strings.Index(out, want); at < 0 || at > fold {
			t.Errorf("%q missing or below the fold:\n%s", want, out)
		}
	}
}

// Library matches print the ref and name from our index; a ref outside it is
// never printed, whatever the model said.
func TestCloudLibraryMatch(t *testing.T) {
	report := &findings.Report{Summary: "1 finding.", Findings: []findings.Finding{{
		Category: findings.CategoryUnmodeledSurface, Severity: findings.SeverityReviewRecommended,
		Title:       "New login endpoint",
		Evidence:    []findings.Evidence{{File: "server.go", Line: 1, Note: "n"}},
		LibraryRefs: []string{"T-001", "T-HALLUCINATED"},
	}}}
	out := Comment(report, ContextInfo{Cloud: cloudInfo()})
	if !strings.Contains(out, "**Library match:** `T-001` — Account takeover\n") {
		t.Errorf("library match missing:\n%s", out)
	}
	if strings.Contains(out, "HALLUCINATED") {
		t.Errorf("an unknown ref was printed:\n%s", out)
	}
	// Local mode never prints one, even if a ref somehow survived.
	if out := Comment(report, ContextInfo{}); strings.Contains(out, "Library match") {
		t.Errorf("local comment printed a library match:\n%s", out)
	}
}

func TestGate(t *testing.T) {
	by := goldenModels(t)
	var none *CloudInfo
	if g := none.Gate(); g.Mode != config.PolicyFailNever || g.Unavailable || g.Blocking != 0 {
		t.Errorf("nil gate = %+v", g)
	}
	info := cloudInfo(one(by, "checkout"), one(by, "refunds"), one(by, "reporting"))
	info.PolicyFailMode = config.PolicyFailOnEnforcedViolation
	if g := info.Gate(); g.Blocking != 1 || !g.Unavailable {
		t.Errorf("gate = %+v, want 1 blocking and unavailable (reporting has no verdict)", g)
	}
	degraded := &CloudInfo{Degraded: "x", PolicyFailMode: config.PolicyFailOnEnforcedViolation}
	if g := degraded.Gate(); !g.Unavailable {
		t.Errorf("degraded gate = %+v, want unavailable", g)
	}
}

func TestCheckConclusionPolicyGate(t *testing.T) {
	clean := &findings.Report{NoDrift: true}
	gated := config.PolicyFailOnEnforcedViolation

	// Blocking violation: fails when gated, never success otherwise.
	if c, title := CheckConclusion(clean, config.FailNever, PolicyGate{Mode: gated, Blocking: 1}); c != "failure" || !strings.Contains(title, "1 blocking policy violation(s)") {
		t.Errorf("gated blocking = %q %q", c, title)
	}
	if c, _ := CheckConclusion(clean, config.FailNever, PolicyGate{Mode: config.PolicyFailNever, Blocking: 1}); c != "neutral" {
		t.Errorf("ungated blocking = %q, want neutral (never success)", c)
	}

	// Gate configured but not applicable: neutral, not green.
	if c, title := CheckConclusion(clean, config.FailNever, PolicyGate{Mode: gated, Unavailable: true}); c != "neutral" || !strings.Contains(title, "policies could not be evaluated") {
		t.Errorf("gated unavailable = %q %q", c, title)
	}
	// Not gated and unavailable: a clean review is still success.
	if c, _ := CheckConclusion(clean, config.FailNever, PolicyGate{Mode: config.PolicyFailNever, Unavailable: true}); c != "success" {
		t.Errorf("ungated unavailable = %q, want success", c)
	}

	// Both gates trip: the title names both.
	drift := &findings.Report{Findings: []findings.Finding{{Severity: findings.SeverityActionRequired}}}
	c, title := CheckConclusion(drift, config.FailOnActionRequired, PolicyGate{Mode: gated, Blocking: 2})
	if c != "failure" || title != "1 drift finding(s), 1 action required; 2 blocking policy violation(s)" {
		t.Errorf("both gates = %q %q", c, title)
	}
	// Drift gate only.
	if c, _ := CheckConclusion(drift, config.FailOnActionRequired, PolicyGate{Mode: gated}); c != "failure" {
		t.Errorf("drift gate alone = %q", c)
	}
	if c, _ := CheckConclusion(drift, config.FailNever, PolicyGate{Mode: gated}); c != "neutral" {
		t.Errorf("no gate = %q", c)
	}
}
