package engine

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/cloud/cloudtest"
	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/deps"
	"github.com/threatcl/drift-action/internal/diff"
	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm/fixture"
	"github.com/threatcl/drift-action/internal/model"
	"github.com/threatcl/drift-action/prompts"
)

const cloudTestModel = `spec_version = "0.8.0"

backend "threatcl-cloud" {
  organization = "acme"
  threatmodel  = "payments"
}

threatmodel "payments" {
  description = "Payments service"
  author      = "@acme"

  threat "credential stuffing" {
    description = "Automated credential stuffing against POST /login"
    impacts     = ["Confidentiality"]
    stride      = ["Spoofing"]

    control "login rate limiting" {
      description = "Per-IP token-bucket rate limiting on POST /login, implemented in internal/auth/ratelimit.go"
      implemented = true
    }
  }
}
`

func cloudWorkspace(t *testing.T) (string, *model.Assertions) {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, contents string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("payments.tm.hcl", cloudTestModel)
	write("internal/auth/ratelimit.go", "package auth\n\nfunc Allow(ip string) bool { return true }\n")
	assertions, err := model.LoadIn(dir, "payments.tm.hcl")
	if err != nil {
		t.Fatal(err)
	}
	return dir, assertions
}

func cloudClient(t *testing.T, transport http.RoundTripper) *cloud.Client {
	t.Helper()
	c, err := cloud.New(Options(transport))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Options builds client options against the fixture transport.
func Options(transport http.RoundTripper) cloud.Options {
	return cloud.Options{BaseURL: "https://cloud.test", Token: "tcl_test", Version: "test", Transport: transport}
}

func contextBody(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "cloud", "testdata", "context_response.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseSameAsHead(dir string) BaseFetcher {
	return func(_ context.Context, path string) ([]byte, bool, error) {
		raw, err := os.ReadFile(filepath.Join(dir, path))
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return raw, err == nil, err
	}
}

func TestCloudContextConnected(t *testing.T) {
	dir, assertions := cloudWorkspace(t)
	transport := &cloudtest.Transport{ContextBody: contextBody(t), Fail: t.Errorf}

	out := CloudContext(context.Background(), config.Default(), CloudInput{
		Client:     cloudClient(t, transport),
		Workspace:  dir,
		Repository: "github.com/acme/payments",
		Assertions: assertions,
		Base:       baseSameAsHead(dir),
	})
	if !out.Connected || out.Degraded != "" {
		t.Fatalf("outcome = %+v, want connected", out)
	}
	if len(out.Link.Models) != 1 || out.Link.Models[0].Slug != "payments" || out.Link.Models[0].Org != "acme" {
		t.Errorf("link = %+v", out.Link)
	}
	for _, want := range []string{"Threats:\n", "T-001 | Account takeover", "Controls:\n", "C-002 | Content security policy"} {
		if !strings.Contains(out.Library, want) {
			t.Errorf("library section missing %q:\n%s", want, out.Library)
		}
	}
	if out.Index["C-001"] != "Multi-factor authentication" || len(out.Index) != 4 {
		t.Errorf("index = %v", out.Index)
	}

	reqs := transport.ContextRequests()
	if len(reqs) != 1 {
		t.Fatalf("%d context request(s), want 1", len(reqs))
	}
	body := string(reqs[0])
	for _, want := range []string{
		`"repository":"github.com/acme/payments"`,
		`"slug":"payments"`, `"backend_org":"acme"`,
		`"name":"payments.tm.hcl"`, `"base":"spec_version`, `"head":"spec_version`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("context request missing %s:\n%s", want, body)
		}
	}
}

// A file the pull request adds has no base, and the request omits it rather
// than sending an empty string the server would hash.
func TestCloudContextOmitsMissingBase(t *testing.T) {
	dir, assertions := cloudWorkspace(t)
	transport := &cloudtest.Transport{ContextBody: contextBody(t), Fail: t.Errorf}
	none := func(context.Context, string) ([]byte, bool, error) { return nil, false, nil }

	out := CloudContext(context.Background(), config.Default(), CloudInput{
		Client: cloudClient(t, transport), Workspace: dir, Repository: "github.com/acme/payments",
		Assertions: assertions, Base: none,
	})
	if !out.Connected {
		t.Fatalf("outcome = %+v", out)
	}
	if body := string(transport.ContextRequests()[0]); strings.Contains(body, `"base"`) {
		t.Errorf("request carries a base for a file with none:\n%s", body)
	}
}

// Every failure degrades to local with a note worded by cause, and the note
// never quotes the server.
func TestCloudContextDegrades(t *testing.T) {
	dir, assertions := cloudWorkspace(t)
	tests := []struct {
		name      string
		transport *cloudtest.Transport
		want      string
	}{
		{"401", &cloudtest.Transport{ContextStatus: 401, ContextBody: cloudtest.ErrorBody(401, "token_invalid", "SERVER WORDING")}, "the API token was rejected"},
		{"403 upgrade", &cloudtest.Transport{ContextStatus: 403, ContextBody: cloudtest.ErrorBody(403, "upgrade_required", "SERVER WORDING")}, "needs the Team plan"},
		{"403 scope", &cloudtest.Transport{ContextStatus: 403, ContextBody: cloudtest.ErrorBody(403, "token_scope_mismatch", "SERVER WORDING")}, "organisation refused"},
		{"500", &cloudtest.Transport{ContextStatus: 500, ContextBody: cloudtest.ErrorBody(500, "internal_error", "SERVER WORDING")}, "could not be reached"},
		{"400", &cloudtest.Transport{ContextStatus: 400, ContextBody: cloudtest.ErrorBody(400, "limit_exceeded", "SERVER WORDING")}, "refused the request"},
		{"timeout", &cloudtest.Transport{Hang: true}, "could not be reached"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.transport.Hang {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100e6)
				defer cancel()
			}
			out := CloudContext(ctx, config.Default(), CloudInput{
				Client: cloudClient(t, tt.transport), Workspace: dir, Repository: "github.com/acme/payments",
				Assertions: assertions, Base: baseSameAsHead(dir),
			})
			if out.Connected || out.Library != "" || out.Response != nil {
				t.Errorf("outcome should be degraded: %+v", out)
			}
			if !strings.Contains(out.Degraded, tt.want) {
				t.Errorf("Degraded = %q, want it to say %q", out.Degraded, tt.want)
			}
			if strings.Contains(out.Degraded, "SERVER WORDING") {
				t.Errorf("the server's message reached the note: %q", out.Degraded)
			}
		})
	}
}

// No token: a repo that configured cloud mode is told; one that never did
// hears nothing, and no request is made either way.
func TestCloudContextWithoutToken(t *testing.T) {
	dir, assertions := cloudWorkspace(t)
	in := CloudInput{Workspace: dir, Repository: "r", Assertions: assertions}

	plain := CloudContext(context.Background(), config.Default(), in)
	if plain.Connected || plain.Degraded != "" {
		t.Errorf("no token, no cloud block: %+v, want silence", plain)
	}

	cfg := config.Default()
	cfg.Cloud.Declared = true
	declared := CloudContext(context.Background(), cfg, in)
	if declared.Connected || !strings.Contains(declared.Degraded, "no API token in this run") {
		t.Errorf("no token with a cloud block: %+v, want the not-connected note", declared)
	}
}

// A base the fetcher cannot read degrades rather than being sent as absent:
// an absent base reads as "never synced", which would be a false answer.
func TestCloudContextDegradesWhenBaseUnreadable(t *testing.T) {
	dir, assertions := cloudWorkspace(t)
	transport := &cloudtest.Transport{ContextBody: contextBody(t), Fail: t.Errorf}
	failing := func(context.Context, string) ([]byte, bool, error) { return nil, false, errors.New("rate limited") }

	out := CloudContext(context.Background(), config.Default(), CloudInput{
		Client: cloudClient(t, transport), Workspace: dir, Repository: "r", Assertions: assertions, Base: failing,
	})
	if out.Connected || !strings.Contains(out.Degraded, "base-commit") {
		t.Errorf("outcome = %+v", out)
	}
	if len(transport.Requests()) != 0 {
		t.Error("a request was sent without the base")
	}
}

// A contradiction between cloud.model and the backend block is a config
// error, with or without a token.
func TestCloudLinkContradiction(t *testing.T) {
	_, assertions := cloudWorkspace(t)
	cfg := config.Default()
	cfg.Cloud.Model = "ledger"
	_, err := CloudLink(cfg, assertions)
	if err == nil || !strings.Contains(err.Error(), ".threatcl-ci.hcl") || !strings.Contains(err.Error(), `"ledger"`) {
		t.Fatalf("CloudLink = %v, want a config error naming the file and the slug", err)
	}
	cfg.Cloud.Model = "payments"
	if _, err := CloudLink(cfg, assertions); err != nil {
		t.Errorf("an agreeing override should pass: %v", err)
	}
}

// With no linked model the request still goes, for the library, with an
// empty (not null) models array.
func TestCloudContextLibraryOnly(t *testing.T) {
	dir, assertions := testWorkspace(t) // no backend block
	transport := &cloudtest.Transport{ContextBody: contextBody(t), Fail: t.Errorf}
	out := CloudContext(context.Background(), config.Default(), CloudInput{
		Client: cloudClient(t, transport), Workspace: dir, Repository: "r", Assertions: assertions,
	})
	if !out.Connected || len(out.Link.Unlinked) != 1 {
		t.Fatalf("outcome = %+v", out)
	}
	if body := string(transport.ContextRequests()[0]); !strings.Contains(body, `"models":[]`) {
		t.Errorf("request should carry an empty models array:\n%s", body)
	}
}

// An empty library yields no section, so the request stays a local one.
func TestRenderLibraryEmpty(t *testing.T) {
	section, index := renderLibrary(cloud.ContextLibrary{})
	if section != "" || len(index) != 0 {
		t.Errorf("empty library rendered %q / %v", section, index)
	}
	section, _ = renderLibrary(cloud.ContextLibrary{Threats: []cloud.LibraryEntry{{ReferenceID: "T-1", Name: "multi\nline\nname"}}})
	if strings.Count(section, "\n") != 2 || !strings.Contains(section, "T-1 | multi line name") {
		t.Errorf("a newline in a name must not survive onto its own line:\n%q", section)
	}
}

// Canary: a marker planted in the diff and in a context file must reach no
// request to cloud, through the whole engine path — link, context call,
// request assembly against the same workspace, write-back.
func TestCloudNeverSeesCode(t *testing.T) {
	const marker = "CANARY-7f3a9c-DO-NOT-SEND"
	dir, assertions := cloudWorkspace(t)
	if err := os.WriteFile(filepath.Join(dir, "internal/auth/ratelimit.go"),
		[]byte("package auth\n\n// "+marker+"\nfunc Allow(ip string) bool { return false }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	transport := &cloudtest.Transport{ContextBody: contextBody(t), Fail: t.Errorf}
	client := cloudClient(t, transport)
	cfg := config.Default()

	out := CloudContext(context.Background(), cfg, CloudInput{
		Client: client, Workspace: dir, Repository: "github.com/acme/payments",
		Assertions: assertions, Base: baseSameAsHead(dir),
	})
	if !out.Connected {
		t.Fatalf("outcome = %+v", out)
	}

	changes := []diff.Change{{
		Path: "internal/auth/ratelimit.go", Status: "modified",
		Patch: "@@ -1,3 +1,4 @@\n package auth\n \n+// " + marker + "\n-func Allow(ip string) bool { return true }\n+func Allow(ip string) bool { return false }\n",
	}}
	assembly := AssembleRequest(cfg, RequestInput{
		Workspace: dir, Assertions: assertions, Kept: changes,
		ManifestFacts: deps.Facts(changes), Library: out.Library,
	})
	// The marker did reach the LLM request, in both places — otherwise the
	// canary proves nothing.
	if !strings.Contains(assembly.Request.Diff, marker) || len(assembly.Request.ContextFiles) != 1 ||
		!strings.Contains(assembly.Request.ContextFiles[0].Contents, marker) {
		t.Fatal("the canary never reached the LLM request; the test is not exercising the path")
	}

	// And a write-back, with everything a review produces in hand.
	rec := cloud.ReviewRecord{
		Repository: "github.com/acme/payments", PRNumber: 1, HeadSHA: "abcdef1",
		Verdict: "findings", Models: []cloud.ReviewModel{{Alignment: cloud.StateNotInCloud}},
	}
	if err := client.ReportReview(context.Background(), rec); err != nil {
		t.Fatal(err)
	}

	for _, r := range transport.Requests() {
		if strings.Contains(string(r.Body), marker) {
			t.Errorf("the canary reached cloud in %s %s:\n%s", r.Method, r.Path, r.Body)
		}
	}
}

// A degraded run must be byte-identical to a local one: same sections digest,
// same prompt, same schema.
func TestDegradedRequestMatchesLocal(t *testing.T) {
	dir, assertions := cloudWorkspace(t)
	cfg := config.Default()
	changes := []diff.Change{{Path: "internal/auth/ratelimit.go", Status: "modified", Patch: "@@ -1 +1 @@\n-a\n+b\n"}}
	build := func(library string) Assembly {
		return AssembleRequest(cfg, RequestInput{Workspace: dir, Assertions: assertions, Kept: changes, Library: library})
	}
	local := build("")

	for _, transport := range []*cloudtest.Transport{
		{ContextStatus: 401, ContextBody: cloudtest.ErrorBody(401, "token_invalid", "")},
		{ContextStatus: 403, ContextBody: cloudtest.ErrorBody(403, "upgrade_required", "")},
		{Hang: true},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 100e6)
		out := CloudContext(ctx, cfg, CloudInput{Client: cloudClient(t, transport), Workspace: dir, Repository: "r", Assertions: assertions, Base: baseSameAsHead(dir)})
		cancel()
		degraded := build(out.Library)
		if fixture.Digest(degraded.Request) != fixture.Digest(local.Request) {
			t.Errorf("degraded request digest differs from local")
		}
		if degraded.Request.Prompt != prompts.DriftCI || string(degraded.Request.Schema) != string(findings.SchemaJSON) {
			t.Errorf("degraded request did not use the local prompt and schema")
		}
	}

	connected := build("Threats:\nT-001 | x\n")
	if fixture.Digest(connected.Request) == fixture.Digest(local.Request) {
		t.Error("a connected request should differ from local")
	}
	if !strings.HasSuffix(connected.Request.Prompt, prompts.DriftCICloud) || string(connected.Request.Schema) != string(findings.CloudSchemaJSON) {
		t.Error("a connected request should carry the addendum and the cloud schema")
	}
}
