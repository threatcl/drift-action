package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/threatcl/drift-action/internal/cloud/cloudtest"
)

func ptr[T any](v T) *T { return &v }

func contextRequest() ContextRequest {
	return ContextRequest{
		Repository: "github.com/acme/payments",
		Models: []RequestModel{{
			Slug:  "payments",
			Files: []RequestFile{{Name: "payments.tm.hcl", Head: ptr("threatmodel \"p\" {}\n")}},
		}},
	}
}

func reviewRecord() ReviewRecord {
	return ReviewRecord{
		Repository: "github.com/acme/payments",
		PRNumber:   412,
		HeadSHA:    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
		Models:     []ReviewModel{{ID: ptr("0b9c6f1e-4d2a-4c3b-9e8f-1a2b3c4d5e6f"), Version: ptr("1.0.6"), Alignment: StateAhead}},
		Verdict:    "clean",
	}
}

func newClient(t *testing.T, base string, transport http.RoundTripper) *Client {
	t.Helper()
	c, err := New(Options{BaseURL: base, Token: "tcl_test", Version: "v9.9.9", Transport: transport})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestContextRoundTrip(t *testing.T) {
	var got *http.Request
	var body ContextRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mustRead(t, "testdata/context_response.v1.json"))
	}))
	defer server.Close()

	resp, err := newClient(t, server.URL, nil).Context(context.Background(), contextRequest())
	if err != nil {
		t.Fatalf("Context: %v", err)
	}

	if got.URL.Path != "/api/v1/org/_/drift/context" {
		t.Errorf("path = %q", got.URL.Path)
	}
	if got.Header.Get("Authorization") != "Bearer tcl_test" {
		t.Errorf("Authorization = %q", got.Header.Get("Authorization"))
	}
	if got.Header.Get("User-Agent") != "threatcl-drift-action/v9.9.9" {
		t.Errorf("User-Agent = %q", got.Header.Get("User-Agent"))
	}
	if body.Schema != SchemaV1 {
		t.Errorf("request schema = %d, the client must set it", body.Schema)
	}
	if resp.Org.Slug != "acme" || len(resp.Models) != 7 || len(resp.Library.Threats) != 2 {
		t.Errorf("response decoded wrongly: org=%+v models=%d threats=%d", resp.Org, len(resp.Models), len(resp.Library.Threats))
	}
}

// A base URL with a path prefix is honoured, and a trailing slash does not
// double up.
func TestContextHonoursBasePath(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write(mustRead(t, "testdata/context_response.v1.json"))
	}))
	defer server.Close()

	if _, err := newClient(t, server.URL+"/prefix/", nil).Context(context.Background(), contextRequest()); err != nil {
		t.Fatalf("Context: %v", err)
	}
	if path != "/prefix/api/v1/org/_/drift/context" {
		t.Errorf("path = %q", path)
	}
}

func TestReportReviewAcceptsCreatedAndUpdated(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusOK} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/org/_/drift/reviews" {
				t.Errorf("path = %q", r.URL.Path)
			}
			var rec ReviewRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Schema != SchemaV1 {
				t.Errorf("record: %+v %v", rec, err)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"id":"x"}`))
		}))
		if err := newClient(t, server.URL, nil).ReportReview(context.Background(), reviewRecord()); err != nil {
			t.Errorf("status %d: ReportReview = %v, want success", status, err)
		}
		server.Close()
	}
}

// Each failure the design names degrades with its own note, so each must be
// distinguishable from the error.
func TestTypedErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		check  func(*APIError) bool
	}{
		{"unauthorized", 401, "token_invalid", (*APIError).Unauthorized},
		{"upgrade required", 403, "upgrade_required", (*APIError).UpgradeRequired},
		{"other forbidden", 403, "token_scope_mismatch", (*APIError).Forbidden},
		{"not found", 404, "model_not_found", (*APIError).NotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write(cloudtest.ErrorBody(tt.status, tt.code, "server wording"))
			}))
			defer server.Close()

			_, err := newClient(t, server.URL, nil).Context(context.Background(), contextRequest())
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want an *APIError", err)
			}
			if !tt.check(apiErr) {
				t.Errorf("%+v did not satisfy %s", apiErr, tt.name)
			}
			if apiErr.Code != tt.code {
				t.Errorf("code = %q, want %q", apiErr.Code, tt.code)
			}
			// Distinct predicates must not overlap: upgrade_required is not
			// "forbidden" for the note's purposes.
			if tt.code == "upgrade_required" && apiErr.Forbidden() {
				t.Error("upgrade_required also reads as Forbidden")
			}
		})
	}
}

// One retry on 429 and 5xx, none on 4xx.
func TestRetries(t *testing.T) {
	for _, tt := range []struct {
		status    int
		wantCalls int32
	}{
		{http.StatusTooManyRequests, 2},
		{http.StatusInternalServerError, 2},
		{http.StatusBadGateway, 2},
		{http.StatusBadRequest, 1},
		{http.StatusUnauthorized, 1},
	} {
		var calls int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(tt.status)
		}))
		_, err := newClient(t, server.URL, nil).Context(context.Background(), contextRequest())
		if err == nil {
			t.Errorf("status %d: expected an error", tt.status)
		}
		if calls != tt.wantCalls {
			t.Errorf("status %d: %d call(s), want %d", tt.status, calls, tt.wantCalls)
		}
		server.Close()
	}
}

// The second attempt is allowed to succeed.
func TestRetrySucceeds(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(mustRead(t, "testdata/context_response.v1.json"))
	}))
	defer server.Close()
	if _, err := newClient(t, server.URL, nil).Context(context.Background(), contextRequest()); err != nil {
		t.Fatalf("Context after one 503: %v", err)
	}
}

// A redirect could re-send the token to a host the workflow never named, so
// none is followed — to another host or to this one.
func TestRedirectsAreRefused(t *testing.T) {
	var followed int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&followed, 1)
		_, _ = w.Write(mustRead(t, "testdata/context_response.v1.json"))
	}))
	defer target.Close()
	for _, location := range []string{target.URL + "/api/v1/org/_/drift/context", "/elsewhere"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, location, http.StatusTemporaryRedirect)
		}))
		_, err := newClient(t, server.URL, nil).Context(context.Background(), contextRequest())
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Errorf("redirect to %s: err = %v, want a refusal", location, err)
		}
		server.Close()
	}
	if followed != 0 {
		t.Errorf("the redirect target was reached %d time(s)", followed)
	}
}

func TestNewRefusesUnsafeURLs(t *testing.T) {
	for _, bad := range []string{"http://api.example.com", "ftp://x", "", "https://u:p@api.example.com"} {
		if _, err := New(Options{BaseURL: bad, Token: "tcl_x"}); err == nil {
			t.Errorf("New(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"https://beta-api.threatcl.com", "http://localhost:8080", "http://127.0.0.1:8080"} {
		if _, err := New(Options{BaseURL: ok, Token: "tcl_x"}); err != nil {
			t.Errorf("New(%q) = %v", ok, err)
		}
	}
	if _, err := New(Options{BaseURL: "https://beta-api.threatcl.com"}); err == nil {
		t.Error("New with no token accepted")
	}
}

func TestContextTimesOut(t *testing.T) {
	transport := &cloudtest.Transport{Hang: true}
	c := newClient(t, "https://cloud.test", transport)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Context(ctx, contextRequest())
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %s to time out", time.Since(start))
	}
}

// Server limits are mirrored so a request it would refuse never carries the
// token to it.
func TestContextRefusesOversizeLocally(t *testing.T) {
	transport := &cloudtest.Transport{Fail: t.Errorf, ContextBody: []byte(`{"schema":1}`)}
	c := newClient(t, "https://cloud.test", transport)

	huge := contextRequest()
	huge.Models[0].Files[0].Head = ptr(strings.Repeat("x", MaxFileBytes+1))
	if _, err := c.Context(context.Background(), huge); err == nil || !strings.Contains(err.Error(), "per-file limit") {
		t.Errorf("oversize head: err = %v", err)
	}

	many := contextRequest()
	for range MaxModels {
		many.Models = append(many.Models, many.Models[0])
	}
	if _, err := c.Context(context.Background(), many); err == nil || !strings.Contains(err.Error(), "over the limit") {
		t.Errorf("too many models: err = %v", err)
	}

	empty := contextRequest()
	empty.Models[0].Files = nil
	if _, err := c.Context(context.Background(), empty); err == nil {
		t.Error("a model with no files was sent")
	}
	if n := len(transport.Requests()); n != 0 {
		t.Errorf("%d request(s) reached the transport, want none", n)
	}
}

func TestReportReviewValidatesLocally(t *testing.T) {
	transport := &cloudtest.Transport{Fail: t.Errorf}
	c := newClient(t, "https://cloud.test", transport)

	bad := reviewRecord()
	bad.HeadSHA = "not-a-sha"
	if err := c.ReportReview(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "head_sha") {
		t.Errorf("err = %v, want head_sha named", err)
	}
	bad = reviewRecord()
	bad.Verdict = "error"
	if err := c.ReportReview(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "verdict") {
		t.Errorf("err = %v, want verdict named", err)
	}
	bad = reviewRecord()
	bad.PRNumber = 0
	if err := c.ReportReview(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "pr_number") {
		t.Errorf("err = %v, want pr_number named", err)
	}
	if n := len(transport.Requests()); n != 0 {
		t.Errorf("%d request(s) reached the transport, want none", n)
	}
}

// An answer in a schema this client does not speak is an error, not a
// best-effort decode.
func TestContextRejectsUnknownSchema(t *testing.T) {
	transport := &cloudtest.Transport{ContextBody: []byte(`{"schema":2,"org":{},"models":[],"library":{}}`)}
	if _, err := newClient(t, "https://cloud.test", transport).Context(context.Background(), contextRequest()); err == nil {
		t.Fatal("schema 2 was accepted")
	}
}
