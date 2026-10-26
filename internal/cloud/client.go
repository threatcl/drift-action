package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Timeouts per call. The context call runs before the diff is fetched and
// never extends the inference timeout; the write-back runs after the review
// and a slow one must not hold the comment.
const (
	ContextTimeout      = 15 * time.Second
	ReportReviewTimeout = 10 * time.Second
)

// Paths under the API base. The token is opaque, so the client never knows the
// org UUID; "_" asks the server to substitute the token's organisation, which
// it does on these routes only.
const (
	contextPath = "/api/v1/org/_/drift/context"
	reviewsPath = "/api/v1/org/_/drift/reviews"
)

// Options configures a Client.
type Options struct {
	// BaseURL is the API host, e.g. https://beta-api.threatcl.com. It must be
	// https unless the host is loopback.
	BaseURL string
	// Token is the organisation-scoped tcl_ API token.
	Token string
	// Version is the action's version, sent as the User-Agent.
	Version string
	// Transport overrides the HTTP transport. Tests supply a fixture that
	// serves recorded responses and fails on any request it did not plan for.
	Transport http.RoundTripper
}

// Client talks to Threatcl Cloud on behalf of one run.
type Client struct {
	base      *url.URL
	token     string
	userAgent string
	http      *http.Client
}

// New builds a client. It refuses a base URL that would carry the token in
// clear — plain http to anything but a loopback host — and a client that
// follows redirects, since a redirect could re-send the token to a host the
// workflow never named.
func New(opts Options) (*Client, error) {
	if opts.Token == "" {
		return nil, errors.New("no API token")
	}
	base, err := parseBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	return &Client{
		base:      base,
		token:     opts.Token,
		userAgent: "threatcl-drift-action/" + version,
		http: &http.Client{
			Transport: opts.Transport,
			// Any redirect is refused, not only a cross-host one. An API
			// endpoint that redirects is misconfigured, and following even a
			// same-host redirect re-sends the Authorization header to a
			// location the response chose.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("refusing to follow a redirect to %s", req.URL.Redacted())
			},
		},
	}, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("API URL %q: %w", raw, err)
	}
	if u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("API URL %q must be an http(s) URL with a host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("API URL %q must carry no credentials, query or fragment", raw)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("API URL %q is plain http to a non-loopback host; the token would travel in clear", raw)
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// APIError is a non-2xx answer from the server. Code is the server's error
// code (upgrade_required, token_invalid, …); Message is its wording, for the
// run log only — the comment's wording is chosen from Status and Code by the
// caller, so nothing the server says reaches a pull request.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("threatcl cloud answered %d", e.Status)
	}
	return fmt.Sprintf("threatcl cloud answered %d %s: %s", e.Status, e.Code, e.Message)
}

// Unauthorized reports a 401: the token was rejected.
func (e *APIError) Unauthorized() bool { return e.Status == http.StatusUnauthorized }

// UpgradeRequired reports the tier gate: the token's organisation is below
// the plan cloud-connected mode needs.
func (e *APIError) UpgradeRequired() bool {
	return e.Status == http.StatusForbidden && e.Code == "upgrade_required"
}

// Forbidden reports a 403 other than the tier gate: a token scoped to another
// organisation, or a holder who is not a member.
func (e *APIError) Forbidden() bool {
	return e.Status == http.StatusForbidden && e.Code != "upgrade_required"
}

// NotFound reports a 404.
func (e *APIError) NotFound() bool { return e.Status == http.StatusNotFound }

// Context asks the server for the context on the pull request's threat model
// files. It persists nothing server-side.
func (c *Client) Context(ctx context.Context, req ContextRequest) (*ContextResponse, error) {
	req.Schema = SchemaV1
	if err := validateContextRequest(req); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, ContextTimeout)
	defer cancel()

	var resp ContextResponse
	if _, err := c.post(ctx, contextPath, req, &resp); err != nil {
		return nil, err
	}
	if resp.Schema != SchemaV1 {
		return nil, fmt.Errorf("threatcl cloud answered with schema %d, want %d", resp.Schema, SchemaV1)
	}
	return &resp, nil
}

// ReportReview records the counts-only review record. The server upserts on
// (repository, pr_number, head_sha): 201 for a new record, 200 for a replaced
// one, and either is success.
func (c *Client) ReportReview(ctx context.Context, rec ReviewRecord) error {
	rec.Schema = SchemaV1
	if err := rec.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, ReportReviewTimeout)
	defer cancel()
	_, err := c.post(ctx, reviewsPath, rec, nil)
	return err
}

// post sends one JSON body and decodes a JSON answer into out, if out is
// non-nil. It retries once on 429 and 5xx, and on a transport error — both
// calls are safe to repeat, one being a read and the other an upsert.
func (c *Client) post(ctx context.Context, path string, body, out any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("encoding the request: %w", err)
	}
	if len(payload) > MaxBodyBytes {
		return 0, fmt.Errorf("request body is %d bytes, over the %d-byte limit", len(payload), MaxBodyBytes)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, lastErr
			case <-time.After(500 * time.Millisecond):
			}
		}
		status, retry, err := c.once(ctx, path, payload, out)
		if err == nil {
			return status, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			return status, err
		}
	}
	return 0, lastErr
}

func (c *Client) once(ctx context.Context, path string, payload []byte, out any) (status int, retry bool, err error) {
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, true, fmt.Errorf("threatcl cloud request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return resp.StatusCode, true, fmt.Errorf("reading the threatcl cloud response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &envelope) == nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return resp.StatusCode, retry, apiErr
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, false, fmt.Errorf("decoding the threatcl cloud response: %w", err)
		}
	}
	return resp.StatusCode, false, nil
}

// validateContextRequest mirrors the server's limits so a request it would
// refuse is refused here, with the same wording, before the token is sent.
func validateContextRequest(req ContextRequest) error {
	if req.Repository == "" {
		return errors.New("context request: repository is required")
	}
	if len(req.Repository) > MaxNameLength {
		return fmt.Errorf("context request: repository exceeds %d characters", MaxNameLength)
	}
	if len(req.Models) > MaxModels {
		return fmt.Errorf("context request: %d models, over the limit of %d", len(req.Models), MaxModels)
	}
	for _, m := range req.Models {
		if m.Slug == "" {
			return errors.New("context request: a model has no slug")
		}
		if len(m.Slug) > MaxNameLength {
			return fmt.Errorf("context request: slug %q exceeds %d characters", m.Slug, MaxNameLength)
		}
		if len(m.Files) == 0 {
			return fmt.Errorf("context request: model %q has no files", m.Slug)
		}
		if len(m.Files) > MaxFilesPerModel {
			return fmt.Errorf("context request: model %q has %d files, over the limit of %d", m.Slug, len(m.Files), MaxFilesPerModel)
		}
		for _, f := range m.Files {
			if f.Name == "" || f.Head == nil {
				return fmt.Errorf("context request: model %q has a file with no name or no head", m.Slug)
			}
			if len(f.Name) > MaxNameLength {
				return fmt.Errorf("context request: file name %q exceeds %d characters", f.Name, MaxNameLength)
			}
			if len(*f.Head) > MaxFileBytes || (f.Base != nil && len(*f.Base) > MaxFileBytes) {
				return fmt.Errorf("context request: %s is over the %d-byte per-file limit", f.Name, MaxFileBytes)
			}
		}
	}
	return nil
}
