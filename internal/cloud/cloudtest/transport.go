// Package cloudtest is the fixture transport for cloud-connected mode: it
// serves exactly the responses a test planned and fails the test on any other
// request, so an unplanned call to Threatcl Cloud is a test failure rather
// than a network call. Unit tests, the corpus and the canary test all run
// against it; nothing in the test suite reaches a real cloud host.
package cloudtest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Request is one call the transport saw.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// Transport answers the two drift routes from canned responses.
type Transport struct {
	// ContextStatus and ContextBody answer POST …/drift/context. A zero
	// status with a body means 200; a zero status and no body means the test
	// planned no context call, and making one fails it.
	ContextStatus int
	ContextBody   []byte
	// ReviewStatus answers POST …/drift/reviews; zero means 201.
	ReviewStatus int
	// ReviewBody is the review answer; empty means a minimal JSON object.
	ReviewBody []byte
	// Hang makes every request block until its context is cancelled, to
	// exercise the client's timeout.
	Hang bool
	// Fail reports an unplanned request. Tests set it to t.Errorf; when nil
	// the request errors and nothing else happens.
	Fail func(format string, args ...any)

	mu       sync.Mutex
	requests []Request
}

// Requests returns every request made so far.
func (t *Transport) Requests() []Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Request(nil), t.requests...)
}

// ContextRequests returns the bodies of the context calls made so far.
func (t *Transport) ContextRequests() [][]byte {
	var out [][]byte
	for _, r := range t.Requests() {
		if strings.HasSuffix(r.Path, "/drift/context") {
			out = append(out, r.Body)
		}
	}
	return out
}

// ReviewRequests returns the bodies of the write-backs made so far.
func (t *Transport) ReviewRequests() [][]byte {
	var out [][]byte
	for _, r := range t.Requests() {
		if strings.HasSuffix(r.Path, "/drift/reviews") {
			out = append(out, r.Body)
		}
	}
	return out
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}
	t.mu.Lock()
	t.requests = append(t.requests, Request{
		Method: req.Method,
		Path:   req.URL.Path,
		Header: req.Header.Clone(),
		Body:   body,
	})
	t.mu.Unlock()

	if t.Hang {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}

	switch {
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/drift/context"):
		if t.ContextStatus == 0 && len(t.ContextBody) == 0 {
			return t.unplanned(req)
		}
		return respond(or(t.ContextStatus, http.StatusOK), t.ContextBody), nil

	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/drift/reviews"):
		body := t.ReviewBody
		if len(body) == 0 {
			body = []byte(`{"id":"00000000-0000-0000-0000-000000000000"}`)
		}
		return respond(or(t.ReviewStatus, http.StatusCreated), body), nil
	}
	return t.unplanned(req)
}

func (t *Transport) unplanned(req *http.Request) (*http.Response, error) {
	msg := fmt.Sprintf("unplanned request to threatcl cloud: %s %s", req.Method, req.URL.Path)
	if t.Fail != nil {
		t.Fail("%s", msg)
	}
	return nil, errors.New(msg)
}

func respond(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func or(status, fallback int) int {
	if status != 0 {
		return status
	}
	return fallback
}

// ErrorBody renders the server's error envelope for a canned failure.
func ErrorBody(status int, code, message string) []byte {
	return []byte(fmt.Sprintf(`{"error":{"code":%q,"message":%q,"status":%d}}`, code, message, status))
}
