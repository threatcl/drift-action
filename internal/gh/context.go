package gh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNotPullRequest means the workflow ran on an event with no PR to review.
// Callers should skip cleanly rather than fail — the action may legitimately
// sit in a workflow that also runs on push.
var ErrNotPullRequest = errors.New("not a pull request event")

// Context is the GitHub-supplied environment the run operates in.
type Context struct {
	Owner     string
	Repo      string
	Number    int
	BaseSHA   string
	HeadSHA   string
	Workspace string
	EventName string
	// Fork is true when the PR comes from a forked repository, which under the
	// pull_request trigger means no secrets and a read-only token.
	Fork bool
}

// eventPayload is the slice of the webhook payload the engine needs.
type eventPayload struct {
	PullRequest *struct {
		Number int `json:"number"`
		Base   struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
		Head struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
}

// LoadContext reads the runner environment. It returns ErrNotPullRequest when
// the event carries no pull request.
func LoadContext() (*Context, error) {
	repository := os.Getenv("GITHUB_REPOSITORY")
	owner, repo, ok := strings.Cut(repository, "/")
	if !ok {
		return nil, fmt.Errorf("GITHUB_REPOSITORY is %q, want owner/repo", repository)
	}

	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return nil, ErrNotPullRequest
	}
	raw, err := os.ReadFile(eventPath)
	if err != nil {
		return nil, fmt.Errorf("reading event payload: %w", err)
	}

	var payload eventPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parsing event payload: %w", err)
	}
	if payload.PullRequest == nil || payload.PullRequest.Number == 0 {
		return nil, ErrNotPullRequest
	}

	workspace := os.Getenv("GITHUB_WORKSPACE")
	if workspace == "" {
		workspace = "."
	}

	return &Context{
		Owner:     owner,
		Repo:      repo,
		Number:    payload.PullRequest.Number,
		BaseSHA:   payload.PullRequest.Base.SHA,
		HeadSHA:   payload.PullRequest.Head.SHA,
		Workspace: workspace,
		EventName: os.Getenv("GITHUB_EVENT_NAME"),
		Fork: payload.PullRequest.Head.Repo.FullName != "" &&
			payload.PullRequest.Head.Repo.FullName != payload.PullRequest.Base.Repo.FullName,
	}, nil
}
