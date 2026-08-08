// Package gh is the GitHub API surface the action needs: read the PR diff
// via the compare endpoint, upsert the sticky comment, create the check run.
package gh

import "errors"

var ErrNotImplemented = errors.New("github client not implemented yet")

// Comment is a minimal issue-comment shape.
type Comment struct {
	ID   int64
	Body string
}

// Client talks to the GitHub API for one PR.
type Client struct {
	Token  string
	Owner  string
	Repo   string
	Number int
}

func (c *Client) UpsertStickyComment(body string) error { return ErrNotImplemented }

func (c *Client) CreateCheckRun(conclusion, summary string) error { return ErrNotImplemented }
