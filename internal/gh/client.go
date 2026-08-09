// Package gh is the GitHub API surface the action needs: read the PR diff via
// the compare endpoint, upsert the sticky comment, create the check run.
package gh

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-github/v75/github"

	"github.com/threatcl/drift-action/internal/diff"
)

// CheckRunName is the name the check run appears under on the PR.
const CheckRunName = "Threat Drift"

// Comment is a minimal issue-comment shape.
type Comment struct {
	ID   int64
	Body string
}

// Client talks to the GitHub API for one PR.
type Client struct {
	api    *github.Client
	owner  string
	repo   string
	number int
}

// New builds a client for the PR described by ctx.
func New(token string, prCtx *Context) *Client {
	api := github.NewClient(nil)
	if token != "" {
		api = api.WithAuthToken(token)
	}
	return &Client{api: api, owner: prCtx.Owner, repo: prCtx.Repo, number: prCtx.Number}
}

// CompareResult is the diff between two commits, plus what the API withheld.
type CompareResult struct {
	Changes []diff.Change
	// TotalFiles is what GitHub reports for the comparison, which can exceed
	// len(Changes) when the response is truncated.
	TotalFiles int
	// PatchOmitted counts files GitHub returned without a patch body — very
	// large files, and binaries. They are reported, never silently treated as
	// unchanged.
	PatchOmitted int
}

// Compare fetches the changed files between base and head. GitHub paginates
// the file list at 300 entries and omits patches for very large files, so both
// limits are surfaced rather than absorbed.
func (c *Client) Compare(ctx context.Context, base, head string) (*CompareResult, error) {
	result := &CompareResult{}
	opts := &github.ListOptions{PerPage: 100}

	for {
		comparison, resp, err := c.api.Repositories.CompareCommits(
			ctx, c.owner, c.repo, base, head, opts)
		if err != nil {
			return nil, fmt.Errorf("comparing %s...%s: %w", base, head, err)
		}
		result.TotalFiles = comparison.GetTotalCommits()
		if files := comparison.Files; files != nil {
			for _, file := range files {
				change := diff.Change{
					Path:    file.GetFilename(),
					OldPath: file.GetPreviousFilename(),
					Status:  file.GetStatus(),
					Patch:   file.GetPatch(),
				}
				if change.Patch == "" && change.Status != "removed" {
					result.PatchOmitted++
				}
				result.Changes = append(result.Changes, change)
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	result.TotalFiles = len(result.Changes)
	return result, nil
}

// UpsertStickyComment creates the action's PR comment, or edits the existing
// one in place so a PR accumulates one comment rather than one per push.
func (c *Client) UpsertStickyComment(ctx context.Context, body string) error {
	existing, err := c.findSticky(ctx)
	if err != nil {
		return err
	}

	if existing != nil {
		_, _, err := c.api.Issues.EditComment(ctx, c.owner, c.repo, existing.ID,
			&github.IssueComment{Body: github.Ptr(body)})
		if err != nil {
			return fmt.Errorf("editing comment %d: %w", existing.ID, err)
		}
		return nil
	}

	_, _, err = c.api.Issues.CreateComment(ctx, c.owner, c.repo, c.number,
		&github.IssueComment{Body: github.Ptr(body)})
	if err != nil {
		return fmt.Errorf("creating comment: %w", err)
	}
	return nil
}

func (c *Client) findSticky(ctx context.Context) (*Comment, error) {
	opts := &github.IssueListCommentsOptions{ListOptions: github.ListOptions{PerPage: 100}}

	for {
		comments, resp, err := c.api.Issues.ListComments(ctx, c.owner, c.repo, c.number, opts)
		if err != nil {
			return nil, fmt.Errorf("listing comments: %w", err)
		}

		page := make([]Comment, 0, len(comments))
		for _, comment := range comments {
			page = append(page, Comment{ID: comment.GetID(), Body: comment.GetBody()})
		}
		if found := FindStickyComment(page); found != nil {
			return found, nil
		}

		if resp == nil || resp.NextPage == 0 {
			return nil, nil
		}
		opts.Page = resp.NextPage
	}
}

// CreateCheckRun reports the run's conclusion. Fork PRs get a read-only token,
// so this is expected to fail there; callers should treat the error as
// non-fatal and still surface the comment.
func (c *Client) CreateCheckRun(ctx context.Context, headSHA, conclusion, title, summary string) error {
	if headSHA == "" {
		return errors.New("no head SHA to attach the check run to")
	}
	_, _, err := c.api.Checks.CreateCheckRun(ctx, c.owner, c.repo, github.CreateCheckRunOptions{
		Name:       CheckRunName,
		HeadSHA:    headSHA,
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr(conclusion),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(title),
			Summary: github.Ptr(summary),
		},
	})
	if err != nil {
		return fmt.Errorf("creating check run: %w", err)
	}
	return nil
}
