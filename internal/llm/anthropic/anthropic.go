package anthropic

import (
	"context"
	"errors"

	sdk "github.com/anthropics/anthropic-sdk-go"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

var _ llm.Provider = (*Client)(nil)

// Reference the SDK so the dependency is pinned in the module graph before
// the engine lands.
var _ = sdk.NewClient

var ErrNotImplemented = errors.New("anthropic provider not implemented yet")

type Client struct {
	model  string
	apiKey string
}

func New(model, apiKey string) *Client {
	return &Client{model: model, apiKey: apiKey}
}

func (c *Client) Review(ctx context.Context, req llm.ReviewRequest) (*findings.Report, error) {
	return nil, ErrNotImplemented
}
