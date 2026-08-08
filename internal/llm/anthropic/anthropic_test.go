package anthropic

import (
	"context"
	"errors"
	"testing"

	"github.com/threatcl/drift-action/internal/llm"
)

func TestReviewNotImplemented(t *testing.T) {
	c := New("claude-sonnet-5", "test-key")
	if c.model != "claude-sonnet-5" {
		t.Errorf("model = %q", c.model)
	}
	_, err := c.Review(context.Background(), llm.ReviewRequest{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("err = %v, want ErrNotImplemented", err)
	}
}
