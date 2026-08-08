package gh

import (
	"testing"

	"github.com/threatcl/drift-action/internal/render"
)

func TestFindStickyComment(t *testing.T) {
	comments := []Comment{
		{ID: 1, Body: "unrelated review comment"},
		{ID: 2, Body: render.StickyMarker + "\n\n## Threat Drift Review by Threatcl"},
		{ID: 3, Body: "another comment"},
	}
	got := FindStickyComment(comments)
	if got == nil || got.ID != 2 {
		t.Fatalf("FindStickyComment = %+v, want ID 2", got)
	}
	if FindStickyComment(comments[:1]) != nil {
		t.Fatal("expected nil when no marker present")
	}
}
