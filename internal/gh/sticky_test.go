package gh

import (
	"testing"

	"github.com/threatcl/drift-action/internal/render"
)

func TestFindStickyComment(t *testing.T) {
	body := render.StickyMarker + "\n\n## Threat Drift Review by Threatcl"
	comments := []Comment{
		{ID: 1, Body: "unrelated review comment", Author: "reviewer"},
		{ID: 2, Body: body, Author: actionsBotLogin},
		{ID: 3, Body: "another comment", Author: "reviewer"},
	}
	got := FindStickyComment(comments, actionsBotLogin)
	if got == nil || got.ID != 2 {
		t.Fatalf("FindStickyComment = %+v, want ID 2", got)
	}
	if FindStickyComment(comments[:1], actionsBotLogin) != nil {
		t.Fatal("expected nil when no marker present")
	}
}

// A user quoting the review reproduces the marker in their comment. Editing
// that comment would overwrite their words, so authorship gates the match.
func TestFindStickyCommentIgnoresOtherAuthors(t *testing.T) {
	body := render.StickyMarker + "\n\n## Threat Drift Review by Threatcl"
	comments := []Comment{
		{ID: 1, Body: "> " + body + "\n\nis this accurate?", Author: "reviewer"},
		{ID: 2, Body: body, Author: actionsBotLogin},
	}

	got := FindStickyComment(comments, actionsBotLogin)
	if got == nil || got.ID != 2 {
		t.Fatalf("FindStickyComment = %+v, want the action's own comment (ID 2)", got)
	}

	// Only the quote exists: first run for the action, so create — never edit.
	if got := FindStickyComment(comments[:1], actionsBotLogin); got != nil {
		t.Fatalf("FindStickyComment = %+v, want nil for another author's quote", got)
	}
}
