package gh

import (
	"strings"

	"github.com/threatcl/drift-action/internal/render"
)

// FindStickyComment returns the existing drift comment to update in place, or
// nil when this is the first run on the PR.
//
// Only a comment authored by the action's own login qualifies. The marker also
// appears wherever someone quotes the review — and "update the sticky comment"
// must never mean overwriting another user's words with a report.
func FindStickyComment(comments []Comment, author string) *Comment {
	for i := range comments {
		if comments[i].Author == author && strings.Contains(comments[i].Body, render.StickyMarker) {
			return &comments[i]
		}
	}
	return nil
}
