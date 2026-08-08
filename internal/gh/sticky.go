package gh

import (
	"strings"

	"github.com/threatcl/drift-action/internal/render"
)

// FindStickyComment returns the existing drift comment to update in place, or
// nil when this is the first run on the PR.
func FindStickyComment(comments []Comment) *Comment {
	for i := range comments {
		if strings.Contains(comments[i].Body, render.StickyMarker) {
			return &comments[i]
		}
	}
	return nil
}
