package deps

import "testing"

// Evidence citations point at these line numbers, so an off-by-one here sends
// reviewers to the wrong line.
func TestParsePatchTracksPostImageLines(t *testing.T) {
	patch := `@@ -5,6 +5,7 @@ require (
 	github.com/hashicorp/hcl/v2 v2.24.0
 	github.com/threatcl/spec v0.7.0
+	github.com/getsentry/sentry-go v0.28.0
 )
@@ -20,3 +21,2 @@ require (
 	golang.org/x/net v0.56.0
-	github.com/old/dep v1.0.0
`

	lines := ParsePatch(patch)

	var added, removed, context []PatchLine
	for _, line := range lines {
		switch line.Kind {
		case Added:
			added = append(added, line)
		case Removed:
			removed = append(removed, line)
		case Context:
			context = append(context, line)
		}
	}

	if len(added) != 1 || added[0].Number != 7 {
		t.Errorf("added = %+v, want one line at 7", added)
	}
	if len(removed) != 1 || removed[0].Number != 0 {
		t.Errorf("removed = %+v, want one line with no post-image number", removed)
	}
	if len(context) != 4 {
		t.Fatalf("context lines = %d, want 4", len(context))
	}
	// The second hunk restarts numbering from its own header.
	if context[3].Number != 21 {
		t.Errorf("second hunk context line = %d, want 21", context[3].Number)
	}
}

func TestParsePatchIgnoresPreamble(t *testing.T) {
	// Lines before the first hunk header have no line number to attribute.
	lines := ParsePatch("diff --git a/go.mod b/go.mod\n--- a/go.mod\n+++ b/go.mod\n@@ -1,1 +1,2 @@\n line\n+added\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %+v, want 2", lines)
	}
	if lines[1].Kind != Added || lines[1].Number != 2 {
		t.Errorf("added line = %+v", lines[1])
	}
}
