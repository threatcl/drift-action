package diff

import (
	"fmt"
	"sort"
	"strings"
)

// Render writes changes as the DIFF section of the review prompt, in path
// order, until budget bytes of section text are used. A budget of zero or less
// means no cap.
//
// Files that do not fit are returned rather than dropped on the floor. Under-
// reviewing produces a clean-looking result that hides drift — the worst
// outcome this action has — so every file the model never saw has to reach the
// comment. Rendering continues past a file that is too large, so one oversized
// patch does not cost the review every file after it.
func Render(changes []Change, budget int) (text string, omitted []string) {
	ordered := make([]Change, len(changes))
	copy(ordered, changes)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })

	var b strings.Builder
	for _, change := range ordered {
		entry := renderChange(change)
		if budget > 0 && b.Len()+len(entry) > budget {
			omitted = append(omitted, change.Path)
			continue
		}
		b.WriteString(entry)
	}
	return b.String(), omitted
}

func renderChange(c Change) string {
	header := fmt.Sprintf("--- %s (%s) ---\n", c.Path, describe(c))
	if strings.TrimSpace(c.Patch) == "" {
		// Say why there is no patch. Silence here reads as "this file did not
		// really change", which is exactly what it does not mean.
		return header + "(no patch: the GitHub API returned this file without one, because it is binary or too large)\n\n"
	}
	return header + strings.TrimRight(c.Patch, "\n") + "\n\n"
}

func describe(c Change) string {
	if c.Status == "renamed" && c.OldPath != "" {
		return fmt.Sprintf("renamed from %s", c.OldPath)
	}
	if c.Status == "" {
		return "modified"
	}
	return c.Status
}

// Paths lists the paths in changes, in the order given.
func Paths(changes []Change) []string {
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		paths = append(paths, change.Path)
	}
	return paths
}
