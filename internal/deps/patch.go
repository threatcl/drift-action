// Package deps implements the deterministic half of dependency drift:
// manifest changes are read straight from the diff, with no LLM involved.
package deps

import (
	"regexp"
	"strconv"
	"strings"
)

// LineKind distinguishes the three line types in a unified diff body.
type LineKind int

const (
	Context LineKind = iota
	Added
	Removed
)

// PatchLine is one line of a unified diff. Number is the line's position in
// the post-image for context and added lines, and 0 for removed lines — so an
// evidence citation always points at a line the reader can actually open.
type PatchLine struct {
	Kind   LineKind
	Number int
	Text   string
}

var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ParsePatch walks a unified diff body, tracking post-image line numbers
// across hunks.
func ParsePatch(patch string) []PatchLine {
	var lines []PatchLine
	newLine := 0

	for raw := range strings.SplitSeq(patch, "\n") {
		if m := hunkHeader.FindStringSubmatch(raw); m != nil {
			start, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			newLine = start
			continue
		}
		if newLine == 0 || raw == "" {
			continue
		}

		switch raw[0] {
		case '+':
			lines = append(lines, PatchLine{Kind: Added, Number: newLine, Text: raw[1:]})
			newLine++
		case '-':
			lines = append(lines, PatchLine{Kind: Removed, Text: raw[1:]})
		case ' ':
			lines = append(lines, PatchLine{Kind: Context, Number: newLine, Text: raw[1:]})
			newLine++
		case '\\':
			// "\ No newline at end of file" — not a content line.
		}
	}
	return lines
}
