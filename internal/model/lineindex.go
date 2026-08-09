package model

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// LineIndex maps threat model blocks to their line numbers in the source
// file. threatcl/spec discards source ranges — its structs carry no hcl.Range
// and its parser is never returned — so we index the file separately and join
// by block type and label. Without this, findings cannot cite the model
// excerpt's file:line, and the evidence rule is unenforceable.
type LineIndex struct {
	path  string
	lines map[string]int
}

// Path is the file the index was built from.
func (li *LineIndex) Path() string {
	if li == nil {
		return ""
	}
	return li.path
}

// Line returns the 1-indexed line where the addressed block starts, or 0 when
// the block is unknown (a JSON model, or a name the index never saw). Callers
// must render a 0 as "no line", never as line zero.
//
// The address is the chain of block types and labels from the file root, e.g.
// Line("threatmodel", "payments", "threat", "credential stuffing").
func (li *LineIndex) Line(address ...string) int {
	if li == nil {
		return 0
	}
	return li.lines[strings.Join(address, "\x00")]
}

// buildLineIndex indexes every block in an HCL file. Non-HCL models (spec also
// accepts JSON) yield an empty index rather than an error — line citations
// degrade, the rest of the run does not.
func buildLineIndex(path string) *LineIndex {
	idx := &LineIndex{path: path, lines: map[string]int{}}

	if !strings.HasSuffix(strings.ToLower(path), ".hcl") {
		return idx
	}
	f, diags := hclparse.NewParser().ParseHCLFile(path)
	if diags.HasErrors() || f == nil {
		return idx
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return idx
	}
	indexBody(body, nil, idx.lines)
	return idx
}

func indexBody(body *hclsyntax.Body, prefix []string, out map[string]int) {
	for _, block := range body.Blocks {
		address := make([]string, 0, len(prefix)+1+len(block.Labels))
		address = append(address, prefix...)
		address = append(address, block.Type)
		address = append(address, block.Labels...)

		// First definition wins, so duplicate names resolve to the block a
		// reader encounters first rather than the last one parsed.
		key := strings.Join(address, "\x00")
		if _, seen := out[key]; !seen {
			out[key] = block.DefRange().Start.Line
		}
		indexBody(block.Body, address, out)
	}
}
