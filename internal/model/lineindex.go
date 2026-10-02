package model

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// LineIndex maps threat model blocks to the file and line they start at.
// threatcl/spec discards source ranges — its structs carry no hcl.Range and
// its parser is never returned — so we index the files separately and join by
// block type and label. Without this, findings cannot cite the model
// excerpt's file:line, and the evidence rule is unenforceable.
//
// A set spans several files, so each entry records the file its block is
// physically in: a citation naming a file that does not contain the block is
// worse than none. Threat model names are unique across a parsed set, so an
// address — which starts with the model's name — identifies one block in one
// file.
type LineIndex struct {
	locations map[string]Location
}

// Location is where a block starts. The zero Location means unknown.
type Location struct {
	File string
	Line int
}

// Locate returns where the addressed block starts, or the zero Location when
// the block is unknown (a JSON model, or a name the index never saw). Callers
// must render an unknown location as no citation, never as line zero.
//
// The address is the chain of block types and labels from the file root, e.g.
// Locate("threatmodel", "payments", "threat", "credential stuffing").
func (li *LineIndex) Locate(address ...string) Location {
	if li == nil {
		return Location{}
	}
	return li.locations[strings.Join(address, "\x00")]
}

// Line returns the 1-indexed line where the addressed block starts, or 0 when
// the block is unknown. See Locate.
func (li *LineIndex) Line(address ...string) int {
	return li.Locate(address...).Line
}

// sourceFile is one model file to index: where to read it, and the path a
// citation shows for it.
type sourceFile struct {
	path    string
	display string
}

// buildLineIndex indexes every block in each HCL file. Non-HCL models (spec
// also accepts JSON) contribute nothing rather than an error — line citations
// degrade, the rest of the run does not.
func buildLineIndex(files []sourceFile) *LineIndex {
	idx := &LineIndex{locations: map[string]Location{}}
	for _, file := range files {
		idx.add(file)
	}
	return idx
}

func (li *LineIndex) add(file sourceFile) {
	if !strings.HasSuffix(strings.ToLower(file.path), ".hcl") {
		return
	}
	f, diags := hclparse.NewParser().ParseHCLFile(file.path)
	if diags.HasErrors() || f == nil {
		return
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return
	}
	indexBody(body, nil, file.display, li.locations)
}

func indexBody(body *hclsyntax.Body, prefix []string, file string, out map[string]Location) {
	for _, block := range body.Blocks {
		address := make([]string, 0, len(prefix)+1+len(block.Labels))
		address = append(address, prefix...)
		address = append(address, block.Type)
		address = append(address, block.Labels...)

		// First definition wins, so duplicate names resolve to the block a
		// reader encounters first rather than the last one parsed. Across a
		// set, "first" follows the configured file order.
		key := strings.Join(address, "\x00")
		if _, seen := out[key]; !seen {
			out[key] = Location{File: file, Line: block.DefRange().Start.Line}
		}
		indexBody(block.Body, address, file, out)
	}
}
