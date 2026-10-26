package model

import (
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/threatcl/spec"
	"github.com/zclconf/go-cty/cty"
)

// Backend is the Threatcl Cloud address one model file declares in its
// backend block: the organisation and, once pushed, the model slug. A file
// with no block has no entry. Cloud-connected mode groups a set's files by
// this address to link each to its cloud model.
//
// It is kept apart from Render() on purpose: a backend block is where a model
// lives, not what it asserts, so it must not reach the prompt — and the
// rendered assertions are every corpus recording's fingerprint.
type Backend struct {
	// File is the model file the block sits in, as configured.
	File  string
	Org   string
	Model string
}

// Backends returns the backend address of every file in the set that declares
// one, in configured file order.
func (a *Assertions) Backends() []Backend {
	if a == nil {
		return nil
	}
	return a.backends
}

// backendsOf attributes backend blocks to files. spec's single-file route
// validates the block (one at most, with an organisation) and the result is
// that file's by construction, JSON models included. The set route appends
// each file's blocks to one list and a file may have none, so the files are
// scanned again with hclsyntax to attribute each block to its own file.
func backendsOf(wrapped *spec.ThreatmodelWrapped, files []sourceFile) []Backend {
	if len(files) == 1 {
		var out []Backend
		for _, b := range wrapped.Backends {
			if b != nil {
				out = append(out, Backend{File: files[0].display, Org: b.BackendOrg, Model: b.BackendTMShort})
			}
		}
		return out
	}

	var out []Backend
	for _, file := range files {
		f, diags := hclparse.NewParser().ParseHCLFile(file.path)
		if diags.HasErrors() || f == nil {
			continue
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type != "backend" {
				continue
			}
			out = append(out, Backend{
				File:  file.display,
				Org:   stringAttr(block.Body, "organization"),
				Model: stringAttr(block.Body, "threatmodel"),
			})
		}
	}
	return out
}

// stringAttr reads a literal string attribute, or "" when it is absent or not
// a string. Backend blocks are literals in practice; anything else is left
// for spec to have rejected.
func stringAttr(body *hclsyntax.Body, name string) string {
	attr, ok := body.Attributes[name]
	if !ok {
		return ""
	}
	value, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || value.Type() != cty.String || value.IsNull() || !value.IsKnown() {
		return ""
	}
	return value.AsString()
}
