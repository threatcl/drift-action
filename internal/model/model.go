package model

import (
	"fmt"
	"path/filepath"

	"github.com/threatcl/spec"
)

// Assertions is the parsed threat model surface the drift engine checks the
// diff against: threats, controls with implemented flags, information assets,
// third-party dependencies, and DFD elements. Lines carries the source line
// numbers spec itself discards.
type Assertions struct {
	Source  string
	Wrapped *spec.ThreatmodelWrapped
	Lines   *LineIndex
}

// Load parses a .tm.hcl file via threatcl/spec and indexes its source lines.
func Load(path string) (*Assertions, error) {
	return load(path, path)
}

// LoadIn loads a model that lives at rel inside root, recording rel as the
// Source. Findings cite Source, and a citation has to be repo-relative to be
// useful — a runner-absolute /github/workspace/... path resolves to nothing
// for the developer reading the PR.
func LoadIn(root, rel string) (*Assertions, error) {
	return load(filepath.Join(root, rel), rel)
}

func load(fsPath, displayPath string) (*Assertions, error) {
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		return nil, fmt.Errorf("loading spec config: %w", err)
	}
	parser := spec.NewThreatmodelParser(cfg)
	if err := parser.ParseFile(fsPath, false); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", displayPath, err)
	}

	index := buildLineIndex(fsPath)
	index.path = displayPath

	return &Assertions{
		Source:  displayPath,
		Wrapped: parser.GetWrapped(),
		Lines:   index,
	}, nil
}

// Models returns the threat models parsed from the file.
func (a *Assertions) Models() []spec.Threatmodel {
	if a == nil || a.Wrapped == nil {
		return nil
	}
	return a.Wrapped.Threatmodels
}
