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

// AnchorLine is where a reader should look when a finding is about something
// the model does not say — the first threatmodel block, or 0 if unknown.
func (a *Assertions) AnchorLine() int {
	for _, tm := range a.Models() {
		if line := a.Lines.Line("threatmodel", tm.Name); line > 0 {
			return line
		}
	}
	return 0
}

// DependencyAssertion is a third-party dependency the model claims exists,
// flattened so consumers need not import spec.
type DependencyAssertion struct {
	Name        string
	Description string
	Uptime      string
	Line        int
}

// Dependencies flattens every third_party_dependency block in the file.
func (a *Assertions) Dependencies() []DependencyAssertion {
	var deps []DependencyAssertion
	for _, tm := range a.Models() {
		for _, dep := range tm.ThirdPartyDependencies {
			deps = append(deps, DependencyAssertion{
				Name:        dep.Name,
				Description: dep.Description,
				Uptime:      string(dep.UptimeDependency),
				Line: a.Lines.Line("threatmodel", tm.Name,
					"third_party_dependency", dep.Name),
			})
		}
	}
	return deps
}
