package model

import (
	"fmt"

	"github.com/threatcl/spec"
)

// Assertions is the parsed threat model surface the drift engine checks the
// diff against: threats, controls with implemented flags, information assets,
// third-party dependencies, and DFD elements.
type Assertions struct {
	Source  string
	Wrapped *spec.ThreatmodelWrapped
}

// Load parses a .tm.hcl file via threatcl/spec.
func Load(path string) (*Assertions, error) {
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		return nil, fmt.Errorf("loading spec config: %w", err)
	}
	parser := spec.NewThreatmodelParser(cfg)
	if err := parser.ParseFile(path, false); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &Assertions{Source: path, Wrapped: parser.GetWrapped()}, nil
}
