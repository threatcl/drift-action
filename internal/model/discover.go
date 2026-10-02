package model

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ErrNoModel means the repo has no threat model to drift-check against.
var ErrNoModel = errors.New("no threat model found")

// discoveryGlobs are searched in order: repo root first, then the conventional
// threatmodels/ directory. Both spellings of that directory are searched — the
// org's own ENISA worked example (a template repo, so its layout propagates)
// keeps its model under the singular threatmodel/.
var discoveryGlobs = []string{
	"*.tm.hcl",
	"threatmodels/*.hcl", "threatmodels/*.tm.hcl",
	"threatmodel/*.hcl", "threatmodel/*.tm.hcl",
}

// Discover finds candidate threat model files under root. It deliberately does
// not glob bare *.hcl at the repo root — that would sweep up .threatcl-ci.hcl
// and any unrelated HCL the repo happens to keep there.
func Discover(root string) ([]string, error) {
	seen := map[string]bool{}
	var found []string

	for _, glob := range discoveryGlobs {
		matches, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			return nil, fmt.Errorf("globbing %s: %w", glob, err)
		}
		for _, match := range matches {
			rel, err := filepath.Rel(root, match)
			if err != nil {
				rel = match
			}
			if seen[rel] || strings.HasSuffix(rel, ".threatcl-ci.hcl") {
				continue
			}
			seen[rel] = true
			found = append(found, rel)
		}
	}

	sort.Strings(found)
	return found, nil
}

// Resolve picks the model files to assess. Configured paths win outright, and
// several of them are assessed together as one set. Otherwise discovery must
// land on exactly one file: the claude-plugin asks the user when a repo has
// several, and CI cannot, so guessing is refused in favour of an error that
// names the fix. Discovering several files does not make them one set — two
// unrelated models assessed together would be one large, muddled review — so
// assessing them together is the reader's choice, made in model_paths.
func Resolve(root string, configured []string) ([]string, error) {
	if len(configured) > 0 {
		return configured, nil
	}

	found, err := Discover(root)
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, ErrNoModel
	case 1:
		return found, nil
	default:
		quoted := make([]string, len(found))
		for i, path := range found {
			quoted[i] = fmt.Sprintf("%q", filepath.ToSlash(path))
		}
		return nil, fmt.Errorf(
			"found %d threat models (%s); set model_paths in .threatcl-ci.hcl to choose one, or list several to assess them together as one set — model_paths = [%s] assesses them all",
			len(found), strings.Join(found, ", "), strings.Join(quoted, ", "))
	}
}
