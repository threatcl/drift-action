package cloud

import (
	"fmt"
	"slices"
	"strings"
)

// ModelFile is one threat model file of the set with the cloud address its
// backend block declares. Org and Model are empty for a file with no block;
// Model alone is empty for a block that names an organisation but no slug,
// which is how a model that has never been pushed looks.
type ModelFile struct {
	Name  string
	Org   string
	Model string
}

// Linked is one cloud model the repo's files resolve to.
type Linked struct {
	Slug string
	// Org is the organisation the files' backend blocks name, or "" when
	// none did. The server compares it with the token's and notes a mismatch;
	// it never changes which organisation is searched.
	Org   string
	Files []string
}

// LinkResult is how the set's files map onto cloud models.
type LinkResult struct {
	Models []Linked
	// Unlinked lists files that joined no model: they declared no address and
	// nothing told them one. They get library and write-back only, and the
	// comment says so.
	Unlinked []string
}

// Link groups the set's files by backend address, each group one cloud model,
// and applies the cloud.model override. That covers both shapes a repo has: a
// model split across files (one address, segments on cloud) and several
// unrelated models in a monorepo (several addresses).
//
// Contradictions are errors, never silently resolved. The override may name
// the one address the set declares, or supply one where the set declares
// none; it may not disagree with an address or pick among several.
//
// A file with no block follows the one address the set declares — a split
// model usually carries the block in one file — or the override. With several
// addresses it is left unlinked and reported, because guessing which model it
// belongs to would quote the wrong model's alignment back to the reader.
func Link(files []ModelFile, override string) (LinkResult, error) {
	type address struct{ org, slug string }
	var order []address
	groups := map[address][]string{}
	var unaddressed []string

	for _, f := range files {
		if f.Model == "" {
			unaddressed = append(unaddressed, f.Name)
			continue
		}
		key := address{f.Org, f.Model}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f.Name)
	}

	var result LinkResult
	switch {
	case len(order) == 0 && override == "":
		result.Unlinked = unaddressed
		return result, nil

	case len(order) == 0:
		result.Models = []Linked{{Slug: override, Files: slices.Clone(unaddressed)}}
		return result, nil

	case len(order) == 1:
		only := order[0]
		if override != "" && override != only.slug {
			return result, fmt.Errorf(
				"cloud.model is %q but the threat model's backend block names %q (%s); remove cloud.model or make them agree",
				override, only.slug, strings.Join(groups[only], ", "))
		}
		result.Models = []Linked{{Slug: only.slug, Org: only.org, Files: append(groups[only], unaddressed...)}}
		return result, nil

	default:
		if override != "" {
			slugs := make([]string, 0, len(order))
			for _, a := range order {
				slugs = append(slugs, a.slug)
			}
			return result, fmt.Errorf(
				"cloud.model is %q but the threat model files declare several backend addresses (%s), so it is ambiguous; remove cloud.model and let each file's backend block link it",
				override, strings.Join(slugs, ", "))
		}
		for _, a := range order {
			result.Models = append(result.Models, Linked{Slug: a.slug, Org: a.org, Files: groups[a]})
		}
		result.Unlinked = unaddressed
		return result, nil
	}
}
