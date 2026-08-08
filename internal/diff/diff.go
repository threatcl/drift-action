// Package diff models the PR diff and filters it to the security-relevant
// subset that feeds deterministic checks and inference.
package diff

// Change is one changed file in the PR diff, as returned by the GitHub
// compare API.
type Change struct {
	Path    string
	OldPath string
	Status  string // added | modified | removed | renamed
	Patch   string
}
