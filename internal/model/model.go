package model

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/threatcl/spec"
)

// Assertions is the parsed threat model surface the drift engine checks the
// diff against: threats, controls with implemented flags, information assets,
// third-party dependencies, and DFD elements. Lines carries the source file
// and line numbers spec itself discards.
//
// It may span several files parsed as one set. Wrapped then holds every
// model in the set, in the order Sources lists their files.
type Assertions struct {
	Sources []string
	Wrapped *spec.ThreatmodelWrapped
	Lines   *LineIndex
}

// Load parses a .tm.hcl file via threatcl/spec and indexes its source lines.
func Load(path string) (*Assertions, error) {
	return loadFile(path, path)
}

// LoadIn loads a model that lives at rel inside root, recording rel as its
// source. Findings cite the source, and a citation has to be repo-relative to
// be useful — a runner-absolute /github/workspace/... path resolves to nothing
// for the developer reading the PR.
func LoadIn(root, rel string) (*Assertions, error) {
	return LoadSet(root, []string{rel})
}

// LoadSet loads the threat model files at rels inside root as one parsed set,
// so a model may extend a parent declared in another file. Duplicate entries
// are collapsed, and the configured order is kept: it is the render order.
//
// One path keeps the single-file route through spec's ParseFile, unchanged:
// it validates the backend block and accepts JSON, and a repo with one model
// must review exactly as it did before sets existed. Several paths go through
// ParseHCLRawSet, which is HCL-only.
//
// Every path must resolve inside root, whichever route it takes: see
// readConfined.
func LoadSet(root string, rels []string) (*Assertions, error) {
	rels = dedupe(rels)
	if len(rels) == 0 {
		return nil, errors.New("no threat model files to load")
	}
	contents, err := readConfined(root, rels)
	if err != nil {
		return nil, err
	}
	if len(rels) == 1 {
		return loadFile(filepath.Join(root, rels[0]), rels[0])
	}
	return loadSet(root, rels, contents)
}

// readConfined reads each model file through an os.Root opened on the
// checkout, refusing any that resolves outside it — by ../, by an absolute
// path, or by a symlink the pull request adds. model_paths comes from the
// pull request's own .threatcl-ci.hcl, and what a model file declares is
// rendered into the prompt sent to the LLM provider, so an unconfined path
// would let a pull request choose a file from the runner to disclose.
//
// The single-file route discards the contents and lets spec's ParseFile read
// the same path again. That second read is safe because nothing can change
// the checkout between the two.
func readConfined(root string, rels []string) ([][]byte, error) {
	for _, rel := range rels {
		// os.Root refuses these too; checking first words the error for the
		// reader rather than as "path escapes from parent".
		if !filepath.IsLocal(rel) {
			return nil, fmt.Errorf(
				"threat model %s is outside the repository: model_paths entries must be relative paths inside it", rel)
		}
	}

	workspace, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("opening the workspace: %w", err)
	}
	defer func() { _ = workspace.Close() }()

	contents := make([][]byte, len(rels))
	for i, rel := range rels {
		content, err := workspace.ReadFile(rel)
		if err != nil {
			// The PathError can name the runner-absolute path; rel is the
			// one the reader configured.
			var pathErr *fs.PathError
			if errors.As(err, &pathErr) {
				err = pathErr.Err
			}
			return nil, fmt.Errorf("reading threat model %s: %w", rel, err)
		}
		contents[i] = content
	}
	return contents, nil
}

func loadFile(fsPath, displayPath string) (*Assertions, error) {
	wrapped, err := parse(func(p *spec.ThreatmodelParser) error {
		return p.ParseFile(fsPath, false)
	})
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", displayPath, explain(err))
	}

	return &Assertions{
		Sources: []string{displayPath},
		Wrapped: wrapped,
		Lines:   buildLineIndex([]sourceFile{{path: fsPath, display: displayPath}}),
	}, nil
}

func loadSet(root string, rels []string, contents [][]byte) (*Assertions, error) {
	inputs := make([]spec.NamedInput, 0, len(rels))
	files := make([]sourceFile, 0, len(rels))
	for i, rel := range rels {
		// Checked before parsing, so the error names the real problem rather
		// than an HCL syntax error from parsing JSON as HCL.
		if filepath.Ext(rel) != ".hcl" {
			return nil, fmt.Errorf(
				"threat model %s: a multi-file set must be HCL — spec parses sets from HCL only", rel)
		}
		fsPath := filepath.Join(root, rel)
		// Name is the real path, not rel: spec resolves a relative
		// `including` or import against it.
		inputs = append(inputs, spec.NamedInput{Name: fsPath, Content: contents[i]})
		files = append(files, sourceFile{path: fsPath, display: rel})
	}

	wrapped, err := parse(func(p *spec.ThreatmodelParser) error {
		return p.ParseHCLRawSet(inputs)
	})
	if err != nil {
		return nil, fmt.Errorf("parsing threat model set (%s): %w",
			strings.Join(rels, ", "), explain(err))
	}

	return &Assertions{
		Sources: rels,
		Wrapped: wrapped,
		Lines:   buildLineIndex(files),
	}, nil
}

// parse runs a spec parse, and runs it a second time when any model in the
// result uses extends.
//
// spec resolves extends by copying the parent's threats, information assets,
// use cases, exclusions and third-party dependencies into the child. Rendered
// as-is, every inherited item appears twice — once per model, the child's
// copy with no citation because the block sits in the parent — and the
// summary counts it twice. The first parse, with resolution on, is kept for
// validation alone: an unknown parent or a cycle fails there. The second skips
// resolution, so the result holds what each model declares, and an inherited
// item is rendered once, under the model that declares it.
//
// The resolved result cannot be filtered instead. inheritFrom copies by value
// and a child's same-named item overrides the parent's, so nothing tells an
// inherited item from an override; "has no line number" would misfire on JSON
// models and on `including` merges.
func parse(run func(*spec.ThreatmodelParser) error) (*spec.ThreatmodelWrapped, error) {
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		return nil, fmt.Errorf("loading spec config: %w", err)
	}

	resolved := spec.NewThreatmodelParser(cfg)
	if err := run(resolved); err != nil {
		return nil, err
	}
	if !usesExtends(resolved.GetWrapped()) {
		return resolved.GetWrapped(), nil
	}

	declared := spec.NewThreatmodelParser(cfg)
	declared.SetSkipExtendsResolution(true)
	if err := run(declared); err != nil {
		return nil, err
	}
	return declared.GetWrapped(), nil
}

func usesExtends(wrapped *spec.ThreatmodelWrapped) bool {
	for _, tm := range wrapped.Threatmodels {
		if tm.Extends != "" {
			return true
		}
	}
	return false
}

// unknownExtends is spec's wording when an extends target is not in the
// parsed set. spec exports no error type for it, so the text is matched; a
// test pins it, so a spec bump that rewords it fails there.
const unknownExtends = "extends references unknown threat model id"

// explain adds the fix to an error the reader cannot act on as spec words it.
// The usual cause is model_paths naming a child without its parent, and spec
// has no way to say that.
func explain(err error) error {
	if strings.Contains(err.Error(), unknownExtends) {
		return fmt.Errorf(
			"a threat model extends one that is not in the files parsed together; add the file declaring the parent to model_paths in .threatcl-ci.hcl: %w",
			err)
	}
	return err
}

// dedupe drops repeated paths, comparing them cleaned so "./a.tm.hcl" and
// "a.tm.hcl" are one file. The first spelling is kept, since it is what the
// reader configured and what citations will show.
func dedupe(rels []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(rels))
	for _, rel := range rels {
		key := filepath.Clean(rel)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rel)
	}
	return out
}

// Models returns the threat models parsed from the set.
func (a *Assertions) Models() []spec.Threatmodel {
	if a == nil || a.Wrapped == nil {
		return nil
	}
	return a.Wrapped.Threatmodels
}
