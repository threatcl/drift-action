package diff

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// generatedHeaderBytes bounds how much of a file is read looking for the
// header. Go requires it before the package clause, so at most a licence block
// sits above it; a package clause further in than this goes unparsed, and the
// file is treated as hand-written, which keeps it in review.
const generatedHeaderBytes = 64 << 10

// GoGenerated returns a predicate for Options.Generated that recognises Go's
// generated-code convention (https://go.dev/s/generatedcode): a
// "// Code generated … DO NOT EDIT." line before the package clause. It is the
// check go vet and gopls make, through go/ast.IsGenerated, so a file this
// skips is one the Go toolchain itself treats as generated.
//
// Only .go files are considered, since the convention is Go's. Files are read
// through root, so a path the pull request turned into a symlink out of the
// checkout is refused rather than followed. Anything that cannot be read or
// parsed — a removed file, a truncated header — is not generated: the answer
// that keeps a file in review.
func GoGenerated(root *os.Root) func(path string) bool {
	return func(p string) bool {
		if !strings.HasSuffix(p, ".go") {
			return false
		}
		f, err := root.Open(filepath.FromSlash(p))
		if err != nil {
			return false
		}
		defer func() { _ = f.Close() }()

		src, err := io.ReadAll(io.LimitReader(f, generatedHeaderBytes))
		if err != nil {
			return false
		}
		file, err := parser.ParseFile(token.NewFileSet(), p, src,
			parser.PackageClauseOnly|parser.ParseComments)
		if err != nil {
			return false
		}
		return ast.IsGenerated(file)
	}
}
