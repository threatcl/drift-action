package llm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// ContextFile is one repo file sent to the model whole.
type ContextFile struct {
	Path     string
	Contents string
}

// ContextSelection is what SelectContext chose to send, and what it left out.
type ContextSelection struct {
	Files []ContextFile
	// Skipped lists files that were selected but could not be sent — over
	// budget, unreadable, or not text. They reach the comment: a review that
	// silently dropped the file backing a control would report a phantom
	// control that is not phantom.
	Skipped []string
	// Bytes is the total size of Files.
	Bytes int
}

// SelectContext picks the repo files worth sending whole: files the threat
// model's prose references *and* this pull request touched, read from the
// checkout at workspace.
//
// Both halves matter. The diff shows only changed hunks, so without the whole
// current file the model cannot tell "the code backing this control was
// deleted" from "it is still there, just outside the hunk" — that distinction
// is the entire phantom-control category. And a file the model says nothing
// about is not worth the tokens.
//
// Files are taken in path order until budget bytes are used; a budget of zero
// or less means no cap.
func SelectContext(workspace string, referenced, touched []string, budget int) ContextSelection {
	selection := ContextSelection{}

	for _, path := range intersect(referenced, touched) {
		contents, err := readInWorkspace(workspace, path)
		if err != nil {
			selection.Skipped = append(selection.Skipped, path)
			continue
		}
		if budget > 0 && selection.Bytes+len(contents) > budget {
			selection.Skipped = append(selection.Skipped, path)
			continue
		}
		selection.Bytes += len(contents)
		selection.Files = append(selection.Files, ContextFile{Path: path, Contents: contents})
	}
	return selection
}

// intersect returns the touched paths that a referenced path names. Model
// prose cites paths loosely ("session.go" as often as "internal/auth/session.go"),
// so a bare reference matches wherever the file actually sits.
func intersect(referenced, touched []string) []string {
	seen := map[string]bool{}
	matched := make([]string, 0, len(touched))

	for _, path := range touched {
		for _, ref := range referenced {
			if ref == "" {
				continue
			}
			if path == ref || strings.HasSuffix(path, "/"+ref) {
				if !seen[path] {
					seen[path] = true
					matched = append(matched, path)
				}
				break
			}
		}
	}

	sort.Strings(matched)
	return matched
}

// readInWorkspace reads a repo-relative path from the checkout. The path comes
// from the GitHub API rather than from the PR body, but the engine still must
// not read outside the workspace whatever it is handed.
func readInWorkspace(workspace, rel string) (string, error) {
	full := filepath.Join(workspace, filepath.FromSlash(rel))
	root := filepath.Clean(workspace) + string(os.PathSeparator)
	if !strings.HasPrefix(full, root) {
		return "", fmt.Errorf("%s resolves outside the workspace", rel)
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("%s is not text", rel)
	}
	return string(data), nil
}
