package diff

import (
	"fmt"
	"path"
	"strings"
)

// trigger_paths and ignore_paths share one pattern language, modelled on
// .gitignore without its negation or "**":
//
//   - A trailing "/" names a directory and matches every file beneath it.
//   - A pattern with no other "/" matches at any depth: "generated/" is any
//     directory called generated, "*_gen.go" any file whose name fits.
//   - Any other pattern is anchored at the repo root and matched with
//     path.Match, whose "*" stops at "/": "cmd/*.go", "services/*/gen/".
//   - A leading "/" anchors a pattern that would otherwise match at any
//     depth: "/Makefile" is the one at the root and no other.
func matchPattern(p, pattern string) bool {
	anchored := strings.HasPrefix(pattern, "/")
	pattern = strings.TrimPrefix(pattern, "/")
	dir := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return false
	}

	if !anchored && !strings.Contains(pattern, "/") {
		segments := strings.Split(p, "/")
		if !dir {
			return globMatch(pattern, segments[len(segments)-1])
		}
		for _, segment := range segments[:len(segments)-1] {
			if globMatch(pattern, segment) {
				return true
			}
		}
		return false
	}

	if !dir {
		return globMatch(pattern, p)
	}
	for i := range len(p) {
		if p[i] == '/' && globMatch(pattern, p[:i]) {
			return true
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	ok, _ := path.Match(pattern, name)
	return ok
}

// matchesAny reports whether a pattern that keeps a file in review names p.
// Matching is generous here, as it is for narrowing: on top of the pattern
// language, a literal path also matches as a suffix, because the threat
// model's prose cites paths loosely ("auth/session.go" for
// "internal/auth/session.go"). A false positive costs a few tokens; a false
// negative hides drift.
func matchesAny(p string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if matchPattern(p, pattern) || strings.HasSuffix(p, "/"+pattern) {
			return true
		}
	}
	return false
}

// ignores reports whether an ignore_paths pattern names p. It applies the
// pattern language and nothing else — no suffix rule — because the cost runs
// the other way: an exclusion that reaches further than it reads removes
// files from review that nobody chose to remove.
func ignores(patterns []string, p string) bool {
	for _, pattern := range patterns {
		if matchPattern(p, pattern) {
			return true
		}
	}
	return false
}

// ValidatePattern rejects an ignore_paths entry that would not match the way
// it reads. Each case it refuses would otherwise be accepted and match
// nothing, or something other than intended, without a word: "**" is two
// stars to path.Match, "!" is a literal character, and a "./" prefix never
// matches a path from the GitHub API.
//
// trigger_paths predates it and is not held to it: refusing a pattern a
// working config already uses would fail that repo's next run outright.
func ValidatePattern(pattern string) error {
	switch {
	case strings.TrimSpace(pattern) == "":
		return fmt.Errorf("pattern is empty")
	case strings.HasPrefix(pattern, "!"):
		return fmt.Errorf("pattern %q: negation is not supported; name the files to review anyway in trigger_paths", pattern)
	case strings.Contains(pattern, "**"):
		return fmt.Errorf("pattern %q: \"**\" is not supported; a pattern without a slash already matches at any depth, and a trailing slash matches everything beneath a directory", pattern)
	}
	for segment := range strings.SplitSeq(strings.Trim(pattern, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("pattern %q: must be a path from the repository root, without empty, \".\" or \"..\" segments", pattern)
		}
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("pattern %q: %w", pattern, err)
	}
	return nil
}
