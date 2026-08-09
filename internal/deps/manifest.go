package deps

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Entry is one dependency read out of a manifest diff.
type Entry struct {
	Name    string
	Version string
	File    string
	Line    int
}

// Delta is what happened to a single dependency across the diff.
type Delta struct {
	Name       string
	File       string
	OldVersion string
	NewVersion string
	Line       int
}

// Added reports a dependency that appears only in the post-image.
func (d Delta) Added() bool { return d.OldVersion == "" && d.NewVersion != "" }

// Removed reports a dependency that appears only in the pre-image.
func (d Delta) Removed() bool { return d.OldVersion != "" && d.NewVersion == "" }

// MajorBump reports a change that crosses a major version boundary. Versions
// that cannot be parsed are never treated as a bump — a false "major upgrade"
// finding on an unparseable version string is worse than a missed one.
func (d Delta) MajorBump() bool {
	if d.OldVersion == "" || d.NewVersion == "" {
		return false
	}
	oldMajor, ok := majorVersion(d.OldVersion)
	if !ok {
		return false
	}
	newMajor, ok := majorVersion(d.NewVersion)
	if !ok {
		return false
	}
	return oldMajor != newMajor
}

var majorPattern = regexp.MustCompile(`(\d+)`)

func majorVersion(version string) (int, bool) {
	m := majorPattern.FindStringSubmatch(version)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// IsManifest reports whether a path is a dependency manifest this package can
// read. Manifests we cannot parse are left to the LLM rather than guessed at.
func IsManifest(p string) bool {
	switch path.Base(p) {
	case "go.mod", "package.json":
		return true
	}
	return false
}

// Deltas reads a manifest patch and pairs up pre- and post-image entries.
func Deltas(file, patch string) []Delta {
	lines := ParsePatch(patch)

	var added, removed []Entry
	switch path.Base(file) {
	case "go.mod":
		added, removed = parseGoMod(file, lines)
	case "package.json":
		added, removed = parsePackageJSON(file, lines)
	default:
		return nil
	}

	byName := map[string]*Delta{}
	order := []string{}
	touch := func(name, file string) *Delta {
		if d, ok := byName[name]; ok {
			return d
		}
		d := &Delta{Name: name, File: file}
		byName[name] = d
		order = append(order, name)
		return d
	}
	for _, e := range removed {
		d := touch(e.Name, e.File)
		d.OldVersion = e.Version
	}
	for _, e := range added {
		d := touch(e.Name, e.File)
		d.NewVersion = e.Version
		d.Line = e.Line
	}

	deltas := make([]Delta, 0, len(order))
	for _, name := range order {
		deltas = append(deltas, *byName[name])
	}
	return deltas
}

// goModRequire matches a require-block entry: a module path followed by a
// version. Indirect dependencies are filtered by the caller — they are
// transitive and would drown the report.
var goModRequire = regexp.MustCompile(`^([a-zA-Z0-9][\w.\-]*(?:\.[\w.\-]+)+(?:/[\w.\-~]+)*)\s+(v[\w.\-+]+)`)

func parseGoMod(file string, lines []PatchLine) (added, removed []Entry) {
	for _, line := range lines {
		if line.Kind == Context {
			continue
		}
		text := strings.TrimSpace(line.Text)
		if strings.Contains(text, "// indirect") {
			continue
		}
		text = strings.TrimPrefix(text, "require ")
		text = strings.TrimPrefix(text, "replace ")
		if strings.HasPrefix(text, "//") {
			continue
		}

		m := goModRequire.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		entry := Entry{Name: m[1], Version: m[2], File: file, Line: line.Number}
		if line.Kind == Added {
			added = append(added, entry)
		} else {
			removed = append(removed, entry)
		}
	}
	return added, removed
}

var (
	jsonSection = regexp.MustCompile(`^"?(dependencies|devDependencies|peerDependencies|optionalDependencies)"?\s*:`)
	jsonDep     = regexp.MustCompile(`^"([^"]+)"\s*:\s*"([^"]+)"`)
)

// parsePackageJSON tracks which manifest section each changed line sits in by
// walking context lines too, so devDependencies can be ignored: a new test
// runner is not third-party surface worth modelling.
func parsePackageJSON(file string, lines []PatchLine) (added, removed []Entry) {
	section := ""
	for _, line := range lines {
		text := strings.TrimSpace(line.Text)

		if m := jsonSection.FindStringSubmatch(text); m != nil {
			section = m[1]
			continue
		}
		if text == "}" || text == "}," {
			section = ""
			continue
		}
		if section != "dependencies" || line.Kind == Context {
			continue
		}

		m := jsonDep.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		entry := Entry{Name: m[1], Version: m[2], File: file, Line: line.Number}
		if line.Kind == Added {
			added = append(added, entry)
		} else {
			removed = append(removed, entry)
		}
	}
	return added, removed
}
