package diff

import (
	"path"
	"strings"
)

// Dependency manifests always survive filtering — they drive the
// deterministic dependency-drift check.
var manifestNames = map[string]bool{
	"go.mod":           true,
	"package.json":     true,
	"requirements.txt": true,
	"Gemfile":          true,
	"Cargo.toml":       true,
	"pom.xml":          true,
	"build.gradle":     true,
	"composer.json":    true,
	"Pipfile":          true,
	"pyproject.toml":   true,
}

// securityKeywords marks path segments suggesting security-relevant code —
// the claude-plugin /threat-drift heuristic: auth, API handlers, data access,
// crypto, network, config.
var securityKeywords = []string{
	"auth", "login", "session", "token", "secret", "password", "crypt",
	"tls", "ssl", "cert", "acl", "permission", "rbac", "handler", "route",
	"endpoint", "api", "middleware", "sql", "storage", "config",
}

var configSuffixes = []string{".yml", ".yaml", ".toml", ".ini", ".conf"}

var skipPrefixes = []string{"vendor/", "node_modules/", "dist/", "third_party/"}

var skipSuffixes = []string{
	".md", ".svg", ".png", ".jpg", ".gif", ".lock", ".sum",
	".pb.go", "_generated.go", ".min.js",
}

// FilterPaths narrows changes to those worth drift-checking: dependency
// manifests, threat model files, security-suggestive paths, config files, and
// anything matching the extra patterns from repo config (a pattern ending in
// "/" matches by prefix, otherwise path.Match against the full path).
func FilterPaths(changes []Change, extraPatterns []string) []Change {
	var kept []Change
	for _, c := range changes {
		if keep(c.Path, extraPatterns) {
			kept = append(kept, c)
		}
	}
	return kept
}

func keep(p string, extraPatterns []string) bool {
	lower := strings.ToLower(p)
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	for _, pattern := range extraPatterns {
		if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(p, pattern) {
				return true
			}
		} else if ok, _ := path.Match(pattern, p); ok {
			return true
		}
	}
	for _, suffix := range skipSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	if manifestNames[path.Base(p)] {
		return true
	}
	if strings.HasSuffix(lower, ".hcl") {
		return true
	}
	for _, suffix := range configSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
