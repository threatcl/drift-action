package diff

import (
	"path"
	"strings"
)

// DefaultNarrowAbove is the number of changed files below which nothing is
// narrowed away. Filtering exists to keep a huge diff within budget, not to
// pre-judge which files matter: the claude-plugin narrows only when a diff runs
// to hundreds of files, and a small PR is cheap to review whole. Below this
// threshold the only thing removed is noise.
const DefaultNarrowAbove = 50

// Options configures filtering.
type Options struct {
	// ExtraPatterns are paths the caller already knows matter: trigger_paths
	// from config, and paths the threat model's prose references. They survive
	// narrowing unconditionally. A pattern ending in "/" matches by prefix,
	// otherwise it is matched with path.Match.
	ExtraPatterns []string
	// NarrowAbove overrides DefaultNarrowAbove. Zero means use the default.
	NarrowAbove int
}

// Result is what survived filtering, and what did not.
type Result struct {
	Kept []Change
	// Noise counts files removed as documentation, lock files, vendored or
	// generated code — content that cannot carry threat model drift.
	Noise int
	// Narrowed reports that the diff was large enough to require narrowing to
	// security-relevant paths, so coverage of this PR is partial and the
	// comment must say so.
	Narrowed bool
	// NarrowedOut counts source files narrowing removed.
	NarrowedOut int
}

// Filter reduces a diff to what is worth reviewing, in two stages. Noise is
// always removed. Everything else is kept unless the diff is too large, in
// which case it is narrowed to security-relevant paths and Narrowed is set.
//
// The default is to keep. An earlier version inverted this — keeping only
// paths whose name contained a security keyword — which silently discarded
// ordinary source files like server.go and store.go, exactly the code a drift
// review has to read.
func Filter(changes []Change, opts Options) Result {
	threshold := opts.NarrowAbove
	if threshold <= 0 {
		threshold = DefaultNarrowAbove
	}

	candidates := make([]Change, 0, len(changes))
	result := Result{}
	for _, change := range changes {
		if isNoise(change.Path) && !matchesAny(change.Path, opts.ExtraPatterns) {
			result.Noise++
			continue
		}
		candidates = append(candidates, change)
	}

	if len(candidates) <= threshold {
		result.Kept = candidates
		return result
	}

	kept := make([]Change, 0, len(candidates))
	for _, change := range candidates {
		if matchesAny(change.Path, opts.ExtraPatterns) || isSecurityRelevant(change.Path) {
			kept = append(kept, change)
		}
	}
	result.Kept = kept
	result.Narrowed = true
	result.NarrowedOut = len(candidates) - len(kept)
	return result
}

// Dependency manifests drive the deterministic dependency check and must never
// be filtered out, whatever else the rules say.
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

var noiseSegments = []string{"vendor", "node_modules", "dist", "build", "third_party", ".git"}

var noiseFilenames = map[string]bool{
	"package-lock.json": true,
	"pnpm-lock.yaml":    true,
	"go.work.sum":       true,
}

// Note the absence of .txt: requirements.txt is a manifest.
var noiseSuffixes = []string{
	".md", ".rst", ".adoc",
	".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf",
	".lock", ".sum", ".min.js", ".map", ".snap",
	".pb.go", "_generated.go", ".generated.go", "_pb2.py",
}

func isNoise(p string) bool {
	if manifestNames[path.Base(p)] {
		return false
	}
	lower := strings.ToLower(p)

	if noiseFilenames[path.Base(lower)] {
		return true
	}
	for _, segment := range noiseSegments {
		if strings.HasPrefix(lower, segment+"/") || strings.Contains(lower, "/"+segment+"/") {
			return true
		}
	}
	for _, suffix := range noiseSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// securitySubstrings mark paths worth keeping when a diff is too large to
// review whole. Matching is generous on purpose: under narrowing a false
// positive costs a few tokens, while a false negative silently hides drift.
var securitySubstrings = []string{
	"auth", "login", "logout", "session", "token", "secret", "password", "passwd",
	"credential", "crypt", "hash", "tls", "ssl", "cert", "jwt", "oauth", "saml",
	"acl", "permission", "privilege", "rbac", "role", "admin", "tenant",
	"handler", "route", "endpoint", "api", "middleware", "server", "client",
	"http", "grpc", "socket", "webhook", "gateway", "proxy", "ingress", "cors",
	"sql", "query", "database", "store", "storage", "repositor", "cache", "migrat",
	"config", "setting", "env", "secret", "deploy", "docker", "terraform",
	"upload", "download", "file", "path", "exec", "command", "shell", "process",
	"serial", "marshal", "parse", "template", "render", "sanitiz", "valid", "escape",
	"user", "account", "profile", "payment", "billing", "order", "invoice",
}

// securityTokens are matched as whole path segments. Short strings like "db"
// would hit half the tree as substrings.
var securityTokens = map[string]bool{"db": true, "id": true, "iam": true, "kms": true}

var configSuffixes = []string{".yml", ".yaml", ".toml", ".ini", ".conf", ".env", ".tf", ".hcl"}

func isSecurityRelevant(p string) bool {
	lower := strings.ToLower(p)

	if manifestNames[path.Base(p)] {
		return true
	}
	for _, suffix := range configSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	for _, keyword := range securitySubstrings {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	for _, token := range strings.FieldsFunc(lower, func(r rune) bool {
		return r == '/' || r == '.' || r == '_' || r == '-'
	}) {
		if securityTokens[token] {
			return true
		}
	}
	return false
}

func matchesAny(p string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(p, pattern) {
				return true
			}
			continue
		}
		if ok, _ := path.Match(pattern, p); ok {
			return true
		}
		// A bare path from the model's prose should match wherever it sits.
		if p == pattern || strings.HasSuffix(p, "/"+pattern) {
			return true
		}
	}
	return false
}
