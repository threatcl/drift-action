package diff

import "testing"

func paths(changes []Change) []string {
	out := make([]string, 0, len(changes))
	for _, change := range changes {
		out = append(out, change.Path)
	}
	return out
}

func changesFor(pathList ...string) []Change {
	out := make([]Change, 0, len(pathList))
	for _, p := range pathList {
		out = append(out, Change{Path: p})
	}
	return out
}

func kept(t *testing.T, result Result, want ...string) {
	t.Helper()
	got := paths(result.Kept)
	if len(got) != len(want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("kept %v, want %v", got, want)
		}
	}
}

// The regression this file exists for: ordinary source files were being
// discarded because their names contained no security keyword, so a PR that
// rewrote a server and a data store was reviewed as zero files.
func TestSmallDiffKeepsOrdinarySourceFiles(t *testing.T) {
	result := Filter(changesFor(
		"README.md",
		"growatt/store.go",
		"server/server.go",
	), Options{})

	kept(t, result, "growatt/store.go", "server/server.go")
	if result.Noise != 1 {
		t.Errorf("Noise = %d, want 1 (the README)", result.Noise)
	}
	if result.Narrowed {
		t.Error("a three-file diff must not be narrowed")
	}
}

func TestSmallDiffKeepsUnremarkableNames(t *testing.T) {
	result := Filter(changesFor(
		"internal/db.go", "pkg/client.go", "cmd/main.go", "widget.go", "a/b/c.rb",
	), Options{})

	if len(result.Kept) != 5 {
		t.Errorf("kept %v, want all five", paths(result.Kept))
	}
}

func TestNoiseIsAlwaysDropped(t *testing.T) {
	result := Filter(changesFor(
		"docs/guide.md",
		"vendor/foo/bar.go",
		"web/node_modules/left-pad/index.js",
		"assets/logo.svg",
		"go.sum",
		"package-lock.json",
		"api/schema.pb.go",
		"dist/bundle.min.js",
		"internal/auth/login.go",
	), Options{})

	kept(t, result, "internal/auth/login.go")
	if result.Noise != 8 {
		t.Errorf("Noise = %d, want 8", result.Noise)
	}
}

// Manifests drive the deterministic dependency check, so they survive every
// rule — including the ones that would otherwise catch them.
func TestManifestsAlwaysSurvive(t *testing.T) {
	result := Filter(changesFor("go.mod", "package.json", "requirements.txt"), Options{})
	if len(result.Kept) != 3 {
		t.Errorf("kept %v, want all three manifests", paths(result.Kept))
	}

	// And again under narrowing, where the keyword rules apply.
	big := changesFor("go.mod", "requirements.txt")
	for i := range 60 {
		big = append(big, Change{Path: "pkg/thing" + string(rune('a'+i%26)) + ".go"})
	}
	narrowed := Filter(big, Options{NarrowAbove: 10})
	if !narrowed.Narrowed {
		t.Fatal("expected narrowing")
	}
	found := map[string]bool{}
	for _, change := range narrowed.Kept {
		found[change.Path] = true
	}
	if !found["go.mod"] || !found["requirements.txt"] {
		t.Errorf("manifests dropped by narrowing: %v", paths(narrowed.Kept))
	}
}

func TestLargeDiffNarrowsAndReportsIt(t *testing.T) {
	changes := changesFor(
		"internal/auth/login.go",
		"internal/httpserver/routes.go",
		"deploy/values.yaml",
		"internal/db.go",
	)
	// Pad past the threshold with files carrying no security signal.
	for i := range 20 {
		changes = append(changes, Change{Path: "widgets/w" + string(rune('a'+i)) + ".go"})
	}

	result := Filter(changes, Options{NarrowAbove: 10})

	if !result.Narrowed {
		t.Fatal("a 24-file diff above the threshold should narrow")
	}
	if result.NarrowedOut != 20 {
		t.Errorf("NarrowedOut = %d, want 20", result.NarrowedOut)
	}
	kept(t, result,
		"internal/auth/login.go",
		"internal/httpserver/routes.go",
		"deploy/values.yaml",
		"internal/db.go",
	)
}

// Paths the model's prose names, and configured trigger paths, must survive
// narrowing even when they look unremarkable.
func TestExtraPatternsSurviveNarrowing(t *testing.T) {
	changes := changesFor("growatt/store.go", "billing/charge.go")
	for i := range 20 {
		changes = append(changes, Change{Path: "widgets/w" + string(rune('a'+i)) + ".go"})
	}

	result := Filter(changes, Options{
		NarrowAbove: 5,
		References:  []string{"widgets/wa.go"},
	})

	found := map[string]bool{}
	for _, change := range result.Kept {
		found[change.Path] = true
	}
	if !found["widgets/wa.go"] {
		t.Errorf("model-referenced path dropped by narrowing: %v", paths(result.Kept))
	}
}

func TestExtraPatternForms(t *testing.T) {
	tests := []struct {
		path, pattern string
		want          bool
	}{
		{"src/payments/refund.go", "src/payments/", true},
		{"src/other/refund.go", "src/payments/", false},
		{"cmd/main.go", "cmd/*.go", true},
		{"internal/mw/rate.go", "internal/mw/rate.go", true},
		// A bare filename from the model's prose matches wherever it sits.
		{"internal/mw/rate.go", "rate.go", true},
		{"internal/mw/other.go", "rate.go", false},
	}
	for _, tt := range tests {
		if got := matchesAny(tt.path, []string{tt.pattern}); got != tt.want {
			t.Errorf("matchesAny(%q, %q) = %t, want %t", tt.path, tt.pattern, got, tt.want)
		}
	}
}

// Noise stays noise even under narrowing, and an explicitly named noise file
// is still honoured.
func TestExtraPatternRescuesNoise(t *testing.T) {
	result := Filter(changesFor("docs/threat-notes.md", "main.go"), Options{
		TriggerPatterns: []string{"docs/threat-notes.md"},
	})
	if len(result.Kept) != 2 {
		t.Errorf("kept %v, want the explicitly named doc plus main.go", paths(result.Kept))
	}
}

func TestIgnorePatternsExclude(t *testing.T) {
	result := Filter(changesFor(
		"server/server.go",
		"generated/client.go",
		"generated/README.md",
		"examples/shop/package.json",
	), Options{IgnorePatterns: []string{"generated/", "examples/"}})

	kept(t, result, "server/server.go")
	// A file that was noise anyway counts as noise: Ignored names only what
	// the exclusion itself took out.
	if result.Noise != 1 {
		t.Errorf("Noise = %d, want 1 (the README)", result.Noise)
	}
	// A manifest is never noise, but an explicit exclusion still reaches it.
	if got := result.Ignored; len(got) != 2 || got[0] != "generated/client.go" || got[1] != "examples/shop/package.json" {
		t.Errorf("Ignored = %v, want the client and the example manifest", got)
	}
}

// trigger_paths is "always review", so it beats an exclusion — which is also
// how a repo carves an exception out of an ignored directory. The model's
// prose references do not: they match loosely, and a bare "client.go" would
// defeat the exclusion everywhere.
func TestTriggerBeatsIgnoreButReferencesDoNot(t *testing.T) {
	result := Filter(changesFor(
		"generated/routes.go",
		"generated/client.go",
	), Options{
		IgnorePatterns:  []string{"generated/"},
		TriggerPatterns: []string{"generated/routes.go"},
		References:      []string{"client.go"},
	})

	kept(t, result, "generated/routes.go")
	if len(result.Ignored) != 1 || result.Ignored[0] != "generated/client.go" {
		t.Errorf("Ignored = %v, want the referenced-but-ignored client", result.Ignored)
	}
}

// Excluded files are gone before the narrowing threshold is counted, so a
// diff that is mostly generated code is reviewed whole rather than narrowed.
func TestIgnoredFilesDoNotCountTowardsNarrowing(t *testing.T) {
	changes := changesFor("widgets/handler.go", "widgets/view.go")
	for i := range 20 {
		changes = append(changes, Change{Path: "gen/m" + string(rune('a'+i)) + ".go"})
	}

	result := Filter(changes, Options{NarrowAbove: 5, IgnorePatterns: []string{"gen/"}})

	if result.Narrowed {
		t.Errorf("narrowed with only two reviewable files: kept %v", paths(result.Kept))
	}
	kept(t, result, "widgets/handler.go", "widgets/view.go")
	if len(result.Ignored) != 20 {
		t.Errorf("Ignored %d files, want 20", len(result.Ignored))
	}
}

func TestGeneratedHeaderIsNoise(t *testing.T) {
	header := map[string]bool{
		"db/queries.go":   true,
		"mocks/store.go":  true,
		"api/handlers.go": true,
	}
	var asked []string
	result := Filter(changesFor(
		"db/queries.go",
		"mocks/store.go",
		"api/handlers.go",
		"auth/session.go",
		"docs/guide.md",
		"gen/thing.go",
	), Options{
		// Named by the model's prose, so reviewed whatever its header says.
		References:     []string{"api/handlers.go"},
		IgnorePatterns: []string{"gen/"},
		Generated: func(p string) bool {
			asked = append(asked, p)
			return header[p]
		},
	})

	kept(t, result, "api/handlers.go", "auth/session.go")
	if result.Noise != 3 {
		t.Errorf("Noise = %d, want 3 (two generated, one doc)", result.Noise)
	}
	if got := result.Generated; len(got) != 2 || got[0] != "db/queries.go" || got[1] != "mocks/store.go" {
		t.Errorf("Generated = %v, want the two header-marked files", got)
	}
	// The header check reads the file, so it runs last: never for a file
	// already settled by name, by exclusion, or by the model naming it.
	for _, p := range asked {
		if p == "docs/guide.md" || p == "gen/thing.go" || p == "api/handlers.go" {
			t.Errorf("header check ran for %s, which was already settled", p)
		}
	}
}
