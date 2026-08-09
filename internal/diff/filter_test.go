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
		NarrowAbove:   5,
		ExtraPatterns: []string{"widgets/wa.go"},
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
		ExtraPatterns: []string{"docs/threat-notes.md"},
	})
	if len(result.Kept) != 2 {
		t.Errorf("kept %v, want the explicitly named doc plus main.go", paths(result.Kept))
	}
}
