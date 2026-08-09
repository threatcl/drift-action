package llm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workspace(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, contents := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Only files that are both referenced by the model and touched by the diff are
// worth the tokens.
func TestSelectContextTakesTheIntersection(t *testing.T) {
	dir := workspace(t, map[string]string{
		"internal/auth/session.go":   "package auth",
		"internal/auth/untouched.go": "package auth",
		"internal/store/store.go":    "package store",
	})

	selection := SelectContext(dir,
		[]string{"internal/auth/session.go", "internal/auth/untouched.go"},
		[]string{"internal/auth/session.go", "internal/store/store.go"},
		0)

	if len(selection.Files) != 1 || selection.Files[0].Path != "internal/auth/session.go" {
		t.Fatalf("files = %+v", selection.Files)
	}
	if selection.Files[0].Contents != "package auth" {
		t.Errorf("contents = %q", selection.Files[0].Contents)
	}
}

// Model prose cites bare filenames as often as full paths.
func TestSelectContextMatchesBareFilenames(t *testing.T) {
	dir := workspace(t, map[string]string{"internal/auth/session.go": "package auth"})

	selection := SelectContext(dir, []string{"session.go"}, []string{"internal/auth/session.go"}, 0)
	if len(selection.Files) != 1 {
		t.Fatalf("files = %+v", selection.Files)
	}

	// A suffix match must be on a path segment, not on any substring.
	selection = SelectContext(dir, []string{"ssion.go"}, []string{"internal/auth/session.go"}, 0)
	if len(selection.Files) != 0 {
		t.Errorf("matched a partial filename: %+v", selection.Files)
	}
}

func TestSelectContextBudgets(t *testing.T) {
	dir := workspace(t, map[string]string{
		"a.go": strings.Repeat("a", 100),
		"b.go": strings.Repeat("b", 100),
	})
	paths := []string{"a.go", "b.go"}

	selection := SelectContext(dir, paths, paths, 150)
	if len(selection.Files) != 1 || selection.Files[0].Path != "a.go" {
		t.Fatalf("files = %+v", selection.Files)
	}
	// What did not fit has to be reportable: a control whose backing file was
	// silently dropped reads as a phantom control.
	if len(selection.Skipped) != 1 || selection.Skipped[0] != "b.go" {
		t.Errorf("skipped = %v, want [b.go]", selection.Skipped)
	}
	if selection.Bytes != 100 {
		t.Errorf("bytes = %d, want 100", selection.Bytes)
	}
}

func TestSelectContextSkipsUnreadableAndBinary(t *testing.T) {
	dir := workspace(t, map[string]string{"binary.go": "\xff\xfe\x00 not utf-8"})
	paths := []string{"binary.go", "missing.go"}

	selection := SelectContext(dir, paths, paths, 0)
	if len(selection.Files) != 0 {
		t.Fatalf("files = %+v, want none", selection.Files)
	}
	if len(selection.Skipped) != 2 {
		t.Errorf("skipped = %v, want both", selection.Skipped)
	}
}

// The engine must not read outside the checkout whatever path it is handed.
func TestSelectContextRefusesToEscapeTheWorkspace(t *testing.T) {
	dir := workspace(t, map[string]string{"inside.go": "ok"})
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "outside.go"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	escape := "../" + filepath.Base(filepath.Dir(dir)) + "/outside.go"
	selection := SelectContext(dir, []string{escape}, []string{escape}, 0)
	if len(selection.Files) != 0 {
		t.Fatalf("read outside the workspace: %+v", selection.Files)
	}
}
