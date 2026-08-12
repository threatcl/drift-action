package model

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// repoWith builds a throwaway repo root containing each named file.
func repoWith(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range files {
		path := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("# placeholder\n"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	return root
}

func TestDiscover(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  []string
	}{
		{
			name:  "root",
			files: []string{"payments.tm.hcl"},
			want:  []string{"payments.tm.hcl"},
		},
		{
			name:  "threatmodels directory",
			files: []string{"threatmodels/payments.tm.hcl"},
			want:  []string{"threatmodels/payments.tm.hcl"},
		},
		{
			name:  "threatmodels directory, bare .hcl",
			files: []string{"threatmodels/payments.hcl"},
			want:  []string{"threatmodels/payments.hcl"},
		},
		{
			// The org's ENISA worked example is a template repo laid out this
			// way, so anyone starting from it inherits the singular spelling.
			name:  "singular threatmodel directory",
			files: []string{"threatmodel/sensorhub.tm.hcl"},
			want:  []string{"threatmodel/sensorhub.tm.hcl"},
		},
		{
			name:  "singular threatmodel directory, bare .hcl",
			files: []string{"threatmodel/sensorhub.hcl"},
			want:  []string{"threatmodel/sensorhub.hcl"},
		},
		{
			name:  "config file is never a model",
			files: []string{".threatcl-ci.hcl", "threatmodels/.threatcl-ci.hcl", "threatmodel/.threatcl-ci.hcl"},
			want:  nil,
		},
		{
			// Bare *.hcl at the root is deliberately not globbed.
			name:  "unrelated root hcl ignored",
			files: []string{"main.hcl", "terraform.hcl"},
			want:  nil,
		},
		{
			name:  "nothing at all",
			files: nil,
			want:  nil,
		},
		{
			name:  "every location at once, deduped and sorted",
			files: []string{"root.tm.hcl", "threatmodels/plural.tm.hcl", "threatmodel/singular.tm.hcl", ".threatcl-ci.hcl"},
			want:  []string{"root.tm.hcl", "threatmodel/singular.tm.hcl", "threatmodels/plural.tm.hcl"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Discover(repoWith(t, tc.files...))
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			// Discover returns OS-native separators; compare on slash paths.
			slashed := make([]string, len(got))
			for i, g := range got {
				slashed[i] = filepath.ToSlash(g)
			}
			if len(slashed) == 0 {
				slashed = nil
			}
			if !reflect.DeepEqual(slashed, tc.want) {
				t.Errorf("Discover = %v, want %v", slashed, tc.want)
			}
		})
	}
}

// A *.tm.hcl under threatmodels/ matches two globs; it must be reported once.
func TestDiscoverDeduplicates(t *testing.T) {
	root := repoWith(t, "threatmodels/payments.tm.hcl", "threatmodel/sensorhub.tm.hcl")
	got, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("Discover = %v, want 2 files", got)
	}
}

func TestResolveConfiguredWins(t *testing.T) {
	// Configured paths are taken as given — no discovery, no existence check.
	root := repoWith(t, "root.tm.hcl", "threatmodel/singular.tm.hcl")
	got, err := Resolve(root, []string{"threatmodel/sensorhub.tm.hcl"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"threatmodel/sensorhub.tm.hcl"}) {
		t.Errorf("Resolve = %v, want the configured path", got)
	}
}

func TestResolveSingleMatch(t *testing.T) {
	root := repoWith(t, "threatmodel/sensorhub.tm.hcl", ".threatcl-ci.hcl")
	got, err := Resolve(root, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{filepath.FromSlash("threatmodel/sensorhub.tm.hcl")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Resolve = %v, want %v", got, want)
	}
}

func TestResolveNoModel(t *testing.T) {
	root := repoWith(t, ".threatcl-ci.hcl", "README.md")
	if _, err := Resolve(root, nil); !errors.Is(err, ErrNoModel) {
		t.Errorf("Resolve error = %v, want ErrNoModel", err)
	}
}

// Several models must not be guessed between: CI cannot ask, so the error has
// to name the fix.
func TestResolveAmbiguous(t *testing.T) {
	root := repoWith(t, "threatmodel/singular.tm.hcl", "threatmodels/plural.tm.hcl")
	_, err := Resolve(root, nil)
	if err == nil {
		t.Fatal("Resolve: want an error for multiple models, got nil")
	}
	if errors.Is(err, ErrNoModel) {
		t.Fatalf("Resolve error = %v, want the ambiguity error not ErrNoModel", err)
	}
	if !strings.Contains(err.Error(), "model_paths") {
		t.Errorf("Resolve error = %q, want it to name model_paths", err)
	}
	for _, want := range []string{"singular.tm.hcl", "plural.tm.hcl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Resolve error = %q, want it to list %s", err, want)
		}
	}
}
