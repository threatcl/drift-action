package diff

import (
	"strings"
	"testing"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		path, pattern string
		want          bool
	}{
		// A directory with no other slash matches at any depth.
		{"generated/api.go", "generated/", true},
		{"pkg/api/generated/client.go", "generated/", true},
		{"pkg/generated.go", "generated/", false},
		{"generated", "generated/", false},
		// A directory with a slash in it is anchored at the root, and may glob.
		{"internal/gen/x.go", "internal/gen/", true},
		{"svc/internal/gen/x.go", "internal/gen/", false},
		{"services/billing/gen/x.go", "services/*/gen/", true},
		{"services/billing/v2/gen/x.go", "services/*/gen/", false},
		// A name with no slash matches the file name at any depth.
		{"a/b/models_gen.go", "*_gen.go", true},
		{"models_gen.go", "*_gen.go", true},
		{"a/b/models_gen.go/x.go", "*_gen.go", false},
		// Anything else is anchored at the root, and "*" stops at "/".
		{"cmd/main.go", "cmd/*.go", true},
		{"cmd/tool/main.go", "cmd/*.go", false},
		// A leading slash anchors what would otherwise match anywhere.
		{"Makefile", "/Makefile", true},
		{"tools/Makefile", "/Makefile", false},
		{"generated/x.go", "/generated/", true},
		{"pkg/generated/x.go", "/generated/", false},
		{"x.go", "/", false},
	}
	for _, tt := range tests {
		if got := matchPattern(tt.path, tt.pattern); got != tt.want {
			t.Errorf("matchPattern(%q, %q) = %t, want %t", tt.path, tt.pattern, got, tt.want)
		}
	}
}

// Exclusion is held to the pattern language alone. The suffix rule that lets
// model prose cite "mw/rate.go" for "internal/mw/rate.go" keeps files in
// review; applied to ignore_paths it would remove files nobody named.
func TestIgnoresHasNoSuffixRule(t *testing.T) {
	if !matchesAny("internal/mw/rate.go", []string{"mw/rate.go"}) {
		t.Error("a keep pattern should match a literal path as a suffix")
	}
	if ignores([]string{"mw/rate.go"}, "internal/mw/rate.go") {
		t.Error("an ignore pattern must not match a literal path as a suffix")
	}
}

func TestValidatePattern(t *testing.T) {
	for _, ok := range []string{
		"generated/", "*_gen.go", "/Makefile", "services/*/gen/", "api/schema.json", "[ab]_test.go",
	} {
		if err := ValidatePattern(ok); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want nil", ok, err)
		}
	}

	tests := []struct{ pattern, wantErr string }{
		{"", "empty"},
		{"  ", "empty"},
		{"!generated/", "negation"},
		{"**/generated/", `"**"`},
		{"generated/**", `"**"`},
		{"./generated/", "repository root"},
		{"../outside/", "repository root"},
		{"a//b", "repository root"},
		{"/", "repository root"},
		{"gen[/", "syntax error"},
	}
	for _, tt := range tests {
		err := ValidatePattern(tt.pattern)
		if err == nil {
			t.Errorf("ValidatePattern(%q) = nil, want an error", tt.pattern)
			continue
		}
		if !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("ValidatePattern(%q) = %v, want it to mention %s", tt.pattern, err, tt.wantErr)
		}
	}
}
