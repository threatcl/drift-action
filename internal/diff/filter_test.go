package diff

import "testing"

func TestFilterPaths(t *testing.T) {
	tests := []struct {
		path     string
		patterns []string
		want     bool
	}{
		{"go.mod", nil, true},
		{"package.json", nil, true},
		{"internal/auth/login.go", nil, true},
		{"app.tm.hcl", nil, true},
		{"deploy/config.yml", nil, true},
		{"docs/readme.md", nil, false},
		{"vendor/foo/go.mod", nil, false},
		{"node_modules/left-pad/index.js", nil, false},
		{"pkg/util/strings.go", nil, false},
		{"assets/logo.svg", nil, false},
		{"src/payments/refund.go", nil, false},
		{"src/payments/refund.go", []string{"src/payments/"}, true},
		{"cmd/main.go", []string{"cmd/*.go"}, true},
		{"cmd/other.txt", []string{"cmd/*.go"}, false},
	}
	for _, tt := range tests {
		got := FilterPaths([]Change{{Path: tt.path}}, tt.patterns)
		if kept := len(got) == 1; kept != tt.want {
			t.Errorf("keep(%q, %v) = %v, want %v", tt.path, tt.patterns, kept, tt.want)
		}
	}
}
