package deps

import "testing"

func findDelta(deltas []Delta, name string) (Delta, bool) {
	for _, delta := range deltas {
		if delta.Name == name {
			return delta, true
		}
	}
	return Delta{}, false
}

func TestGoModDeltas(t *testing.T) {
	patch := `@@ -5,7 +5,8 @@ require (
 	github.com/threatcl/spec v0.7.0
+	github.com/getsentry/sentry-go v0.28.0
-	github.com/old/dep v1.4.0
-	github.com/bumped/lib v1.2.0
+	github.com/bumped/lib v2.0.0
+	golang.org/x/text v0.40.0 // indirect
 )
`
	deltas := Deltas("go.mod", patch)

	added, ok := findDelta(deltas, "github.com/getsentry/sentry-go")
	if !ok || !added.Added() || added.NewVersion != "v0.28.0" {
		t.Errorf("added delta = %+v", added)
	}
	removed, ok := findDelta(deltas, "github.com/old/dep")
	if !ok || !removed.Removed() {
		t.Errorf("removed delta = %+v", removed)
	}
	bumped, ok := findDelta(deltas, "github.com/bumped/lib")
	if !ok || !bumped.MajorBump() {
		t.Errorf("bumped delta = %+v, want a major bump", bumped)
	}
	// Indirect dependencies are transitive noise, not modelled surface.
	if _, ok := findDelta(deltas, "golang.org/x/text"); ok {
		t.Error("indirect dependency should be ignored")
	}
}

// devDependencies are tooling, not third-party attack surface.
func TestPackageJSONIgnoresDevDependencies(t *testing.T) {
	patch := `@@ -8,10 +8,12 @@
   "dependencies": {
     "express": "^4.18.0",
+    "stripe": "^14.0.0"
   },
   "devDependencies": {
+    "jest": "^29.0.0"
   }
`
	deltas := Deltas("package.json", patch)

	if _, ok := findDelta(deltas, "stripe"); !ok {
		t.Errorf("stripe should be reported, got %+v", deltas)
	}
	if _, ok := findDelta(deltas, "jest"); ok {
		t.Error("devDependencies should be ignored")
	}
}

func TestMajorBumpIsConservative(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		wantBump bool
	}{
		{"major change", "v1.2.0", "v2.0.0", true},
		{"minor change", "v1.2.0", "v1.9.0", false},
		{"caret ranges", "^4.18.0", "^14.0.0", true},
		{"unparseable old", "latest", "v2.0.0", false},
		{"unparseable new", "v1.0.0", "workspace:*", false},
		{"pseudo version", "v0.0.0-20240422174119-9fd32a8b3d3d", "v0.5.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delta := Delta{OldVersion: tt.old, NewVersion: tt.new}
			if got := delta.MajorBump(); got != tt.wantBump {
				t.Errorf("MajorBump(%q -> %q) = %t, want %t", tt.old, tt.new, got, tt.wantBump)
			}
		})
	}
}

func TestIsManifest(t *testing.T) {
	for _, path := range []string{"go.mod", "package.json", "web/package.json"} {
		if !IsManifest(path) {
			t.Errorf("IsManifest(%q) = false", path)
		}
	}
	for _, path := range []string{"go.sum", "package-lock.json", "internal/auth/login.go"} {
		if IsManifest(path) {
			t.Errorf("IsManifest(%q) = true", path)
		}
	}
}
