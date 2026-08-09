package model

import "testing"

// threatcl/spec discards source ranges, so these line numbers are the only
// thing standing between a finding and a fabricated citation. The fixture is
// testdata/simple.tm.hcl; update both together.
func TestLineIndexAddresses(t *testing.T) {
	a, err := Load("../../testdata/simple.tm.hcl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name    string
		address []string
		want    int
	}{
		{"threatmodel", []string{"threatmodel", "simple"}, 3},
		{"information asset", []string{"threatmodel", "simple", "information_asset", "user credentials"}, 7},
		{"threat", []string{"threatmodel", "simple", "threat", "credential stuffing"}, 12},
		{"nested control", []string{"threatmodel", "simple", "threat", "credential stuffing", "control", "login rate limiting"}, 17},
		{"third party dependency", []string{"threatmodel", "simple", "third_party_dependency", "identity provider"}, 23},
	}
	for _, tt := range tests {
		if got := a.Lines.Line(tt.address...); got != tt.want {
			t.Errorf("%s line = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// An unknown block must resolve to 0 so callers can omit the citation rather
// than print a misleading line number.
func TestLineIndexUnknownAddressIsZero(t *testing.T) {
	a, err := Load("../../testdata/simple.tm.hcl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := a.Lines.Line("threatmodel", "simple", "threat", "does not exist"); got != 0 {
		t.Errorf("unknown address line = %d, want 0", got)
	}
	var nilIndex *LineIndex
	if got := nilIndex.Line("threatmodel", "simple"); got != 0 {
		t.Errorf("nil index line = %d, want 0", got)
	}
}

// Citations must be repo-relative: a runner-absolute path resolves to nothing
// for a developer reading the PR.
func TestLoadInKeepsRelativeSource(t *testing.T) {
	a, err := LoadIn("../../testdata", "simple.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	if a.Source != "simple.tm.hcl" {
		t.Errorf("Source = %q, want the repo-relative path", a.Source)
	}
	if got := a.Lines.Path(); got != "simple.tm.hcl" {
		t.Errorf("LineIndex.Path = %q, want the repo-relative path", got)
	}
	if got := a.Lines.Line("threatmodel", "simple"); got != 3 {
		t.Errorf("line index should still work off the real file, got %d", got)
	}
}
