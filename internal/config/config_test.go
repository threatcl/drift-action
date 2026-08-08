package config

import "testing"

func TestDefault(t *testing.T) {
	c := Default()
	if c.FailMode != FailNever {
		t.Errorf("default fail mode = %q, want %q", c.FailMode, FailNever)
	}
	if c.ConfigPath != ".threatcl-ci.hcl" {
		t.Errorf("default config path = %q", c.ConfigPath)
	}
	if c.Provider != "anthropic" || c.Model == "" {
		t.Errorf("default provider/model = %q/%q", c.Provider, c.Model)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("INPUT_CONFIG-PATH", "ci/drift.hcl")
	t.Setenv("INPUT_FAIL-MODE", FailOnActionRequired)
	t.Setenv("INPUT_MODEL", "claude-opus-5")

	c := FromEnv()
	if c.ConfigPath != "ci/drift.hcl" {
		t.Errorf("ConfigPath = %q", c.ConfigPath)
	}
	if c.FailMode != FailOnActionRequired {
		t.Errorf("FailMode = %q", c.FailMode)
	}
	if c.Model != "claude-opus-5" {
		t.Errorf("Model = %q", c.Model)
	}
}
