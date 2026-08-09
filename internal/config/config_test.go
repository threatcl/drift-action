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

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
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

func TestDryRunFromActionInput(t *testing.T) {
	t.Setenv("INPUT_DRY-RUN", "true")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if !c.DryRun {
		t.Error("INPUT_DRY-RUN=true should enable dry run")
	}
}

// The hyphen in INPUT_DRY-RUN cannot be exported from a POSIX shell, so local
// runs need the alias.
func TestDryRunFromShellAlias(t *testing.T) {
	t.Setenv(DryRunEnv, "1")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if !c.DryRun {
		t.Errorf("%s=1 should enable dry run", DryRunEnv)
	}
}

func TestDryRunDefaultsOff(t *testing.T) {
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.DryRun {
		t.Error("dry run should be off unless asked for")
	}
}

// Silently treating an unparseable value as false would post a comment to
// someone who believed they had asked for a dry run.
func TestDryRunRejectsNonBoolean(t *testing.T) {
	t.Setenv(DryRunEnv, "yes")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected an error for a non-boolean dry-run value")
	}
}

func TestDryRunCanBeDisabledExplicitly(t *testing.T) {
	t.Setenv(DryRunEnv, "false")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.DryRun {
		t.Error("explicit false should not enable dry run")
	}
}
