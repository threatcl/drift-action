package config

import (
	"path/filepath"
	"strings"
	"testing"
)

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

// TestProviderSwitchRederivesDefaults pins the wrinkle that made per-provider
// defaults necessary: the model and API key env follow from the provider, but
// the provider is not known until the config file has been read. Selecting one
// and saying nothing else must not leave the previous provider's model behind.
func TestProviderSwitchRederivesDefaults(t *testing.T) {
	cfg, err := Default().LoadFile(writeConfig(t, `llm { provider = "openai" }`))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Provider != ProviderOpenAI {
		t.Errorf("provider = %q, want %q", cfg.Provider, ProviderOpenAI)
	}
	if cfg.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("api_key_env = %q — the Anthropic default survived the switch", cfg.APIKeyEnv)
	}
	if cfg.Model != "" {
		t.Errorf("model = %q, want empty: openai has no verified default model", cfg.Model)
	}
	// That empty model is refused before a diff is ever fetched.
	if err := cfg.validate(); err == nil {
		t.Error("a provider with no model must not validate")
	}
}

// TestProviderSwitchKeepsExplicitChoices: the file's own llm.model and
// llm.api_key_env are applied after the re-derive, so an explicit choice wins.
func TestProviderSwitchKeepsExplicitChoices(t *testing.T) {
	cfg, err := Default().LoadFile(writeConfig(t, `
llm {
  provider    = "openai"
  model       = "chosen-model"
  api_key_env = "MY_OPENAI_KEY"
}`))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Model != "chosen-model" {
		t.Errorf("model = %q, want the explicitly configured one", cfg.Model)
	}
	if cfg.APIKeyEnv != "MY_OPENAI_KEY" {
		t.Errorf("api_key_env = %q, want the explicitly configured one", cfg.APIKeyEnv)
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("an explicitly configured provider should validate: %v", err)
	}
}

// TestLoadKeepsInputModelAboveProviderSwitch is why FromEnv runs twice inside
// Load. A single pass would have the file's provider switch re-derive the
// model on top of the model input, silently ignoring it.
func TestLoadKeepsInputModelAboveProviderSwitch(t *testing.T) {
	workspace := filepath.Dir(writeConfig(t, `llm { provider = "openai" }`))
	t.Setenv("INPUT_MODEL", "model-from-input")

	cfg, err := Load(workspace)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Model != "model-from-input" {
		t.Errorf("model = %q, want the action input to win over the provider default", cfg.Model)
	}
	if cfg.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("api_key_env = %q, want the switched provider's default", cfg.APIKeyEnv)
	}
}

// TestLoadRejectsProviderWithNoModel checks the refusal end to end, through
// the same entry point the action uses.
func TestLoadRejectsProviderWithNoModel(t *testing.T) {
	workspace := filepath.Dir(writeConfig(t, `llm { provider = "openai" }`))

	_, err := Load(workspace)
	if err == nil {
		t.Fatal("expected an error: openai has no default model")
	}
	if !strings.Contains(err.Error(), "llm.model must be set") {
		t.Errorf("error = %v, want it to name the missing setting", err)
	}
}

// TestLoadWithoutConfigFile: a repo with no .threatcl-ci.hcl gets a complete,
// valid config rather than a half-built one.
func TestLoadWithoutConfigFile(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("a missing config file must not be an error: %v", err)
	}
	if cfg.Provider != ProviderAnthropic || cfg.Model == "" || cfg.APIKeyEnv == "" {
		t.Errorf("incomplete default config: %q/%q/%q", cfg.Provider, cfg.Model, cfg.APIKeyEnv)
	}
}
