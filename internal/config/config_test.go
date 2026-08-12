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
	if cfg.Model == "claude-opus-5" {
		t.Error("the Anthropic default model survived the switch to openai")
	}
	if cfg.Model == "" {
		t.Error("openai should carry its own verified default model")
	}
}

// TestValidateRejectsProviderWithNoModel covers the provider added to
// providerDefaults without a verified model. Both shipped providers now carry
// one, so this exercises validate directly rather than through a real
// provider — the guard has to keep working for the next one added.
func TestValidateRejectsProviderWithNoModel(t *testing.T) {
	cfg := Default()
	cfg.Provider = "some-future-provider"
	cfg.Model = ""

	err := cfg.validate()
	if err == nil {
		t.Fatal("a provider with no model must not validate")
	}
	if !strings.Contains(err.Error(), "llm.model must be set") {
		t.Errorf("error = %v, want it to name the missing setting", err)
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

// TestLoadSelectsOpenAIWithoutAModel: selecting a provider is now the whole
// config change a repo needs, because both shipped providers carry a verified
// default model.
func TestLoadSelectsOpenAIWithoutAModel(t *testing.T) {
	workspace := filepath.Dir(writeConfig(t, `llm { provider = "openai" }`))

	cfg, err := Load(workspace)
	if err != nil {
		t.Fatalf("selecting openai alone should be enough: %v", err)
	}
	if cfg.Provider != ProviderOpenAI || cfg.Model == "" || cfg.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("incomplete openai config: %q/%q/%q", cfg.Provider, cfg.Model, cfg.APIKeyEnv)
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

// TestLoadRejectsBadFailModeInput closes the gap between the two config
// paths: LoadFile has always rejected an unknown fail_mode, but the action
// input reached FailMode unchecked, so a typo silently degraded to "never"
// and left the author believing their pull requests were gated.
func TestLoadRejectsBadFailModeInput(t *testing.T) {
	t.Setenv("INPUT_FAIL-MODE", "on-action-requried") // a plausible typo

	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("expected an error: a misspelled fail mode must not degrade to never")
	}
	if !strings.Contains(err.Error(), "fail_mode must be") {
		t.Errorf("error = %v, want it to name the setting", err)
	}
}

func TestLoadAcceptsBothFailModes(t *testing.T) {
	for _, mode := range []string{FailNever, FailOnActionRequired} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("INPUT_FAIL-MODE", mode)
			cfg, err := Load(t.TempDir())
			if err != nil {
				t.Fatalf("%q should be accepted: %v", mode, err)
			}
			if cfg.FailMode != mode {
				t.Errorf("fail mode = %q, want %q", cfg.FailMode, mode)
			}
		})
	}
}

// TestOpenAIDefaultModelIsVerified pins the default to the model the
// committed OpenAI recordings were made against. Changing it without
// re-recording would leave the corpus measuring a model the action no
// longer uses.
func TestOpenAIDefaultModelIsVerified(t *testing.T) {
	cfg, err := Default().WithProvider(ProviderOpenAI)
	if err != nil {
		t.Fatalf("selecting openai: %v", err)
	}
	if cfg.Model != "gpt-5.6-sol" {
		t.Errorf("openai default model = %q; if this changed deliberately, re-record the corpus", cfg.Model)
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("openai should now validate without an explicit model: %v", err)
	}
}
