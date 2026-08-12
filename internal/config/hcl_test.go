package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), DefaultConfigPath)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestLoadFileOverlays(t *testing.T) {
	path := writeConfig(t, `
model_paths   = ["threatmodels/payments.hcl"]
categories    = ["phantom_control", "dependency_drift"]
trigger_paths = ["src/payments/"]
fail_mode     = "on-action-required"

llm {
  provider = "anthropic"
  model    = "claude-sonnet-5"
  effort   = "medium"
}

limits {
  max_diff_files = 50
}
`)

	cfg, err := Default().LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if len(cfg.ModelPaths) != 1 || cfg.ModelPaths[0] != "threatmodels/payments.hcl" {
		t.Errorf("ModelPaths = %v", cfg.ModelPaths)
	}
	if cfg.FailMode != FailOnActionRequired {
		t.Errorf("FailMode = %q", cfg.FailMode)
	}
	if cfg.Model != "claude-sonnet-5" || cfg.Effort != "medium" {
		t.Errorf("llm = %q/%q", cfg.Model, cfg.Effort)
	}
	if cfg.MaxDiffFiles != 50 {
		t.Errorf("MaxDiffFiles = %d", cfg.MaxDiffFiles)
	}
	// Unset fields keep their defaults rather than zeroing out.
	if cfg.MaxPatchBytes != Default().MaxPatchBytes {
		t.Errorf("MaxPatchBytes = %d, want default", cfg.MaxPatchBytes)
	}
	if cfg.APIKeyEnv != Default().APIKeyEnv {
		t.Errorf("APIKeyEnv = %q, want default", cfg.APIKeyEnv)
	}
}

func TestLoadFileMissingIsNotAnError(t *testing.T) {
	cfg, err := Default().LoadFile(filepath.Join(t.TempDir(), "absent.hcl"))
	if err != nil {
		t.Fatalf("missing config should not error: %v", err)
	}
	if cfg.Model != Default().Model {
		t.Errorf("defaults not preserved: %+v", cfg)
	}
}

// A typo must fail loudly. Silently ignoring an unknown category would
// disable a drift check without anyone noticing.
func TestLoadFileRejectsBadValues(t *testing.T) {
	tests := []struct {
		name, body, wantErr string
	}{
		{"unknown category", `categories = ["phantom_controls"]`, "unknown drift category"},
		{"bad fail mode", `fail_mode = "always"`, "fail_mode must be"},
		// vertex, not openai: openai is accepted now, and the point of this
		// case is a provider the engine has no implementation for.
		{"unknown provider", `llm { provider = "vertex" }`, "llm.provider must be"},
		{"bad effort", `llm { effort = "extreme" }`, "llm.effort must be"},
		{"malformed hcl", `fail_mode = `, "parsing"},
		{"unknown attribute", `not_a_setting = true`, "decoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Default().LoadFile(writeConfig(t, tt.body))
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// Action inputs are the highest-precedence layer, above the config file.
func TestEnvBeatsFile(t *testing.T) {
	path := writeConfig(t, `
fail_mode = "never"
llm { model = "claude-sonnet-5" }
`)
	t.Setenv("INPUT_MODEL", "claude-opus-5")
	t.Setenv("INPUT_FAIL-MODE", FailOnActionRequired)

	cfg, err := Default().LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	cfg, err = cfg.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}

	if cfg.Model != "claude-opus-5" {
		t.Errorf("Model = %q, want the input to win", cfg.Model)
	}
	if cfg.FailMode != FailOnActionRequired {
		t.Errorf("FailMode = %q, want the input to win", cfg.FailMode)
	}
}

func TestCategoryEnabled(t *testing.T) {
	all := Default()
	if !all.CategoryEnabled("dfd_drift") {
		t.Error("empty category list should enable everything")
	}

	limited := Config{Categories: []string{"dependency_drift"}}
	if !limited.CategoryEnabled("dependency_drift") {
		t.Error("listed category should be enabled")
	}
	if limited.CategoryEnabled("dfd_drift") {
		t.Error("unlisted category should be disabled")
	}
}
