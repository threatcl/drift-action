package config

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// fileConfig mirrors the .threatcl-ci.hcl schema. Every field is optional so
// a partial config file layers cleanly over the defaults.
type fileConfig struct {
	ModelPaths   []string     `hcl:"model_paths,optional"`
	Categories   []string     `hcl:"categories,optional"`
	TriggerPaths []string     `hcl:"trigger_paths,optional"`
	FailMode     string       `hcl:"fail_mode,optional"`
	LLM          *llmBlock    `hcl:"llm,block"`
	Limits       *limitsBlock `hcl:"limits,block"`
}

type llmBlock struct {
	Provider  string `hcl:"provider,optional"`
	Model     string `hcl:"model,optional"`
	Effort    string `hcl:"effort,optional"`
	MaxTokens int    `hcl:"max_tokens,optional"`
	APIKeyEnv string `hcl:"api_key_env,optional"`
}

type limitsBlock struct {
	MaxDiffFiles    int `hcl:"max_diff_files,optional"`
	MaxPatchBytes   int `hcl:"max_patch_bytes,optional"`
	MaxContextBytes int `hcl:"max_context_bytes,optional"`
	NarrowAbove     int `hcl:"narrow_above,optional"`
}

// LoadFile overlays the config file at path onto c. A missing file is not an
// error — the defaults stand. A malformed file is, so a typo never silently
// disables a drift category.
func (c Config) LoadFile(path string) (Config, error) {
	src, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("reading %s: %w", path, err)
	}

	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL(src, path)
	if diags.HasErrors() {
		return c, fmt.Errorf("parsing %s: %s", path, diags.Error())
	}

	var fc fileConfig
	if diags := gohcl.DecodeBody(f.Body, nil, &fc); diags.HasErrors() {
		return c, fmt.Errorf("decoding %s: %s", path, diags.Error())
	}

	return c.apply(fc, path)
}

func (c Config) apply(fc fileConfig, path string) (Config, error) {
	if len(fc.ModelPaths) > 0 {
		c.ModelPaths = fc.ModelPaths
	}
	if len(fc.Categories) > 0 {
		for _, category := range fc.Categories {
			if !knownCategory(category) {
				return c, fmt.Errorf("%s: unknown drift category %q", path, category)
			}
		}
		c.Categories = fc.Categories
	}
	if len(fc.TriggerPaths) > 0 {
		c.TriggerPaths = fc.TriggerPaths
	}
	if fc.FailMode != "" {
		if fc.FailMode != FailNever && fc.FailMode != FailOnActionRequired {
			return c, fmt.Errorf("%s: fail_mode must be %q or %q, got %q",
				path, FailNever, FailOnActionRequired, fc.FailMode)
		}
		c.FailMode = fc.FailMode
	}
	if fc.LLM != nil {
		if fc.LLM.Provider != "" {
			if !knownProvider(fc.LLM.Provider) {
				return c, fmt.Errorf(
					"%s: llm.provider must be \"anthropic\" (v0 supports anthropic only), got %q",
					path, fc.LLM.Provider)
			}
			c.Provider = fc.LLM.Provider
		}
		if fc.LLM.Model != "" {
			c.Model = fc.LLM.Model
		}
		if fc.LLM.Effort != "" {
			if !knownEffort(fc.LLM.Effort) {
				return c, fmt.Errorf(
					"%s: llm.effort must be low, medium, high, xhigh or max, got %q",
					path, fc.LLM.Effort)
			}
			c.Effort = fc.LLM.Effort
		}
		if fc.LLM.MaxTokens > 0 {
			c.MaxTokens = fc.LLM.MaxTokens
		}
		if fc.LLM.APIKeyEnv != "" {
			c.APIKeyEnv = fc.LLM.APIKeyEnv
		}
	}
	if fc.Limits != nil {
		if fc.Limits.MaxDiffFiles > 0 {
			c.MaxDiffFiles = fc.Limits.MaxDiffFiles
		}
		if fc.Limits.MaxPatchBytes > 0 {
			c.MaxPatchBytes = fc.Limits.MaxPatchBytes
		}
		if fc.Limits.MaxContextBytes > 0 {
			c.MaxContextBytes = fc.Limits.MaxContextBytes
		}
		if fc.Limits.NarrowAbove > 0 {
			c.NarrowAbove = fc.Limits.NarrowAbove
		}
	}
	return c, nil
}

// knownProvider fails a provider typo at config time, like every other enum
// here — main's provider switch would otherwise catch it only at review time,
// after the diff has already been fetched.
func knownProvider(provider string) bool {
	switch provider {
	case "anthropic":
		return true
	}
	return false
}

// knownEffort keeps a typo from reaching the API as a 400 mid-run, after the
// diff has already been fetched.
func knownEffort(effort string) bool {
	switch effort {
	case "low", "medium", "high", "xhigh", "max":
		return true
	}
	return false
}

// knownCategory keeps config typos from silently disabling a category. The
// list mirrors internal/findings.Categories; it is duplicated here rather than
// imported so config stays free of engine dependencies.
func knownCategory(category string) bool {
	switch category {
	case "stale_assertion", "phantom_control", "unmodeled_surface",
		"dfd_drift", "dependency_drift", "unclassified_data":
		return true
	}
	return false
}
