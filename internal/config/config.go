package config

import "os"

// Fail modes accepted in config and the fail-mode action input.
const (
	FailNever            = "never"
	FailOnActionRequired = "on-action-required"
)

// Config carries the engine's settings. Resolution order: Default, overlaid
// by the repo's .threatcl-ci.hcl (parsing not yet implemented), overlaid by
// action inputs via FromEnv.
type Config struct {
	// ConfigPath is the repo-relative path to the .threatcl-ci.hcl file.
	ConfigPath string
	// ModelPaths are the threat model files to assess. Empty means discover
	// (*.tm.hcl at repo root, then threatmodels/).
	ModelPaths []string
	// Categories are the enabled drift categories. Empty means all six.
	Categories []string
	// TriggerPaths extend the built-in security-relevant path heuristic.
	TriggerPaths []string
	// FailMode decides the check-run conclusion policy.
	FailMode string
	// Provider and Model select the LLM backend.
	Provider string
	Model    string
	// APIKeyEnv names the environment variable holding the provider API key.
	APIKeyEnv string
	// MaxDiffFiles and MaxPatchBytes cap what is sent to inference; beyond
	// them the run reports "diff too large" rather than silently truncating.
	MaxDiffFiles  int
	MaxPatchBytes int
}

func Default() Config {
	return Config{
		ConfigPath:    ".threatcl-ci.hcl",
		FailMode:      FailNever,
		Provider:      "anthropic",
		Model:         "claude-sonnet-5",
		APIKeyEnv:     "ANTHROPIC_API_KEY",
		MaxDiffFiles:  200,
		MaxPatchBytes: 400_000,
	}
}

// FromEnv overlays the GitHub Actions input env vars onto Default. Input env
// names contain hyphens (INPUT_CONFIG-PATH), which os.Getenv handles fine but
// POSIX shells cannot reference.
func FromEnv() Config {
	c := Default()
	if v := os.Getenv("INPUT_CONFIG-PATH"); v != "" {
		c.ConfigPath = v
	}
	if v := os.Getenv("INPUT_FAIL-MODE"); v != "" {
		c.FailMode = v
	}
	if v := os.Getenv("INPUT_MODEL"); v != "" {
		c.Model = v
	}
	return c
}
