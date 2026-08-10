package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/threatcl/drift-action/internal/diff"
)

// Fail modes accepted in config and the fail-mode action input.
const (
	FailNever            = "never"
	FailOnActionRequired = "on-action-required"
)

// DefaultConfigPath is the repo-relative location of the drift config file.
const DefaultConfigPath = ".threatcl-ci.hcl"

// Config carries the engine's settings. Resolution order: Default, overlaid
// by the repo's .threatcl-ci.hcl, overlaid by action inputs via FromEnv.
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
	// Effort is the model's reasoning effort: low | medium | high | xhigh | max.
	Effort string
	// MaxTokens caps the model's output. It covers thinking as well as the
	// findings array — too tight truncates the report mid-JSON.
	MaxTokens int
	// APIKeyEnv names the environment variable holding the provider API key.
	APIKeyEnv string
	// MaxDiffFiles caps how many files may be sent to inference, applied
	// after filtering and narrowing. Over it the run refuses outright — "diff
	// too large, run locally" — rather than reviewing a subset.
	MaxDiffFiles int
	// MaxPatchBytes budgets the rendered diff; files that do not fit are
	// omitted from the review and named in the comment.
	MaxPatchBytes int
	// MaxContextBytes caps the whole repo files sent alongside the diff.
	MaxContextBytes int
	// NarrowAbove is the changed-file count above which the diff is narrowed
	// to security-relevant paths. Below it every non-noise file is reviewed.
	NarrowAbove int
	// DryRun suppresses every GitHub write. The diff is still fetched and the
	// comment and check run are still rendered and logged — they are just
	// never posted. It does not change the verdict or the exit code.
	DryRun bool
}

func Default() Config {
	return Config{
		ConfigPath:      DefaultConfigPath,
		FailMode:        FailNever,
		Provider:        "anthropic",
		Model:           "claude-opus-5",
		Effort:          "high",
		MaxTokens:       32_000,
		APIKeyEnv:       "ANTHROPIC_API_KEY",
		MaxDiffFiles:    200,
		MaxPatchBytes:   400_000,
		MaxContextBytes: 200_000,
		NarrowAbove:     diff.DefaultNarrowAbove,
	}
}

// DryRunEnv is a shell-friendly alias for the dry-run input. The action input
// arrives as INPUT_DRY-RUN, and a hyphen cannot appear in a POSIX shell
// variable name, so local runs would otherwise need `env "INPUT_DRY-RUN=true"`.
const DryRunEnv = "THREATCL_DRIFT_DRY_RUN"

// FromEnv overlays the GitHub Actions input env vars onto cfg. Input env
// names contain hyphens (INPUT_CONFIG-PATH), which os.Getenv handles fine but
// POSIX shells cannot reference.
func (c Config) FromEnv() (Config, error) {
	if v := os.Getenv("INPUT_CONFIG-PATH"); v != "" {
		c.ConfigPath = v
	}
	if v := os.Getenv("INPUT_FAIL-MODE"); v != "" {
		c.FailMode = v
	}
	if v := os.Getenv("INPUT_MODEL"); v != "" {
		c.Model = v
	}

	dryRun, set, err := boolEnv("INPUT_DRY-RUN", DryRunEnv)
	if err != nil {
		return c, err
	}
	if set {
		c.DryRun = dryRun
	}
	return c, nil
}

// FromEnv overlays the action inputs onto the built-in defaults. Callers that
// also read a config file should use Default, LoadFile, then Config.FromEnv so
// the inputs stay the highest-precedence layer.
func FromEnv() (Config, error) {
	return Default().FromEnv()
}

// boolEnv reads the first variable that is set among names. An unparseable
// value is an error rather than a silent false: someone who sets
// THREATCL_DRIFT_DRY_RUN=yes believes nothing will be posted, and quietly
// posting a comment anyway is the worst thing this flag could do.
func boolEnv(names ...string) (value, set bool, err error) {
	for _, name := range names {
		raw := os.Getenv(name)
		if raw == "" {
			continue
		}
		parsed, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			return false, false, fmt.Errorf(
				"%s is %q, want a boolean (true or false)", name, raw)
		}
		return parsed, true, nil
	}
	return false, false, nil
}

// CategoryEnabled reports whether a drift category should be assessed. An
// empty Categories list means all six are enabled.
func (c Config) CategoryEnabled(category string) bool {
	if len(c.Categories) == 0 {
		return true
	}
	return slices.Contains(c.Categories, category)
}
