package config

import (
	"fmt"
	"os"
	"path/filepath"
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

// Providers the engine can run inference through.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
)

// providerDefault holds the settings that follow from which provider is
// selected, rather than standing on their own.
type providerDefault struct {
	Model     string
	APIKeyEnv string
}

// providerDefaults is the one list of known providers: knownProvider reads it
// too, so adding a provider here is all it takes to make it configurable.
//
// These cannot simply be fixed in Default(). The provider is not known until
// the config file has been read, so a file that selects a different one has
// to re-derive them — otherwise selecting openai and saying nothing else
// leaves an Anthropic model name and ANTHROPIC_API_KEY in place, and the run
// fails at inference time with the diff already fetched.
var providerDefaults = map[string]providerDefault{
	ProviderAnthropic: {Model: "claude-opus-5", APIKeyEnv: "ANTHROPIC_API_KEY"},

	// Deliberately no default model. Structured-output support is
	// model-specific — the same reason CLAUDE.md says to verify it before
	// changing the Anthropic default — and no OpenAI model has been verified
	// against this engine's forced-JSON path yet. A guessed default would
	// fail at review time, after the diff has been fetched, so openai asks
	// for llm.model explicitly until a verified default ships with the
	// provider implementation.
	ProviderOpenAI: {APIKeyEnv: "OPENAI_API_KEY"},
}

// Config carries the engine's settings. Resolution order: Default, overlaid
// by the repo's .threatcl-ci.hcl, overlaid by action inputs via FromEnv.
type Config struct {
	// ConfigPath is the repo-relative path to the .threatcl-ci.hcl file.
	ConfigPath string
	// ModelPaths are the threat model files to assess. Empty means discover
	// (*.tm.hcl at repo root, then threatmodels/ and threatmodel/).
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
	cfg := Config{
		ConfigPath:      DefaultConfigPath,
		FailMode:        FailNever,
		Provider:        ProviderAnthropic,
		Effort:          "high",
		MaxTokens:       32_000,
		MaxDiffFiles:    200,
		MaxPatchBytes:   400_000,
		MaxContextBytes: 200_000,
		NarrowAbove:     diff.DefaultNarrowAbove,
	}
	// Complete, not half-built: a caller that uses Default() on its own — the
	// finding-quality corpus does — gets a config it can actually review with.
	return cfg.withProviderDefaults(ProviderAnthropic)
}

// WithProvider selects a provider and re-derives the settings that follow
// from it. An unknown name is refused here, so a typo cannot survive to
// review time with the diff already fetched.
func (c Config) WithProvider(provider string) (Config, error) {
	if !knownProvider(provider) {
		return c, fmt.Errorf("llm.provider must be %s, got %q", knownProviders(), provider)
	}
	if provider != c.Provider {
		c = c.withProviderDefaults(provider)
	}
	c.Provider = provider
	return c, nil
}

// withProviderDefaults sets the settings derived from provider. It overwrites
// rather than filling blanks, because it runs when the provider changes and
// the values it replaces belong to the provider being left behind. The config
// file's own llm.model and llm.api_key_env are applied after it, and the
// action inputs after those, so an explicit choice still wins.
func (c Config) withProviderDefaults(provider string) Config {
	defaults := providerDefaults[provider]
	c.Model = defaults.Model
	c.APIKeyEnv = defaults.APIKeyEnv
	return c
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
// also read a config file want Load, which layers all three in the right
// order and validates the result.
func FromEnv() (Config, error) {
	return Default().FromEnv()
}

// Load resolves the engine's configuration for the checkout at workspace:
// built-in defaults, overlaid by the repo's config file, overlaid by the
// action inputs — inputs are the highest-precedence layer.
//
// FromEnv runs twice on purpose. The first pass supplies config-path, which
// decides which file is read at all; the second restores input precedence
// over whatever that file set. The second pass also repairs the case a single
// pass gets wrong: a file that selects a different provider re-derives the
// model for it, and only a later input pass can put an explicit model input
// back on top of that.
//
// Validation happens here rather than in LoadFile because it needs the
// finished config — whether a model is set is not answerable until the last
// layer has been applied.
func Load(workspace string) (Config, error) {
	cfg, err := Default().FromEnv()
	if err != nil {
		return cfg, err
	}
	cfg, err = cfg.LoadFile(filepath.Join(workspace, cfg.ConfigPath))
	if err != nil {
		return cfg, err
	}
	cfg, err = cfg.FromEnv()
	if err != nil {
		return cfg, err
	}
	return cfg, cfg.validate()
}

// validate rejects a config that cannot produce a review. It runs before the
// diff is fetched: every check here is one a run would otherwise fail after
// spending a compare API call and, worse, after the reader has been told a
// review is in progress.
func (c Config) validate() error {
	if c.Model == "" {
		return fmt.Errorf(
			"llm.model must be set when llm.provider is %q: it has no default model, because structured-output support is model-specific and has to be verified per model",
			c.Provider)
	}
	return nil
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
