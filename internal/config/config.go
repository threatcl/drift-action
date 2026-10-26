package config

import (
	"fmt"
	"net"
	"net/url"
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

// Policy fail modes accepted in the cloud block. Separate from fail_mode: a
// repo will want both gates, and a third fail_mode value would make them
// exclusive.
const (
	PolicyFailNever               = "never"
	PolicyFailOnEnforcedViolation = "on-enforced-violation"
)

// Cloud-connected mode is turned on by the token and nothing else. Both names
// are the threatcl CLI's, already shell-friendly, so action.yml forwards the
// threatcl-api-token input as THREATCL_API_TOKEN and a local run sets it by
// hand.
//
// The API URL is read from the environment only, never from .threatcl-ci.hcl:
// that file arrives in the pull request under review, and a URL in it would
// let a pull request send the organisation's token to a host of its choosing.
const (
	CloudTokenEnv = "THREATCL_API_TOKEN"
	CloudURLEnv   = "THREATCL_API_URL"
	// DefaultCloudURL is the CLI's default host, baked in as the CLI bakes it.
	DefaultCloudURL = "https://beta-api.threatcl.com"
)

// Cloud holds the cloud {} block of .threatcl-ci.hcl. Declared records that
// the block was present at all: with no token in the run — a fork or
// Dependabot pull request — a repo that configured cloud mode is told it was
// not connected, while a repo that never did hears nothing about it.
type Cloud struct {
	Declared bool
	// Model is the cloud model slug the repo's files link to. It overrides a
	// backend block's threatmodel; the two contradicting is a hard error.
	Model string
	// PolicyFailMode decides whether an enforced policy violation fails the
	// check run.
	PolicyFailMode string
}

// DefaultConfigPath is the repo-relative location of the drift config file.
const DefaultConfigPath = ".threatcl-ci.hcl"

// Providers the engine can run inference through.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderGemini    = "gemini"
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

	// gpt-5.6-sol is the verified default, not a guess: it is the model the
	// committed OpenAI corpus recordings were made against, passing all seven
	// finding-quality cases including clean. Structured-output support is
	// model-specific, so changing this means re-recording the corpus and
	// re-reading the results, exactly as it does for the Anthropic default.
	ProviderOpenAI: {Model: "gpt-5.6-sol", APIKeyEnv: "OPENAI_API_KEY"},

	// gemini-3.8-flash is verified the same way: recorded against all seven
	// corpus cases (recording.gemini.json), passing every one including
	// clean, and agreeing with the other two providers on which cases are
	// action_required — which took a tightening of the prompt's severity
	// rule (prompts/ADAPTATIONS.md) to achieve. Changing it means
	// re-recording, as for the other two.
	//
	// GEMINI_API_KEY rather than GOOGLE_API_KEY: it is the name the Gemini
	// API documentation uses, and the one that cannot be mistaken for a GCP
	// credential.
	ProviderGemini: {Model: "gemini-3.8-flash", APIKeyEnv: "GEMINI_API_KEY"},
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
	// IgnorePaths exclude files from review on top of the built-in noise
	// rules. TriggerPaths win over them.
	IgnorePaths []string
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
	// DryRun suppresses every GitHub write and the cloud write-back. The diff
	// is still fetched, the cloud context is still read, and the comment and
	// check run are still rendered and logged — they are just never posted.
	// It does not change the verdict or the exit code.
	DryRun bool
	// Cloud is the cloud {} block. Whether cloud mode runs is decided by the
	// token in the environment (CloudTokenEnv), not by this block.
	Cloud Cloud
	// CloudURL is the Threatcl Cloud API base. Environment only, see
	// CloudURLEnv; https unless the host is loopback.
	CloudURL string
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
		Cloud:           Cloud{PolicyFailMode: PolicyFailNever},
		CloudURL:        DefaultCloudURL,
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
	if v := os.Getenv(CloudURLEnv); v != "" {
		c.CloudURL = v
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
	// Every shipped provider carries a verified default, so this fires only
	// for a provider added to providerDefaults without one. Keeping it means
	// that omission surfaces here rather than as an empty model reaching the
	// API with the diff already fetched.
	if c.Model == "" {
		return fmt.Errorf(
			"llm.model must be set when llm.provider is %q: it has no default model, because structured-output support is model-specific and has to be verified per model",
			c.Provider)
	}
	// The config-file path has always rejected a bad fail_mode; the action
	// input path did not, so a typo in the fail-mode input degraded silently
	// to "never". Someone who believes their pull requests are gated must
	// never be quietly ungated.
	if c.FailMode != FailNever && c.FailMode != FailOnActionRequired {
		return fmt.Errorf("fail_mode must be %q or %q, got %q",
			FailNever, FailOnActionRequired, c.FailMode)
	}
	if err := ValidateCloudURL(c.CloudURL); err != nil {
		return fmt.Errorf("%s: %w", CloudURLEnv, err)
	}
	return nil
}

// ValidateCloudURL accepts an https URL, or http to a loopback host for a
// local API. The token travels in every request to this host, so plain http
// anywhere else would put it on the wire in clear — and the host is the
// workflow's to set, never the pull request's.
func ValidateCloudURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%q must be an http(s) URL with a host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must carry no credentials, query or fragment", raw)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("%q is plain http to a non-loopback host; the API token would travel in clear", raw)
		}
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
