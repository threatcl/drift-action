// Package findings defines the drift report structure — the contract between
// LLM inference (forced JSON schema output), deterministic checks, and the
// renderers.
package findings

type Category string

const (
	CategoryStaleAssertion   Category = "stale_assertion"
	CategoryPhantomControl   Category = "phantom_control"
	CategoryUnmodeledSurface Category = "unmodeled_surface"
	CategoryDFDDrift         Category = "dfd_drift"
	CategoryDependencyDrift  Category = "dependency_drift"
	CategoryUnclassifiedData Category = "unclassified_data"
)

// Categories lists every drift category in render order.
var Categories = []Category{
	CategoryPhantomControl,
	CategoryStaleAssertion,
	CategoryUnmodeledSurface,
	CategoryDFDDrift,
	CategoryDependencyDrift,
	CategoryUnclassifiedData,
}

type Severity string

const (
	SeverityActionRequired    Severity = "action_required"
	SeverityReviewRecommended Severity = "review_recommended"
)

var Severities = []Severity{SeverityActionRequired, SeverityReviewRecommended}

// ModelExcerpt quotes the threat model assertion a finding is about.
type ModelExcerpt struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Quote string `json:"quote"`
}

// Evidence is one file:line citation from the diff or repo backing a finding.
type Evidence struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Note string `json:"note"`
}

type Relevance struct {
	Rating        string `json:"rating"` // strong | moderate | weak
	Justification string `json:"justification"`
}

type Finding struct {
	Category     Category     `json:"category"`
	Severity     Severity     `json:"severity"`
	Title        string       `json:"title"`
	ModelExcerpt ModelExcerpt `json:"model_excerpt"`
	Evidence     []Evidence   `json:"evidence"`
	Relevance    Relevance    `json:"relevance"`
	// AgentPrompt is a self-contained remediation prompt the developer can
	// paste into an AI coding agent to update the threat model.
	AgentPrompt  string `json:"agent_prompt"`
	SuggestedFix string `json:"suggested_fix"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	NoDrift       bool      `json:"no_drift"`
	Summary       string    `json:"summary"`
	Findings      []Finding `json:"findings"`
}
