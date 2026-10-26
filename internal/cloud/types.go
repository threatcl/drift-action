// Package cloud is the Threatcl Cloud client for cloud-connected mode: one
// read of context about the pull request's threat model (alignment with the
// cloud copy, the organisation's policy verdict, the referenceable library)
// and one counts-only write-back after the review.
//
// Two rules bound it, and both are enforced by tests rather than convention.
// Cloud never receives source code or a diff: this package imports nothing
// from internal/diff, internal/llm, internal/findings or internal/deps — it
// imports nothing from this module at all — so it cannot be handed one
// (TestImportsNothingThatCarriesCode). And the write-back is integers and
// closed-set strings only: every string field of ReviewRecord carries an enum
// or pattern tag, and TestReviewRecordHasNoFreeText fails on one that does not.
//
// The JSON shapes are schema 1 of a bespoke contract with tcl-test, pinned on
// both sides by the goldens in testdata/ (see testdata/SOURCE). Alignment
// states and notes are closed sets today, but the server may add to them, so
// callers render an unknown value generically rather than failing.
package cloud

import "slices"

// SchemaV1 is the request and response schema version this client speaks.
const SchemaV1 = 1

// Alignment states. A segment's state places its base and head file hashes in
// the model's retained version history; a model's state is its most severe
// segment's, ordered conflict > behind > unsynced > ahead > aligned.
const (
	// StateAligned: base matches the current version and head equals base.
	StateAligned = "aligned"
	// StateAhead: base matches the current version and head differs — the PR
	// edits a model that was in sync.
	StateAhead = "ahead"
	// StateBehind: base matches an older version and head equals base — cloud
	// moved on since the repo last synced.
	StateBehind = "behind"
	// StateConflict: base matches an older version and head differs — both
	// sides moved.
	StateConflict = "conflict"
	// StateUnsynced: base is absent (a new file) or matches no retained
	// version — never pushed from a committed copy, or edited in the cloud
	// editor.
	StateUnsynced = "unsynced"
	// StateNotInCloud: the slug names no model in the token's organisation.
	StateNotInCloud = "not_in_cloud"
)

// Notes are per-model annotations from the server: link sanity checks and the
// reasons a part of the context could not be computed. They never refuse the
// request.
const (
	// NoteOrgMismatch: the request's backend_org differs from the token
	// organisation's slug. The model was still resolved in the token's org.
	NoteOrgMismatch = "org_mismatch"
	// NoteRepositoryMismatch: the model declares repositories and none matches
	// the request's repository.
	NoteRepositoryMismatch = "repository_mismatch"
	// NoteNoPolicies: the organisation has no enabled policies; policy is null.
	NoteNoPolicies = "no_policies"
	// NotePolicyUnavailable: the policies could not be evaluated against the
	// head set; policy is null. Distinct from "no violations".
	NotePolicyUnavailable = "policy_unavailable"
	// NoteNotInCloud accompanies alignment state not_in_cloud.
	NoteNotInCloud = "not_in_cloud"
	// NoteUnplacedFile is a prefix: the full note is "unplaced_file:<name>"
	// for a submitted file whose segment could not be derived. The file
	// contributed to neither alignment nor policy.
	NoteUnplacedFile = "unplaced_file"
	// NoteHeadParseError: a head file failed security validation or parsing.
	// Alignment still comes from hashes; delta and policy are null.
	NoteHeadParseError = "head_parse_error"
	// NotePartialSet: the stored model has segments the repo did not submit.
	// Policies were evaluated against the submitted segments only.
	NotePartialSet = "partial_set"
)

// Request limits, mirrored from the server so a request that would be refused
// is refused here, before it is sent. Body over MaxBodyBytes is a 413; the
// rest are 400 limit_exceeded.
const (
	MaxBodyBytes     = 2 << 20   // 2 MiB
	MaxModels        = 20        // per request
	MaxFilesPerModel = 50        // per model
	MaxFileBytes     = 512 << 10 // 512 KiB, each of base and head
	MaxNameLength    = 255       // file name, slug, backend_org, repository
)

// ---------------------------------------------------------------------------
// POST /api/v1/org/_/drift/context — request
// ---------------------------------------------------------------------------

// ContextRequest is the body of a context call: the repo's threat-model HCL
// files grouped by model, each with its base-commit and PR-head content.
// Nothing else — no diff, no source — can be expressed in it.
type ContextRequest struct {
	Schema     int            `json:"schema"`
	Repository string         `json:"repository"`
	Models     []RequestModel `json:"models"`
}

// RequestModel is one model the repo addresses.
type RequestModel struct {
	Slug string `json:"slug"`
	// BackendOrg is the organisation the files' backend block names, if any.
	// The server notes org_mismatch when it differs from the token's; it never
	// changes which organisation is searched.
	BackendOrg *string       `json:"backend_org,omitempty"`
	Files      []RequestFile `json:"files"`
}

// RequestFile is one HCL file of a model. Base is absent for a file the PR
// adds; Head is required.
type RequestFile struct {
	Name string  `json:"name"`
	Base *string `json:"base,omitempty"`
	Head *string `json:"head"`
}

// ---------------------------------------------------------------------------
// POST /api/v1/org/_/drift/context — response
// ---------------------------------------------------------------------------

// ContextResponse answers a context call: one entry per submitted model in
// submission order, plus the organisation-level library.
type ContextResponse struct {
	Schema  int            `json:"schema"`
	Org     ContextOrg     `json:"org"`
	Models  []ContextModel `json:"models"`
	Library ContextLibrary `json:"library"`
}

// ContextOrg identifies the token's organisation.
type ContextOrg struct {
	Slug string `json:"slug"`
	Tier string `json:"tier"`
}

// ContextModel is the context for one submitted model.
type ContextModel struct {
	Slug string `json:"slug"`
	// ID and Version are null when the model is not_in_cloud.
	ID      *string `json:"id"`
	Version *string `json:"version"`
	// RepositoryMatch is null when the model declares no repository.
	RepositoryMatch *bool     `json:"repository_match"`
	Alignment       Alignment `json:"alignment"`
	// Policy is null with note no_policies, policy_unavailable,
	// head_parse_error or not_in_cloud.
	Policy *PolicyContext `json:"policy"`
	Notes  []string       `json:"notes"`
}

// HasNote reports whether the server attached note.
func (m ContextModel) HasNote(note string) bool {
	return slices.Contains(m.Notes, note)
}

// Alignment places the submitted copy in the model's version history.
type Alignment struct {
	State string `json:"state"`
	// BaseMatches is the version string the deciding segment's base matched;
	// null when it matched nothing.
	BaseMatches    *string            `json:"base_matches"`
	VersionsBehind int                `json:"versions_behind"`
	Segments       []SegmentAlignment `json:"segments"`
	// Delta is the entity-level change from the cloud current version to the
	// submitted head, present only for behind and conflict. "removed" means
	// present in cloud and absent from the submitted copy. Empty categories
	// are omitted, so a conflict whose head already equals cloud's current
	// version arrives with an empty, non-null delta.
	Delta Delta `json:"delta"`
}

// SegmentAlignment is one submitted segment's own state.
type SegmentAlignment struct {
	Segment        string  `json:"segment"`
	State          string  `json:"state"`
	BaseMatches    *string `json:"base_matches"`
	VersionsBehind int     `json:"versions_behind"`
}

// Delta is the entity-level diff keyed by category — threats, controls,
// assets, usecases, exclusions, tpds, dfds — holding only the categories that
// changed. A nil map is the server's null. It is a map rather than a struct
// so a category the server adds later renders rather than vanishes.
type Delta map[string]EntityChange

// EntityChange lists identifiers added, removed or modified in one category.
// Control identifiers are "<threat>::<control>"; usecase and exclusion
// identifiers are their descriptions.
type EntityChange struct {
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Modified []string `json:"modified,omitempty"`
}

// PolicyContext is the organisation's policy verdict on the submitted head
// content. Blocking counts results that are enforced, severity error and
// failed.
type PolicyContext struct {
	Evaluated int            `json:"evaluated"`
	Enforced  int            `json:"enforced"`
	Violated  int            `json:"violated"`
	Blocking  int            `json:"blocking"`
	Results   []PolicyResult `json:"results"`
}

// PolicyResult is one policy's verdict. Message is org-authored and may
// interpolate model content, which the pull request controls, so it renders
// escaped and capped.
type PolicyResult struct {
	PolicyName string `json:"policy_name"`
	Severity   string `json:"severity"`
	Enforced   bool   `json:"enforced"`
	Passed     bool   `json:"passed"`
	Message    string `json:"message"`
}

// ContextLibrary is the organisation's referenceable library: published items
// that carry a reference_id, capped per kind, ordered by reference_id.
type ContextLibrary struct {
	Threats   []LibraryEntry `json:"threats"`
	Controls  []LibraryEntry `json:"controls"`
	Truncated bool           `json:"truncated"`
}

// LibraryEntry is a referenceable library item. Descriptions are not sent.
type LibraryEntry struct {
	ReferenceID string `json:"reference_id"`
	Name        string `json:"name"`
}

// ---------------------------------------------------------------------------
// POST /api/v1/org/_/drift/reviews — request
// ---------------------------------------------------------------------------

// ReviewRecord is the body of a write-back: counts only. Every string field
// carries an `enum` tag (a closed set, "|"-separated) or a `pattern` tag (an
// anchored regular expression that also bounds its length). Validate enforces
// both before a record is sent, and TestReviewRecordHasNoFreeText fails on a
// string field that has neither — so a finding title, excerpt, file path or
// summary cannot reach the ledger by adding a field. The server refuses
// unknown fields too.
type ReviewRecord struct {
	Schema     int     `json:"schema"`
	Repository string  `json:"repository" pattern:"^[A-Za-z0-9._/-]{1,255}$"`
	PRNumber   int     `json:"pr_number" min:"1"`
	HeadSHA    string  `json:"head_sha" pattern:"^[0-9a-f]{7,64}$"`
	BaseSHA    *string `json:"base_sha,omitempty" pattern:"^[0-9a-f]{7,64}$"`

	Models []ReviewModel `json:"models"`

	Verdict             string        `json:"verdict" enum:"clean|findings|action-required|unassessed"`
	Counts              ReviewCounts  `json:"counts"`
	ActionRequiredCount int           `json:"action_required_count"`
	Policy              *ReviewPolicy `json:"policy,omitempty"`

	FilesChanged  int `json:"files_changed"`
	FilesReviewed int `json:"files_reviewed"`

	Provider      *string `json:"provider,omitempty" enum:"anthropic|openai|gemini"`
	LLMModel      *string `json:"llm_model,omitempty" pattern:"^[A-Za-z0-9._:/-]{1,128}$"`
	ActionVersion *string `json:"action_version,omitempty" pattern:"^[A-Za-z0-9._:/-]{1,32}$"`
}

// ReviewModel is one model the review covered. ID and Version are null for a
// model that was not_in_cloud.
type ReviewModel struct {
	ID             *string `json:"id" pattern:"^[0-9a-fA-F-]{36}$"`
	Version        *string `json:"version" pattern:"^[0-9A-Za-z.+-]{1,64}$"`
	Alignment      string  `json:"alignment" enum:"aligned|ahead|behind|conflict|unsynced|not_in_cloud"`
	VersionsBehind int     `json:"versions_behind"`
}

// ReviewPolicy is the policy summary the review saw.
type ReviewPolicy struct {
	Evaluated int `json:"evaluated"`
	Violated  int `json:"violated"`
	Blocking  int `json:"blocking"`
}

// ReviewCounts holds exactly the six drift categories.
type ReviewCounts struct {
	StaleAssertion   int `json:"stale_assertion"`
	PhantomControl   int `json:"phantom_control"`
	UnmodeledSurface int `json:"unmodeled_surface"`
	DfdDrift         int `json:"dfd_drift"`
	DependencyDrift  int `json:"dependency_drift"`
	UnclassifiedData int `json:"unclassified_data"`
}
