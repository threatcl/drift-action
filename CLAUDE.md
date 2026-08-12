# drift-action

Self-hosted GitHub Action that reviews pull requests for threat model drift —
divergence between what the code does and what the repo's Threatcl `.tm.hcl`
asserts. It is the detection half of a pair: this action finds drift on the
PR, and the claude-plugin's `/threat-drift` remediates it from the agent
prompt each finding carries.

Drift is **not** "the `.tm.hcl` changed". It is divergence between what the
code now does and what the model asserts, in six categories: stale
assertions, phantom controls, unmodeled surface, DFD drift, dependency drift,
unclassified data.

## Pipeline

Deterministic first, inference second — facts are extracted before the model
is asked anything.

1. **Parse** the threat model via `threatcl/spec` into structured assertions,
   with line numbers recovered separately. → `internal/model`
2. **Fetch and filter** the diff from the GitHub compare API down to the
   review set. Nothing relevant changed → no inference at all.
   → `internal/diff`
3. **Extract facts** from dependency manifests: what changed, with line
   numbers. Facts for the prompt, never findings — whether a change matters
   is judgement, and judgement belongs to the model. → `internal/deps`
4. **Assemble and infer**: one shot, model assertions + filtered diff +
   targeted context stuffing (whole files that plausibly back touched
   controls, so "was the backing code removed?" is answerable beyond the
   hunks), forced to the findings schema. → `internal/engine`, `internal/llm`
5. **Render**: our code, never the model, turns the validated report into the
   sticky comment and check run. → `internal/render`, `internal/gh`

## Out of scope (deliberately, not yet-to-do)

- General code review — bugs, style, tests. Threat drift only.
- Agentic repo exploration during inference. Revisit only if single-shot plus
  targeted context stuffing proves insufficient on phantom controls.
- Auto-committing model updates to the PR. The agent-prompt handoff keeps a
  human and the claude-plugin in the loop on purpose.
- GitLab/Bitbucket.

## Decisions (do not relitigate)

- **2026-08:** Separate repo from `threatcl-action`. Different trust profile
  (PR write + LLM key vs none), different release cadence (prompt/renderer
  iteration vs CLI lockstep), different mental model (PR reviewer bot vs
  pipeline step).
- **2026-08:** The engine lives here, in Go — not as a `threatcl` CLI
  subcommand. Decoupled release cadence; the claude-plugin already covers
  local/interactive runs.
- **2026-08:** Docker container action. `image: Dockerfile` while iterating;
  switch `action.yml` to `docker://ghcr.io/threatcl/drift-action:vX.Y.Z` at
  first release (sibling threatcl-action pattern).
- **2026-08:** Anthropic provider first, behind `internal/llm.Provider`.
  OpenAI/Vertex later, once finding quality is validated.
- **2026-08:** PR diff comes from the GitHub compare API, not git-in-container.
  Keeps the final image distroless/static, avoids `fetch-depth: 0` and
  `safe.directory` failure modes. Context-file reads use the checkout at
  `/github/workspace`.
- **2026-08:** Inputs are env-var based with declared `outputs:` — never
  positional args (explicit rejection of threatcl-action's entrypoint.sh
  pattern).
- **2026-08:** Deterministic-first pipeline. Parse model → filter diff →
  extract manifest facts → single-shot LLM with targeted context stuffing →
  render. No agentic repo exploration in v1.
- **2026-08:** Deterministic code extracts facts; it does not produce findings.
  `internal/deps` originally judged dependency drift itself — matching model
  block names to module paths by fuzzy substring, assigning severities, writing
  agent prompts. That duplicated what the model does better (it sees the same
  manifest hunk), needed dedup once inference landed, and covered only two
  ecosystems. It now reports what changed and leaves every judgement to the
  model. Resist re-adding rule-based findings for any category.

## Hard constraints

- **Never commit** `github-drift-integration-plan.md` or
  `prior-claude-chat.md` (gitignored; internal business context).
- **Prompt provenance:** `prompts/upstream/` is a verbatim copy of
  claude-plugin's `commands/threat-drift.md` at the SHA in
  `prompts/upstream/SOURCE`. Never hand-edit it — re-vendor and update SOURCE.
  CI adaptations live only in `prompts/drift-ci.md`, with deltas documented in
  `prompts/ADAPTATIONS.md`.
- **Forced JSON:** LLM output must validate against
  `internal/findings/schema/findings-v0.schema.json`. `findings.Sanitize`
  drops evidence-free findings before rendering — the evidence rule is
  enforced in code, not just in the prompt. LLM output influences nothing but
  the report body.
- **Sticky marker:** `<!-- threatcl-drift-action -->` (defined once, in
  `internal/render`). It is a compatibility contract — changing it orphans
  comments on existing PRs. The upsert matches on **author as well as
  marker**: someone quoting the review in their own comment would otherwise
  have that comment silently overwritten by the next push.
- **Docs and examples always use `pull_request`**, never
  `pull_request_target`.
- **Diff filtering defaults to keep.** `internal/diff.Filter` removes only
  noise (docs, lock files, vendored, generated), and narrows to
  security-relevant paths *only* above `narrow_above`. An earlier version
  inverted this — keeping just paths whose name contained a security keyword —
  and silently discarded `server.go` and `store.go`, reviewing a real PR as
  zero files. Under-reviewing yields a clean-looking result that hides drift,
  the worst outcome this action has, so never tighten the filter without a
  matching coverage report: narrowing and an empty review set must both reach
  the comment.

## Gotchas

- Action input env names contain hyphens (`INPUT_CONFIG-PATH`): fine from
  `os.Getenv`, impossible from POSIX shell. Inputs that need setting by hand
  during local runs therefore get a shell-friendly alias — `dry-run` has
  `THREATCL_DRIFT_DRY_RUN` (`config.DryRunEnv`).
- `dry-run` suppresses every GitHub write and nothing else: the diff is still
  fetched (so a token is still required), the comment is still rendered and
  printed, and the verdict and exit code are unchanged. A non-boolean value is
  a hard error, never a silent `false` — someone who believes they asked for a
  dry run must never have a comment posted on their behalf.
- `go.mod` requires go 1.26.5 — forced by the `threatcl/spec` dependency.
  Keep the Dockerfile's `golang:` base and spec bumps in sync.
- Anthropic structured outputs don't support `minItems`, so "≥1 evidence per
  finding" cannot be enforced schema-side — that's why `findings.Sanitize`
  exists.
- Structured-outputs model support is model-specific. Defaults are
  `claude-opus-5` and `gpt-5.6-sol` (`config.providerDefaults`), and both are
  the models the committed corpus recordings were made against. Changing
  either means re-recording that provider's corpus, not just editing the
  constant.
- `threatcl/spec` discards source ranges: its structs carry no `hcl.Range` and
  its `hclparse.Parser` is never returned. `internal/model.LineIndex` re-parses
  the file with `hclsyntax` to recover line numbers, and joins to spec's
  structs by block type and label. Without it, `model_excerpt.file:line`
  cannot be produced and the evidence rule is unenforceable. An unknown line
  is 0 and must render as "no line", never as `:0`.
- Both `claude-opus-5` and `claude-sonnet-5` carry elevated cybersecurity
  safeguards, and we send security-relevant diffs. A refusal arrives as
  HTTP 200 with `stop_reason: "refusal"` and possibly an empty content array —
  check the stop reason before reading content, and render a refusal as
  "could not assess", never as "no drift". The OpenAI provider needs the same
  outcome from a different shape: no stop reason, but either a `refusal`
  content part beside the text parts or `incomplete_details.reason ==
  "content_filter"`. Both are checked before any output is read, because a
  refusal's output text is empty and reading it first turns a declined review
  into a silent one.
- Server-side fallbacks are on by default (`fallbacks: "default"` plus the
  `server-side-fallback-2026-07-01` beta), which puts the provider on the
  **beta** message surface: `client.Beta.Messages.NewStreaming` and the whole
  `Beta*` param/response family. The non-beta `MessageNewParams` has no
  `Fallbacks` field. A fallback silently changes which model answered, so
  `ReviewResult.Fallback` is detected from `usage.iterations` — the `fallback`
  content block only marks a mid-response switch — and the comment names the
  model that served the review.
- `max_tokens` caps thinking *plus* output. Hitting it truncates the report
  mid-JSON; that is an error, never a rendered half-review.
- The partial-contradiction rule in `prompts/drift-ci.md` — an assertion still
  true but now incomplete is `review_recommended`, not `action_required` — is
  what keeps `fail_mode = on-action-required` from flipping a build on
  judgement wobble. Severity is enforced only in the prompt, so loosening that
  rule changes CI outcomes with nothing in code to catch it.
- `internal/engine` owns `NewProvider` and `AssembleRequest` because `main`
  and the corpus must build the *same* request. They once didn't: the corpus
  assembled its own and silently stopped setting `Categories`, so the corpus
  measured a prompt the action never sent. It sits above `internal/llm`
  because the provider packages import `llm`, so `llm` cannot import them.
- Provider settings cascade. `config.providerDefaults` is the single list of
  known providers (`knownProvider` reads it), and `Model`/`APIKeyEnv` are
  *derived* from the provider, re-derived when a config file switches it.
  That is why `config.Load` runs `FromEnv` twice: the first pass supplies
  `config-path`, and only a second can put an explicit `model` input back
  above a provider switch. Validation runs at the end, on the finished config.
- `openai.strictSchema` translates the shared schema for strict mode inside
  the provider — the schema itself stays the validation source of truth and
  goes to Anthropic verbatim. Narrow by design: `const` becomes a
  single-value `enum`, a const-only property gains the `type` strict mode
  requires, `$schema` is dropped. A test walks the result asserting every
  object is structurally strict, so a schema edit that breaks it fails
  locally rather than at the API.
- The corpus asserts category and cited file, never severity or primary
  category — the two providers legitimately disagree there (on `dfd-drift`
  Anthropic leads with `unmodeled_surface`, OpenAI with `dfd_drift`) while
  agreeing on which cases are `action_required`. Tightening those assertions
  would break one provider for a difference that is judgement, not error.
- Dogfooding wiring: `threatcl-drift-action.tm.hcl` is guarded by
  `TestRepoThreatModel` — it must load, and every prose-referenced path must
  exist, because those references are what context stuffing hangs off.
  `.threatcl-ci.hcl` sets `trigger_paths = ["prompts/"]`: `.md` is filter
  noise, but a prompt edit changes the reviewer itself. Spec's DFD slugifier
  splits every capital (`PR Author` → `p_r_author`), so the DFD flows use
  quoted-name refs rather than dot notation.
- Inference error text never reaches the comment. A schema-validation failure
  quotes the model's output, which the pull request's own diff shaped — so
  `findings.ErrInvalidOutput` is matched and the engine supplies its own
  wording, with the detail going to the run log. Model output reaches the
  comment through the report body and nothing else.
- `THREATCL_DRIFT_RECORD` / `THREATCL_DRIFT_REPLAY` (`internal/llm/fixture`)
  capture and replay a review so the GitHub half of the pipeline can be tested
  without paying for inference. Fixtures live in `testdata/recordings/`. A
  replayed run must always disclose itself in the comment and must re-validate
  the recorded report against the schema — a fixture is not trusted more than a
  live response, and it must never be able to pass for one.
- The corpus replay fails closed both ways: a case with no recording for the
  configured provider fails, and a recording whose fingerprint no longer
  matches the assembled request fails. `fixture.Digest` covers
  `ReviewRequest.Sections()` and deliberately *not* its `Prompt`, so editing
  `prompts/drift-ci.md` stales nothing — what forces a re-record is a change
  to assembly (`internal/llm/sections.go`, the `N→` prefixes, `deps.Render`,
  context selection) or to a case's inputs, which is exactly when the old
  recording has stopped describing what the model sees.

## State

Complete and released. Everything in the pipeline above runs in production —
config, model discovery and line indexing, diff filtering, manifest facts,
context stuffing, inference, schema validation, the comment renderer, the
check run wired to `fail_mode`, and `dry-run`.

Two providers ship, Anthropic and OpenAI, both validated against the
seven-case corpus and agreeing on which cases are `action_required` — so
`fail_mode` does not depend on which one a repo picks. The corpus replay is
CI's only finding-quality gate and now fails closed both ways.

Dogfooding is live on this repo's own pull requests, and has already found
real gaps in this repo's own threat model that the agent-prompt handoff then
remediated.

A release is a **`workflow_dispatch`, not a tag push**. `release.yml` publishes
the image, reads back its digest, commits that digest into `action.yml` on
`main`, tags that commit, and moves the major alias; pushing a tag by hand
publishes nothing. The order is load-bearing — a digest can only name an image
that already exists — so read `docs/RELEASING.md`, which holds the procedure
and the partial-failure recovery table, before dispatching. v0.1.0 through
v0.1.2 shipped; v1 is the next cut and the docs already name it.

## Open items

- The claude-plugin's `/threat-ci` scaffolder still emits the wrong thing: it
  needs to write `.threatcl-ci.hcl` and a workflow with a `concurrency:`
  block, a pinned ref and `pull_request`. The threatcl editor LSP also flags
  `.threatcl-ci.hcl` as an invalid threat model — it should skip the file, as
  engine discovery already does. Tracked in this repo because `/threat-ci` is
  this action's on-ramp, but the work lands in `../claude-plugin`.
- Vertex is the next provider candidate and faces the same bar the other two
  cleared: all seven corpus cases under its own recordings, `clean` included.
  `ReviewResult.Fallback` stays Anthropic-only — do not invent an equivalent.
- A fork contributor who changes request assembly cannot re-record the corpus,
  having no key and no secrets on a fork run, so a maintainer re-records on
  the branch. Accepted, and recorded in the threat model.

## Siblings

- `../spec` — HCL parser. `spec.LoadSpecConfig()` →
  `spec.NewThreatmodelParser(cfg)` → `parser.ParseFile(path, false)` →
  `parser.GetWrapped().Threatmodels`.
- `../claude-plugin` — prompt source of truth (`commands/threat-drift.md`) and
  the remediation half of the loop.
- `../threatcl-action` — release workflow pattern to copy; input pattern to
  avoid.

## Build and test

```
go build ./... && go vet ./... && go test ./...
docker build -t drift-action:dev .
```
