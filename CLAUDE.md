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
   with file and line numbers recovered separately. A model split across
   several files (`model_paths`) is parsed and reviewed as one set.
   → `internal/model`
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
- **2026-09:** Gemini is the Gemini *Developer* API (`google.golang.org/genai`,
  API key, `generativelanguage.googleapis.com`), not Vertex. The backend is
  pinned to `BackendGeminiAPI` in code so `GOOGLE_GENAI_USE_VERTEXAI` on a
  runner cannot reroute a review to a GCP project the workflow never named.
  Vertex, if wanted, is a separate provider with a separate credential story.
- **2026-09:** A provider earns its default model by recording every corpus
  case *and* agreeing with the existing providers on which cases are
  `action_required`. Gemini's first recording passed the assertions but
  demoted `dfd-drift`; the fix was to tighten the prompt's severity rule so
  every provider reads the exposure the same way, not to accept a
  provider-dependent `fail_mode`. Passing the assertions alone is not done.
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
  the comment. The two content-based removals follow that rule. A repo's
  `ignore_paths` lists every file it excludes by path. Go files carrying a
  `// Code generated … DO NOT EDIT.` header (`diff.GoGenerated`, stdlib
  `ast.IsGenerated`, read through an `os.Root`) are noise and are listed too.
  Precedence is deliberate: `trigger_paths` beats `ignore_paths`, but the
  model's prose references do not. They match loosely through the keep-side
  suffix rule, so a bare `server.go` would defeat every exclusion. That suffix
  rule lives in `matchesAny` only. `ignores` gets the pattern language alone,
  because an exclusion must remove exactly what it names.

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
  `claude-opus-5`, `gpt-5.6-sol` and `gemini-3.8-flash`
  (`config.providerDefaults`), and all three are the models the committed
  corpus recordings were made against. Changing any means re-recording that
  provider's corpus, not just editing the constant.
- `threatcl/spec` discards source ranges: its structs carry no `hcl.Range` and
  its `hclparse.Parser` is never returned. `internal/model.LineIndex` re-parses
  every file in the set with `hclsyntax` to recover locations, and joins to
  spec's structs by block type and label. Without it, `model_excerpt.file:line`
  cannot be produced and the evidence rule is unenforceable. Each entry stores
  the *file* as well as the line, and citations take the file from the entry —
  across a set, a block's model need not live in the file the block does, and a
  citation naming a file that lacks the block is worse than none. The address
  keys still work because spec makes threat model names unique across a set.
  An unknown line is 0 and must render as "no line", never as `:0`.
- `extends` is parsed twice. spec resolves it by copying the parent's
  collections into the child, so rendering the resolved set showed every
  inherited threat and control twice — the child's copy uncited, since the
  block sits in the parent — and counted it twice in "Context used". The first
  parse (resolution on) only validates: an unknown parent or a cycle fails
  there. If any model has `Extends`, `model.parse` re-parses with
  `SetSkipExtendsResolution(true)` and keeps *that* result, so each item is
  rendered once, under the model that declares it, and the child carries an
  `extends:` line saying what it inherits. Filtering the resolved result
  instead does not work: `inheritFrom` copies by value and a same-named child
  item overrides the parent's, so nothing distinguishes inherited from
  overridden, and "has no line number" misfires on JSON and `including`. With
  no `extends` there is no second parse. spec has no typed error for an
  unknown parent, so `model.explain` matches its wording to add the
  `model_paths` hint; `TestLoadChildAloneNamesTheFix` pins that wording.
- One configured path stays on spec's `ParseFile`; only two or more go
  through `ParseHCLRawSet`. That keeps single-file behaviour exactly as it was
  — backend validation, JSON support — and keeps a plain one-file model's
  `Render()` byte-identical, which every corpus recording's fingerprint
  depends on (`TestRenderSingleFileUnchanged`, against
  `testdata/simple.render.golden`; never regenerate it to make a test pass).
  `ParseHCLRawSet` is HCL-only and skips `validateBackend`, so a JSON file in
  a multi-file list is refused by name, and `NamedInput.Name` is the real
  filesystem path because spec resolves `including` and imports against it.
- Model files are read through an `os.Root` on the checkout
  (`model.readConfined`), on both routes. `model_paths` comes from the pull
  request's own `.threatcl-ci.hcl`, and what a model file declares is sent to
  the LLM provider, so an entry that escapes — `../`, an absolute path, or a
  symlink the PR adds — would let a PR pick a runner file to disclose. Escapes
  are refused, never reinterpreted: `/threatmodels/x.hcl` is an error, not a
  repo-relative path. `including`/imports inside a model resolve through spec
  and are not confined; context stuffing's `readInWorkspace` is lexical only
  and follows symlinks. Both residuals are recorded on the threat model's
  `TCL-T-LLM-DATASHARE` control.
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
  judgement wobble. Two named exposures take precedence over it (sensitive
  data reachable without the model's auth; sensitive data reaching another
  organisation), and their exact wording is load-bearing:
  `prompts/ADAPTATIONS.md` records how earlier drafts re-categorised
  `dependency-drift` and demoted `unmodeled-surface` on Gemini. Severity is
  enforced only in the prompt, so any edit to that section changes CI
  outcomes with nothing in code to catch it — and although `fixture.Digest`
  excludes the prompt, a severity edit is a re-record-every-provider event in
  practice, because agreement on `action_required` is checked by eye.
- `internal/engine` owns `NewProvider`, `LoadModel` and `AssembleRequest`
  because `main` and the corpus must build the *same* request. They once
  didn't: the corpus assembled its own and silently stopped setting
  `Categories`, so the corpus measured a prompt the action never sent; and it
  loaded only the first resolved model file while `main` refused several. A
  corpus case may carry `workspace/.threatcl-ci.hcl`, read through
  `config.LoadFile` as the action reads a repo's. It sits above `internal/llm`
  because the provider packages import `llm`, so `llm` cannot import them.
- Provider settings cascade. `config.providerDefaults` is the single list of
  known providers (`knownProvider` reads it), and `Model`/`APIKeyEnv` are
  *derived* from the provider, re-derived when a config file switches it.
  That is why `config.Load` runs `FromEnv` twice: the first pass supplies
  `config-path`, and only a second can put an explicit `model` input back
  above a provider switch. Validation runs at the end, on the finished config.
- `llm.PortableSchema` translates the shared schema for the providers whose
  accepted dialect excludes `const` — OpenAI strict mode and Gemini's
  `responseJsonSchema` draw the same line — while the schema itself stays the
  validation source of truth and goes to Anthropic verbatim. Narrow by
  design: `const` becomes a single-value `enum`, a const-only property gains
  the `type` strict mode requires, `$schema` is dropped. It lives in
  `internal/llm` because two providers need the identical rewrite; the OpenAI
  test still walks the result asserting every object is structurally strict,
  so a schema edit that breaks it fails locally rather than at the API.
- Gemini refusals have two shapes, and neither carries an explanation. A
  blocked *prompt* arrives as `promptFeedback.blockReason` with no candidate
  at all; a classifier stop mid-answer arrives as a candidate `finishReason`
  of `SAFETY`/`BLOCKLIST`/`PROHIBITED_CONTENT`/`SPII`/`RECITATION`. Both are
  checked before any text is read, and any other unexpected finish reason is
  an error even when the preceding text parses. `blockReasonMessage` and
  `finishMessage` are Vertex-only — the SDK drops them from Gemini API
  responses — so the category is the whole signal.
- The genai SDK differs from the other two in ways the Gemini provider has to
  absorb: `NewClient` fails at construction without a key (so `gemini.New`
  returns an error and `engine.NewProvider` propagates it); retries are off
  unless `HTTPRetryOptions` is set (the provider asks for 3 attempts, matching
  the siblings' default of two retries); `maxOutputTokens` includes thought
  tokens (so the shared `max_tokens` semantics hold); and thoughts are counted
  apart from candidates in usage, so `OutputTokens` sums the two to mean the
  same thing it does elsewhere.
- Gemini `effort` is sent as `thinkingConfig.thinkingLevel`, which the Gemini
  3 family accepts and has no value above `HIGH`, so `xhigh` and `max`
  collapse onto it rather than being rejected for one provider. Gemini 2.5
  models used `thinkingBudget` instead; the provider does not target them.
- The corpus asserts category and cited file, never severity or primary
  category — plus, only where an expectation names `model_file`, the model
  file the excerpt cites, which has a wrong answer only in a multi-file set.
  The providers legitimately disagree on severity and primary category (on `dfd-drift`
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

Three providers ship verified — Anthropic, OpenAI and Gemini
(`internal/llm/gemini`, the Developer API by key, `gemini-3.8-flash`) — all
recorded against all eight corpus cases and agreeing on which are
`action_required`, so `fail_mode` does not depend on which one a repo picks.
Gemini's agreement was won by tightening the prompt's severity rule; the
Anthropic and OpenAI recordings predate that edit (the digest does not cover
the prompt, so they remain valid) and a live spot-check of both on
`dfd-drift`, `dependency-drift` and `unmodeled-surface` under the new wording
is still owed.

The corpus replay is CI's only finding-quality gate and fails closed both
ways — though it replays only the default provider, so the OpenAI and Gemini
recordings are not gated there.

Multi-file threat model sets (issue #28) are implemented on the
`multi-file-handling` branch and not yet released: several `model_paths` are
one set, `extends` may cross files, and a hierarchy renders each item once.
The eighth corpus case, `multi-file-set`, is recorded for all three
providers, and all three agree: one `phantom_control`, `action_required`, its
excerpt citing the parent file that declares the control rather than the
child that inherits it.

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
  engine discovery already does. It should also emit a multi-entry
  `model_paths` when a repo's model is split across files. Tracked in this
  repo because `/threat-ci` is this action's on-ramp, but the work lands in
  `../claude-plugin`.
- Discovery that finds several files still refuses rather than assessing
  them as a set; the error offers the `model_paths` line to paste. Whether
  discovery should assemble a set itself (issue #28 leans that way, but two
  unrelated models are only distinguishable from one split model after
  parsing) is an open maintainer decision. Glob support in `model_paths` is
  not implemented; if added, a glob matching nothing must be a hard error.
- Spot-check Anthropic and OpenAI under the 2026-09 severity wording:
  `THREATCL_DRIFT_CORPUS=live THREATCL_DRIFT_CORPUS_PROVIDER=<p> <KEY>=… go
  test ./internal/corpus -run 'TestCorpus$/(dfd-drift|dependency-drift|unmodeled-surface)' -v`
  and confirm the `action_required` set is unchanged. Re-record them if you
  want every provider's baseline on the same prompt.
- CI's corpus replay covers only the default provider. A matrix over the
  three providers would make the OpenAI and Gemini recordings a gate too.
- Vertex, if ever, is a separate provider from Gemini — different credential
  (ADC/project, not an API key) and the `finishMessage` fields the Gemini API
  drops. Same bar: every corpus case under its own recordings, `clean`
  included. `ReviewResult.Fallback` stays Anthropic-only — do not invent an
  equivalent.
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
