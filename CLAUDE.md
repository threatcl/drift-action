# drift-action

Self-hosted GitHub Action that reviews pull requests for threat model drift —
divergence between what the code does and what the repo's Threatcl `.tm.hcl`
asserts. Phase 1 of a larger roadmap; the committed scope is
`docs/phase1-plan.md`.

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
- **2026-08:** Anthropic provider only in v0, behind `internal/llm.Provider`.
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
  comments on existing PRs.
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
- Structured-outputs model support is model-specific; default is
  `claude-opus-5` (`internal/config`). Verify support before changing it.
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
  "could not assess", never as "no drift".
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

## State

Milestones 1 and 2 are done. The action runs end to end and actually reviews:
config parsing, model discovery and line indexing, assertion rendering, the
GitHub compare/comment/check-run client, diff filtering and rendering, manifest
fact extraction, targeted context stuffing, the Anthropic provider (streaming,
forced JSON, refusal handling, server-side fallbacks), schema validation, the
comment renderer, and `dry-run`.

Milestone 3 is polish and dogfooding: check-run conclusions wired to
`fail_mode`, the diff-size cap with the "run locally" message, the
`docker://` release switch, and the `testdata/` finding-quality corpus that
tells us whether the engine is any good. See the plan file.

## Open items

- `threatcl/spec` has no LICENSE file. It is a direct dependency, so resolve
  that before this repo is made public.
- Config file name `.threatcl-ci.hcl`: coordinate with the claude-plugin's
  `/threat-ci` scaffolder before first release.
- No repo in the org has a root-level `.tm.hcl` yet, so dogfooding needs one
  added (or `model_paths` pointed at an existing model).

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
