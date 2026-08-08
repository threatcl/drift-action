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
  deterministic checks → single-shot LLM with targeted context stuffing →
  render. No agentic repo exploration in v1.

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

## Gotchas

- Action input env names contain hyphens (`INPUT_CONFIG-PATH`): fine from
  `os.Getenv`, impossible from POSIX shell.
- `go.mod` requires go 1.26.5 — forced by the `threatcl/spec` dependency.
  Keep the Dockerfile's `golang:` base and spec bumps in sync.
- Anthropic structured outputs don't support `minItems`, so "≥1 evidence per
  finding" cannot be enforced schema-side — that's why `findings.Sanitize`
  exists.
- Structured-outputs model support is model-specific; default is
  `claude-sonnet-5` (`internal/config`). Verify support before changing it.

## Open items

- LICENSE: none yet, intentionally — repo is private and the open/closed
  question is unsettled. MIT is the family default (threatcl-action is MIT).
  Resolve `threatcl/spec`'s missing LICENSE before anything here goes public.
- Config file name `.threatcl-ci.hcl`: coordinate with the claude-plugin's
  `/threat-ci` scaffolder before first release.
- Engine implementation: compare-API client, manifest-based dependency drift,
  targeted context stuffing, Anthropic structured-output call, full comment
  renderer.

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
