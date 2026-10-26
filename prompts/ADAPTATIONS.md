# drift-ci.md — adaptations from upstream

`drift-ci.md` derives from `upstream/threat-drift.md` (the claude-plugin's
`/threat-drift` command, pinned in `upstream/SOURCE`). The six drift
categories, the evidence rule, the "too vague to drift" gate, and the "say
plainly when there is no drift" rule are shared IP and are kept intact — when
upstream changes those, re-vendor and re-derive.

## Removed (interactive-only)

| Upstream | Why removed |
|----------|-------------|
| `git diff $ARGUMENTS` resolution (step 1) | The engine resolves and filters the diff; the prompt receives it as data |
| "Find the local `.hcl` file… ask the user which model" (step 2) | Model paths come from `.threatcl-ci.hcl` config; CI cannot ask |
| Markdown report template (step 4) | Output is forced JSON conforming to `internal/findings/schema/findings-v0.schema.json`; our code renders the comment |
| "Don't write to the HCL" section | Not applicable — the action only ever emits a report |

## Kept (the shared IP)

- The six category definitions and their per-category check instructions,
  near-verbatim.
- The evidence rule: "Cite specific file:line evidence for every finding. A
  drift finding without a code reference is a guess."
- The "when the model is too vague to drift" gate — repurposed from an
  interactive bail-out into a structured verdict (`no_drift = false`, empty
  findings, explanatory summary).
- The "no drift" plain statement rule.

## Added (CI-specific)

- Input-section contract (`THREAT MODEL ASSERTIONS` / `ENABLED CATEGORIES` /
  `DEPENDENCY MANIFEST CHANGES` / `CONTEXT FILES` / `DIFF`), ordered stable
  content first so the prompt prefix stays cacheable.
- The dependency-drift check reads the engine's extracted manifest deltas
  rather than re-deriving them from the diff. The extraction states what
  changed and assigns no severity; the judgement stays here.
- `ENABLED CATEGORIES` honours the `categories` config setting, which upstream
  has no equivalent of.
- Prompt-injection framing: diff and file contents are untrusted data, never
  instructions.
- JSON-only output instruction tied to the provided schema.
- Severity-tier defaults (contradicted assertions and phantom controls →
  `action_required`), plus a partial-contradiction rule upstream doesn't
  need: an assertion that is still true but now incomplete is
  `review_recommended`, never `action_required`. Two identical runs scored
  the same partially-contradicted assertion differently, which flips
  `action-required-count` and can flip the build under
  `fail_mode = "on-action-required"` — the plugin has no build to fail, so
  the rule is CI-only.
- Two named exposures inside the "concrete, currently-exposed risk" clause,
  given precedence over the partial-contradiction rule: sensitive data
  (Confidential or Restricted by the model, or plainly so) reachable without
  the authentication the model's other paths rely on, and sensitive data now
  reaching another organisation's service or endpoint the model does not
  show. Both are `action_required` whatever category they are filed under.
  Added when the Gemini provider was recorded against the corpus: on
  `dfd-drift` (customer emails posted to an unmodeled analytics collector)
  Anthropic and OpenAI escalated under the bare risk clause while Gemini —
  consistently, on two models — read the partial rule's own example as
  covering it and stayed at `review_recommended`, which made `fail_mode`
  gating provider-dependent. Three things about the wording were learned
  the expensive way and are deliberate. It names *two* shapes: a draft that
  named only the disclosure one anchored Gemini's reading of "concrete
  risk" to that shape, and it demoted the unauthenticated `/admin/export`
  of `unmodeled-surface` to `review_recommended` twice out of twice, its
  justification no longer mentioning authentication at all. It defines the
  disclosure *recipient* (another organisation) rather than excluding
  internal infrastructure: drafts that said "a new store or component the
  system itself runs is not this" re-filed `dependency-drift` (session
  tokens into Redis) as `unmodeled_surface` three runs out of three, because
  describing the exclusion in component terms reframed a dependency question
  as a data-flow one. And it avoids the phrase "third party", which is the
  name of the dependency category and reads as "third-party library".
- `CONTEXT FILES` lines carry `N→` line-number prefixes, with instructions
  to cite the printed number and to strip the prefix when quoting.
  Upstream runs inside Claude Code where the model reads files with
  numbered lines natively; single-shot CI observed citations landing 1–3
  lines off when the model did its own arithmetic.
- Per-finding `agent_prompt` and `relevance` field guidance (from the PR
  output spec).

## Cloud addendum (`drift-ci-cloud.md`)

Cloud-connected mode appends `drift-ci-cloud.md` to `drift-ci.md` **only when
the request carries an `ORG LIBRARY` section** — that is, when the run holds a
Threatcl API token and the context call succeeded. Local mode's prompt is
byte-identical to before, `drift-ci.md` stays a clean derivation of the
vendored upstream, and `prompt-sync.yml` is untouched.

The addendum covers:

- what `ORG LIBRARY` is (`REFERENCE-ID | name` lines, after `ENABLED
  CATEGORIES`), and that it is data, not instruction;
- the one extra per-finding field, `library_refs`, and when to fill it: only
  for an entry that genuinely fits — an empty array is the normal answer, and
  only ids printed in the section may be used (`findings.PruneLibraryRefs`
  drops anything else in code, the same shape as the evidence rule);
- to prefer `ref = "…"` in `suggested_fix` and `agent_prompt` over a
  generated block, as `/threat-for-code` does;
- that the library never changes a finding's category or severity. That line
  is load-bearing: severity agreement across providers is what keeps
  `fail_mode` provider-independent, and a library must not become a second
  severity rubric.

The schema sent with it is `findings-v0-cloud` — v0 plus the required
`library_refs` array. It is a separate document because every property is
required (OpenAI strict mode insists), so adding the field to v0 would
invalidate all of the committed local-mode recordings.

Recorded 2026-10-26 on all three providers. Every provider cited `T-DATA-004`
(and `C-AUTHZ-003`, a fitting control) on `cloud-library-ref`, cited nothing
on `cloud-library-no-match`, and kept each case's primary finding at
`action_required` — the same tier as its local twin, so the library did not
move the gate. One observation to carry forward rather than act on: on
`cloud-library-ref`, Anthropic and OpenAI both rated a *secondary*
`unclassified_data` finding `action_required`, where their local
`unmodeled-surface` recordings rate the same finding `review_recommended`
(Gemini produced no secondary finding). The exposure — unauthenticated bulk
export of emails — is the named exposure in the severity rule, so the cloud
reading is defensible; but two providers shifting the same way with only the
library added is worth re-checking if the addendum is ever reworded.
