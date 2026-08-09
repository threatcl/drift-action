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
  `action_required`).
- Per-finding `agent_prompt` and `relevance` field guidance (from the PR
  output spec).
