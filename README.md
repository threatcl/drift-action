# Threatcl Drift Action

Threat model drift review for pull requests. On each PR, this action answers
one question:

> *Do the code changes in this PR require the threat model to evolve?*

It checks the PR diff against the repo's [Threatcl](https://threatcl.github.io)
`.tm.hcl` threat model and posts a single sticky comment with evidence-backed
findings — the CI counterpart of the
[threatcl claude-plugin](https://github.com/threatcl/claude-plugin)'s
`/threat-drift` command.

> **Status: pre-release skeleton.** The action interface, report schema, and
> prompts are in place; the drift engine is not implemented yet. See
> [docs/phase1-plan.md](docs/phase1-plan.md).

## What it detects

| Category | Example |
|----------|---------|
| Stale assertions | Model says "passwords hashed with BCrypt"; PR switches schemes |
| Phantom controls | Control claims `implemented = true`; PR deleted the middleware |
| New unmodeled surface | New public endpoint with no corresponding threat |
| DFD drift | Service starts calling a third-party API missing from the DFD |
| Dependency drift | `go.mod` adds a crypto library with no `third_party_dependency` block |
| Unclassified data | New `ssn` field with no `information_asset` coverage |

Findings carry `file:line` evidence and a copy-paste **agent prompt** for
updating the model with the claude-plugin. When there is no drift, the comment
says so plainly.

## Usage

```yaml
name: threat-drift
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: threatcl/drift-action@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `config-path` | `.threatcl-ci.hcl` | Path to the drift config file |
| `anthropic-api-key` | — | LLM API key; omit to run deterministic checks only |
| `github-token` | `${{ github.token }}` | Reads the PR diff, writes the comment/check |
| `fail-mode` | from config | `never` \| `on-action-required` |
| `model` | from config | Override the LLM model |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total drift findings |
| `action-required-count` | Findings at the Action required tier |
| `verdict` | `clean` \| `findings` \| `action-required` \| `skipped` \| `error` |
| `report-path` | Workspace-relative path to the rendered report |

### Configuration

The long tail lives in a repo-level `.threatcl-ci.hcl` (design in
[docs/phase1-plan.md](docs/phase1-plan.md)): threat model paths, enabled
categories, extra trigger paths, fail mode, provider/model, diff size limits.

## Security notes

- Use the `pull_request` trigger (as scaffolded above), not
  `pull_request_target`. Fork PRs then run without secrets and the action
  degrades to deterministic-only checks.
- PR content is treated as data, never instructions; the LLM's output is
  forced into a JSON schema and influences nothing but the report body, and
  findings without code evidence are discarded.
- Self-hosted by design: your code and threat model go only to the LLM
  provider you configure, under your own key — never to threatcl.

## Related

- [threatcl](https://github.com/threatcl/threatcl) — the CLI
- [threatcl/spec](https://github.com/threatcl/spec) — the HCL spec and parser
- [threatcl/claude-plugin](https://github.com/threatcl/claude-plugin) — local
  threat modeling commands, including `/threat-drift`
- [threatcl/threatcl-action](https://github.com/threatcl/threatcl-action) —
  validate/export/dashboard as a build step
