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
| `anthropic-api-key` | — | LLM API key; without one, no drift category is assessed |
| `github-token` | `${{ github.token }}` | Reads the PR diff, writes the comment/check |
| `fail-mode` | from config | `never` \| `on-action-required` |
| `model` | from config | Override the LLM model |
| `dry-run` | `false` | Render and log the review without posting anything |

### Trying it without posting

`dry-run` fetches the diff and renders the full review, then prints it instead
of writing to the pull request. Use it to trial the action on real PRs before
letting it comment:

```yaml
- uses: threatcl/drift-action@main
  with:
    dry-run: true
```

Running the binary locally works the same way. The action input arrives as
`INPUT_DRY-RUN`, and a hyphen cannot appear in a shell variable name, so there
is a shell-friendly alias:

```bash
go build -o /tmp/drift-action ./cmd/drift-action

gh pr view 210 --repo threatcl/threatcl \
  --json number,baseRefOid,headRefOid \
  --jq '{pull_request:{number:.number, base:{sha:.baseRefOid}, head:{sha:.headRefOid}}}' \
  > /tmp/event.json

THREATCL_DRIFT_DRY_RUN=true \
GITHUB_REPOSITORY=threatcl/threatcl \
GITHUB_EVENT_PATH=/tmp/event.json \
GITHUB_WORKSPACE=/tmp/ws \
GITHUB_TOKEN="$(gh auth token)" \
RUNNER_TEMP=/tmp \
/tmp/drift-action
```

A token is still required — the diff comes from the GitHub compare API — but
no comment or check run is written. A value that is not a boolean is a hard
error rather than a silent `false`, so a typo can never post a comment you
thought you had suppressed. Dry run suppresses writes only; it does not change
the verdict or the exit code.

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total drift findings |
| `action-required-count` | Findings at the Action required tier |
| `verdict` | `clean` \| `findings` \| `action-required` \| `skipped` \| `error` |
| `report-path` | Path to the rendered markdown report (written under `RUNNER_TEMP`) |

### Configuration

The long tail lives in a repo-level `.threatcl-ci.hcl`. Every setting is
optional — without the file, the action discovers a single `*.tm.hcl` at the
repo root or under `threatmodels/` and uses the defaults below.

```hcl
# Which model to assess. Required only when the repo has more than one.
model_paths = ["threatmodels/payments.hcl"]

# Restrict the drift categories assessed. Omit to run all six.
categories = ["phantom_control", "stale_assertion", "dependency_drift"]

# Paths that must always be reviewed, even when a large diff is narrowed.
# A trailing slash matches by prefix; otherwise the pattern is matched with
# path.Match, and a bare filename matches wherever it sits in the tree.
trigger_paths = ["src/payments/", "cmd/*.go"]

# never (default) | on-action-required
fail_mode = "never"

llm {
  provider    = "anthropic"
  model       = "claude-opus-5"
  effort      = "high" # low | medium | high | xhigh | max
  api_key_env = "ANTHROPIC_API_KEY"
}

limits {
  max_diff_files  = 200
  max_patch_bytes = 400000
  narrow_above    = 50
}
```

An unknown category or fail mode is a hard error rather than a silent default,
so a typo can never quietly disable a drift check.

### What gets reviewed

Two rules decide which changed files reach the review, and the comment always
reports the outcome of both.

Documentation, lock files, images, and vendored or generated code are always
skipped — they cannot carry threat model drift. Dependency manifests
(`go.mod`, `package.json`, …) are never skipped, whatever else the rules say.

Everything else is reviewed. Only when a diff exceeds `narrow_above` files is
it cut down to security-relevant paths to stay within budget, and when that
happens the comment says how many files went unreviewed. The default is to
keep a file, not to drop it: under-reviewing a PR produces a clean-looking
result that hides real drift, which is the worst outcome this action has.

## Security notes

- Use the `pull_request` trigger (as scaffolded above), not
  `pull_request_target`. Fork PRs then run without secrets, so no review is
  produced and the comment says so — rather than posting a shallow result that
  looks like a review and is not.
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
