# Threatcl Drift Action

Threat model drift review for pull requests. On each PR, this action answers
one question:

> *Do the code changes in this PR require the threat model to evolve?*

It checks the PR diff against the repo's [Threatcl](https://threatcl.github.io)
`.tm.hcl` threat model and posts a single sticky comment with evidence-backed
findings — the CI counterpart of the
[threatcl claude-plugin](https://github.com/threatcl/claude-plugin)'s
`/threat-drift` command.

> **Status: pre-release.** The engine runs end to end — it parses the model,
> selects the diff, and reviews it — but the finding quality has not been
> validated on a corpus yet, and the action is not tagged for release. See
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

# One review in flight per PR. A push supersedes the run for the previous
# commit rather than racing it for the sticky comment.
concurrency:
  group: threat-drift-${{ github.event.pull_request.number }}
  cancel-in-progress: true

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

The `concurrency` block matters more here than in most workflows: the review
takes minutes of inference, and without it two rapid pushes race to update the
same sticky comment — last writer wins, possibly with findings from the older
commit. Cancelling the in-flight run means the comment always reflects the
newest push.

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

### Testing without paying for inference

Iterating on the GitHub half of the pipeline — comment upsert, sticky updates,
check runs, outputs — means running the action over and over, and each run is
a paid review of the same unchanged diff. Record one review, then replay it:

```bash
# Once, with a key: run the review and write it out on the way past.
THREATCL_DRIFT_RECORD=testdata/recordings/my-pr.json … /tmp/drift-action

# Thereafter, free and offline. No API key needed.
THREATCL_DRIFT_REPLAY=testdata/recordings/my-pr.json … /tmp/drift-action
```

A replayed run says so in the comment's "Analysis" line, and the recording
carries the pull request and head SHA it came from plus a fingerprint of the
prompt it was recorded against — so replaying over a diff that has since moved
on is reported rather than passed off as a fresh review. The recorded report is
re-validated against the schema on the way out, exactly as a live response is.

This is a local testing affordance. Do not wire either variable into a real
workflow: a replayed review says nothing about the pull request in front of it.
See [`testdata/recordings/`](testdata/recordings/).

Two things differ when driving the binary by hand rather than from a workflow.

Check runs can only be created by a GitHub App, so a personal access token gets
`403 You must authenticate via a GitHub App` — the comment still posts, and the
run logs the check run as a warning rather than failing, exactly as it does for
a fork PR's read-only token. Under Actions, `GITHUB_TOKEN` is an app
installation token and `checks: write` works.

And `GITHUB_WORKSPACE` has to hold the repository at the pull request's head
commit. The diff arrives from the compare API, but context stuffing reads whole
files from that directory — point it at a stale tree and the review answers
"was the code behind this control removed?" from the wrong revision.

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total drift findings |
| `action-required-count` | Findings at the Action required tier |
| `verdict` | `clean` \| `findings` \| `action-required` \| `unassessed` \| `skipped` \| `error` |
| `report-path` | Path to the rendered markdown report (written under `RUNNER_TEMP`) |

`clean` is reserved for a run where the model actually assessed the change and
found it consistent. A run that produced no findings because it assessed
nothing — no API key, no reviewable file, a refused request — reports
`unassessed`, so a workflow gating on this output cannot mistake silence for
safety. `skipped` means the run did not apply at all (no pull request, or no
threat model in the repo); `error` means the action itself failed.

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
  max_tokens  = 32000  # covers thinking as well as the findings array
  api_key_env = "ANTHROPIC_API_KEY"
}

limits {
  max_diff_files    = 200    # hard cap on files sent to review; over it, no review runs
  max_patch_bytes   = 400000 # cap on the rendered diff
  max_context_bytes = 200000 # cap on whole files sent alongside it
  narrow_above      = 50
}
```

An unknown category, fail mode, effort level or provider is a hard error
rather than a silent default, so a typo can never quietly disable a drift
check or fail the request after the diff has already been fetched.

`max_tokens` bounds the model's output *including* its thinking. Too tight and
the report is truncated mid-JSON, which the run reports as an error rather than
rendering a half-written review.

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

If more than `max_diff_files` files still need review after filtering and
narrowing, no review runs at all. The comment says the diff is too large and
to run `/threat-drift` locally with the [threatcl
claude-plugin](https://github.com/threatcl/claude-plugin), the check run stays
neutral, and the verdict is `unassessed`. The cap is deliberately
all-or-nothing — reviewing the first 200 files of a 500-file diff would
present partial coverage as a review.

## Security notes

- Use the `pull_request` trigger (as scaffolded above), not
  `pull_request_target`. Fork PRs then run without secrets, so no review is
  produced and the comment says so — rather than posting a shallow result that
  looks like a review and is not.
- PR content is treated as data, never instructions; the LLM's output is
  forced into a JSON schema and influences nothing but the report body, and
  findings without code evidence are discarded.
- The models this action uses carry elevated cybersecurity safeguards, and it
  sends security-relevant diffs and asks what attack surface they introduce.
  A declined request is re-served on a fallback model automatically, and the
  comment names the model that answered when that happens. If the review
  cannot be produced at all, the comment says the change could not be
  assessed — never that there is no drift.
- Self-hosted by design: your code and threat model go only to the LLM
  provider you configure, under your own key — never to threatcl.

## Related

- [threatcl](https://github.com/threatcl/threatcl) — the CLI
- [threatcl/spec](https://github.com/threatcl/spec) — the HCL spec and parser
- [threatcl/claude-plugin](https://github.com/threatcl/claude-plugin) — local
  threat modeling commands, including `/threat-drift`
- [threatcl/threatcl-action](https://github.com/threatcl/threatcl-action) —
  validate/export/dashboard as a build step
