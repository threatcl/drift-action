# Finding-quality corpus

Paired threat models and synthetic diffs with known expected findings — one
case per drift category, plus a `clean` case that must produce none. This is
the suite that says whether the engine is any good; everything else in the
repo only says whether it runs.

The harness is `internal/corpus/corpus_test.go`.

## Running it

`TestCorpusAssembles` always runs (free) and proves every case parses and
assembles into a review request. `TestCorpus` runs actual reviews and is
gated on an env var so `go test ./...` never costs money:

```bash
# Pay for a full run, ~7 reviews at the default model and effort:
THREATCL_DRIFT_CORPUS=live ANTHROPIC_API_KEY=… go test ./internal/corpus -v -timeout 60m

# Pay once, and keep each case's review in <case>/recording.json:
THREATCL_DRIFT_CORPUS=record ANTHROPIC_API_KEY=… go test ./internal/corpus -v -timeout 60m

# Re-assert against the recordings, free and offline:
THREATCL_DRIFT_CORPUS=replay go test ./internal/corpus -v
```

A replayed case asserts what the engine produced when it was recorded — it
exercises the harness, the schema, and the evidence rule for free, but says
nothing about the current prompt. When a recording's fingerprint no longer
matches the assembled request, the case logs it; re-record to re-measure.

## Case layout

```
<case-name>/
  workspace/           the repo at PR head: the .tm.hcl, plus any file the
                       model references that the diff touches (context stuffing
                       reads exactly that intersection — other files are never
                       read and are not included)
  changes.json         the PR diff: [{path, status, patch_file}, …]
  patches/*.patch      unified-diff hunks, GitHub compare API style: hunks
                       only, no ---/+++ headers. Blank context lines must be
                       a single space, never empty — the manifest parser
                       skips empty lines and line numbers desync.
  expected.json        what a good review must produce
  recording.json       written by record mode; not committed until it has been
                       eyeballed
```

`expected.json`:

```json
{
  "description": "one paragraph on what drifted and why the expectation holds",
  "no_drift": false,
  "context_files": ["internal/auth/ratelimit.go"],
  "findings": [
    {"category": "phantom_control", "evidence_file": "internal/auth/ratelimit.go"}
  ]
}
```

## What is asserted, and what deliberately is not

A case passes when, for every expected finding, the review produced **at
least one finding of that category whose evidence cites that file**. The
clean case passes when the review produced **no findings and said
`no_drift`** — a finding there is the cries-wolf failure mode, and it fails.

Severity and line numbers are **never** asserted: both proved unstable across
identical runs. Extra findings beyond the expected ones are logged for
eyeballing, never failed — over-reporting an adjacent category (a phantom
control that also reads as a stale assertion, say) is judgement, not error.

`context_files` is asserted in the free test: cases that hinge on context
stuffing (phantom controls above all — "is the code really gone, or just
outside the hunk?") declare the file, so an assembly regression fails CI
instead of silently weakening the case.

## Adding a case

1. Write the smallest `workspace/` and diff that exhibit exactly one drift
   category. Keep the confession out of the code — the diff shows the
   change; comments must not narrate it.
2. Count hunk line numbers accurately. The model cites lines it computes
   from the `@@` headers; sloppy headers produce off-by-N citations.
3. Run the free test, then one paid run of just the new case:
   `THREATCL_DRIFT_CORPUS=live … go test ./internal/corpus -run 'TestCorpus/<case>' -v -timeout 20m`
