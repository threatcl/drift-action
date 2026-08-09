# Recorded reviews

Captured model output for a specific pull request, replayed with
`THREATCL_DRIFT_REPLAY` so the GitHub half of the pipeline — comment upsert,
sticky updates, check runs, action outputs — can be exercised repeatedly
without paying for inference each time.

A recording is only meaningful against the diff it was made from. Each file
carries its `source` (`owner/repo#number@sha`) and a `request_digest`
fingerprinting the prompt sections it was recorded from; on replay a mismatch
is reported in the comment rather than passed off as a fresh review. A
replayed run always says so in its "Analysis" line, whatever the findings say.

## Recording one

```bash
THREATCL_DRIFT_RECORD=testdata/recordings/<name>.json \
ANTHROPIC_API_KEY=… \
  ./drift-action        # plus the usual GITHUB_* environment
```

The review runs and is written out on the way past, so a recording costs one
real review and nothing after that.

## Replaying it

```bash
THREATCL_DRIFT_REPLAY=testdata/recordings/<name>.json ./drift-action
```

No API key is needed. The recorded report is re-validated against
`internal/findings/schema/findings-v0.schema.json` on the way out: a fixture is
not trusted just because it is on disk, and a hand-edited one cannot put
anything past the schema that a model could not.

## The files

| File | Source | Notes |
|------|--------|-------|
| `growud-test-1.json` | `threatcl/growud-test#1` — a PR adding an unauthenticated `/api/export` bulk CSV endpoint | 3 findings (1 action required) across unmodeled surface, stale assertion, DFD drift |

`growud-test-1.json` was reconstructed from the rendered output of a real
`claude-opus-5` review rather than captured with `THREATCL_DRIFT_RECORD`, so it
carries no `request_digest` and replay reports that it could not be checked
against the diff. Re-record it to get a fingerprinted one.
