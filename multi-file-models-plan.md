# Plan: multi-file threat model sets

> Working brief for an implementation session. **Do not commit this file** —
> leave it out of every `git add`, and delete it when the feature lands.

## Goal

Let `model_paths` in `.threatcl-ci.hcl` list several `.tm.hcl` files and have
drift-action assess them as one parsed set, including a model hierarchy
(`id = "payments.api"`, `extends = "payments"`) that is split across files.
Fix the single-file hierarchy rendering at the same time, because the same
change covers both.

The pinned `github.com/threatcl/spec v0.8.1` already has everything needed on
the parser side. No spec bump is required.

## What happens today (verified by loading test models through `internal/model`)

- **Several `threatmodel` blocks in one file** work. `Summary`, `Render` and
  `ReferencedPaths` in `internal/model/render.go` loop over every model.
- **`extends` inside one file** runs, but the output is distorted. spec copies
  the parent's threats, information assets, use cases, exclusions and
  third-party dependencies into the child at parse time
  (`inheritFrom` in spec's `parser_extends.go`), and drift-action then renders
  each model separately. With a parent `payments` and a child
  `payments.api extends "payments"`:
  - each inherited threat and control is rendered twice, once per model;
  - the child's copy has no `(file:line)` citation, because `LineIndex` looks
    it up under the child's name and the block sits inside the parent;
  - "Context used" reported 3 threats, 3 controls, 2 information assets for a
    file that declares 2, 2 and 1;
  - neither `id` nor `extends` is rendered, so the reviewing model cannot tell
    the duplicates are one assertion.
- **A hierarchy split across files** fails every way, always with an error:
  - discovery finding more than one file errors and asks for `model_paths`
    (`model.Resolve`, `internal/model/discover.go`);
  - a multi-entry `model_paths` stops at
    `cmd/drift-action/main.go:204` with "assessing multiple threat models in
    one run is not supported yet";
  - `model_paths` naming only the child fails in spec with
    `extends references unknown threat model id 'payments'`, because
    `model.load` parses one file with `ParseFile`.

## spec v0.8.1 API to use

- `(*ThreatmodelParser).ParseHCLRawSet(inputs []spec.NamedInput) error` —
  parses several HCL inputs into one set. Set-level validation (unique names
  and ids, reserved id segments, `extends` resolution) runs once over the
  merged set, so a child may extend a parent in another input in any order.
  `NamedInput{Name string; Content []byte}`.
  - `including` and imports resolve relative to `Name`, so `Name` must be the
    real filesystem path (`filepath.Join(root, rel)`), not the display path.
  - It is HCL-only. There is no JSON equivalent.
  - It does **not** run `validateBackend` the way single-file `parseHCL` does;
    each input may carry its own backend block.
  - It does not expose which input a model came from.
- `(*ThreatmodelParser).SetSkipExtendsResolution(true)` — parse
  "file-faithfully": no inherited items are materialised, `Extends` stays
  populated, and an unknown `extends` target is not an error. All other
  validation is unchanged.
- Threat model names are unique across a parsed set (`validateTms`), which is
  what lets the line index keep its current address keys.

## Design

One set means one assertions section, one inference call and one comment. A
plain single-file model (no `id`, no `extends`) must produce byte-identical
`Render()` output, so every existing corpus recording stays valid —
`fixture.Digest` covers `ReviewRequest.Sections()`, which includes the
rendered assertions.

None of the corpus models, `testdata/simple.tm.hcl` or
`threatcl-drift-action.tm.hcl` uses `id`, `extends`, `including` or `imports`
today, so the new render lines cannot touch them.

### 1. Loading — `internal/model/model.go`

- Add `LoadSet(root string, rels []string) (*Assertions, error)`.
  - De-duplicate `rels`, keep configured order (it is the render order).
  - **One path:** keep the existing `ParseFile` route exactly, so single-file
    behaviour (backend validation, JSON support) does not change.
  - **Two or more paths:** read each file, call `ParseHCLRawSet` with
    `Name = filepath.Join(root, rel)`.
  - A non-`.hcl` file in a multi-file list is a hard error naming the file.
  - A missing or unreadable file is a hard error naming the repo-relative
    path.
  - When spec reports `extends references unknown threat model id`, wrap the
    error with a hint: add the parent's file to `model_paths`.
  - Errors should cite repo-relative paths where practical, as `LoadIn` does
    today for the same reason (a runner-absolute path means nothing to the
    PR reader).
- `Assertions.Source string` becomes a list of sources (keep a convenience
  accessor if it keeps call sites small). `Load` and `LoadIn` can stay as thin
  wrappers over the one-path case so existing tests keep compiling.

### 2. Declared versus inherited content — the two-parse rule

- First parse: resolution on. Its only job when `extends` is in play is
  validation — unknown targets and cycles surface here.
- If any parsed model has `Extends != ""`, parse the same inputs again with
  `SetSkipExtendsResolution(true)` and use **that** result for `Wrapped`.
  Rendering, `Summary` and `ReferencedPaths` then see declared content only.
- If no model uses `extends`, there is no second parse and nothing changes.
- This applies to the one-path route too: it is what fixes the single-file
  duplicates.

Why two parses rather than detecting inherited items after the fact:
`inheritFrom` copies by value and a child's same-named item overrides the
parent's, so a resolved child gives no reliable way to tell an inherited item
from an override. Detecting it by "has no line number" would also misfire on
JSON models and on `including` merges.

### 3. Line index — `internal/model/lineindex.go`

- Index every file in the set. Store file and line per address, not just the
  line, so a citation names the file the block is physically in.
- `Assertions.ref` (in `render.go`) takes the file from the index entry
  instead of `a.Source`.
- Keep the rules already documented in CLAUDE.md: unknown line is 0 and
  renders as no citation, never `:0`; first definition wins.
- `LineIndex.Path()` is used only by `TestLoadInKeepsRelativeSource`; adapt
  or replace it.

### 4. Rendering — `internal/model/render.go`

- Header: `Threat model file: X` stays exactly as is for one file. For
  several, list them all.
- Per model, only when the field is set:
  - a line carrying the declared `id`;
  - a line for `extends` that names the parent and says what is inherited
    (threats, information assets, use cases, exclusions, third-party
    dependencies — not data flow diagrams) and that same-named items declared
    in the child override the parent's.
- Inherited items are therefore rendered once, under the parent, with a real
  citation. A finding about an inherited control cites the parent's block,
  which is the one place to fix it.
- `Summary`: `Path` becomes all paths; counts are over declared items, so
  nothing is double-counted.
- **Do not edit `prompts/drift-ci.md`.** The hierarchy explanation lives in
  the rendered assertions. Prompt edits near the severity section change CI
  outcomes with nothing in code to catch them.

### 5. One loader for the action and the corpus — `internal/engine`

- Move `loadModel` out of `cmd/drift-action/main.go:196` into
  `internal/engine` (for example `engine.LoadModel(workspace, cfg)`), built on
  `model.Resolve` + `model.LoadSet`. Delete the "not supported yet" error.
- `internal/corpus/corpus_test.go` `assemble` (around line 210) currently
  calls `model.Resolve` then `model.LoadIn(workspace, paths[0])`. Switch it to
  the engine function. Same reasoning as the existing CLAUDE.md gotcha about
  `AssembleRequest`: the corpus must load the model the way the action does.
- `main` still maps `model.ErrNoModel` to the existing `skip(...)`.

### 6. Discovery — `internal/model/discover.go`

**Open decision, not yet confirmed by the maintainer.** Default in this plan:
keep `Resolve` erroring when discovery finds several files and `model_paths`
is unset, and reword the error to say that listing several files assesses
them together as one set. Reasoning: smallest behaviour change, and a
monorepo of unrelated models does not silently become one large prompt. The
alternative is to assess every discovered file as a set. Confirm before
changing discovery behaviour beyond the error text.

### 7. Comment — `internal/render/comment.go`

- `ContextInfo.ModelPath` carries every model file; `writeContext` (line 162)
  lists them. One file must render exactly as today.
- `main.go` also logs `summary.Path` at line 100; update it.

### 8. Tests

Add fixtures under `testdata/` (for example `testdata/set/parent.tm.hcl` and
`child.tm.hcl`, plus a single-file hierarchy).

- Cross-file `extends` loads, in either path order.
- Citations name the right file for blocks in each file.
- Inherited items are rendered once; the child shows its `id` and `extends`
  lines.
- `Summary` counts declared items only and lists every path.
- `model_paths` naming only the child errors with the hint.
- A JSON file in a multi-file list errors.
- Duplicate entries in `model_paths` are collapsed.
- Byte-identity: `Render()` for `testdata/simple.tm.hcl` is unchanged
  (compare against output captured before the change).
- Comment renderer: single-file "Context used" line unchanged; multi-file
  line lists every file.
- Update `TestResolveAmbiguous` for the reworded error.

Fixture note: spec requires `description` on every `control` block; a control
without one fails to parse.

### 9. Docs

- `README.md` configuration section (around line 196): `model_paths` may list
  several files, assessed together as one set; cross-file `extends` needs the
  parent listed; multi-file sets are HCL-only.
- `CLAUDE.md` gotchas: the two-parse rule and why; the per-file line index;
  the single-path route deliberately staying on `ParseFile`.
- `threatcl-drift-action.tm.hcl`: check for any single-file claim and for
  prose paths that move (`TestRepoThreatModel` requires every
  prose-referenced path to exist).

## Constraints to respect (from CLAUDE.md)

- Deterministic code extracts facts and never produces findings.
- `prompts/upstream/` is never hand-edited.
- Model output and inference error text reach the comment only through the
  validated report body.
- A change to request assembly stales corpus recordings. This plan is built
  so it does not; the replay below is the proof.

## Verification

```
go build ./... && go vet ./... && go test ./...
THREATCL_DRIFT_CORPUS=replay go test ./internal/corpus -v
```

The corpus replay must pass with no recording touched. A fingerprint mismatch
means the single-file render changed and step 4 needs fixing — do not
re-record to make it pass.

Local lint: the installed `golangci-lint` is too old for this module; use
`staticcheck` via `go run` instead.

## Not in this change

- **An eighth corpus case** for a multi-file set (for example a phantom
  control declared in the parent file). It needs live recordings from all
  three providers, so it needs the maintainer's API keys. The corpus also
  uses `config.Default()` per case, so a multi-file case needs either a
  per-case `model_paths` or the discovery decision in step 6 settled first.
- **claude-plugin `/threat-ci`** should emit a multi-entry `model_paths` when
  a repo has a split hierarchy. That work lands in `../claude-plugin`.
- **Glob support in `model_paths`** (`threatmodels/*.tm.hcl`). If added
  later, a glob matching nothing must be a hard error.
- **`including` merges** still render without citations for the merged-in
  items. Existing behaviour, unchanged here.
