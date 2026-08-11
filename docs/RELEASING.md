# Releasing

The action ships as a container image on ghcr. A release is a git tag;
`.github/workflows/release.yml` does the rest — it builds and pushes the
image, then moves the `v0` alias so `uses: threatcl/drift-action@v0` follows.

## What a consumer actually references

A consumer writes `uses: threatcl/drift-action@v0`. Git resolves `v0` to the
released commit, GitHub reads *that commit's* `action.yml`, and `action.yml`
names an exact image — `docker://ghcr.io/threatcl/drift-action:vX.Y.Z`. The
ref moves; the engine behind it stays pinned.

Pinned by tag, though, not by content: a ghcr tag is itself a mutable
pointer, and anyone with `packages: write` can repoint it silently — the
same class of problem as the force-moved `v0` alias, one link further down
the chain. The immutable form is a digest
(`docker://ghcr.io/threatcl/drift-action@sha256:…`), but a digest can only
name an image that already exists, and the steady-state order tags the
commit before its image is built. Digest-pinning every release would need a
publish-before-tag flow, which this is not. Steady-state releases accept
the tag-pin residual; the one place a digest pin is free is the v0.1.1
bootstrap flip below, and it takes it.

`image: 'Dockerfile'` works too, and is what the repo ships pre-release, but
it makes every consumer build the container on every run: roughly seven
minutes before the review even starts, against seconds to pull. That gap is
the whole reason to cut a release.

## Steady-state release

1. Open a release PR that sets `action.yml`'s `image:` to
   `docker://ghcr.io/threatcl/drift-action:vX.Y.Z` — **the version you are
   about to tag**, not the one already out — and updates the README if the
   inputs, outputs or config surface changed.
2. Merge it.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
4. Watch `release.yml`: it publishes the image, then moves `v0`.

Between steps 3 and 4 there is a window of a few minutes where `@v0` resolves
to an `action.yml` naming an image that is not published yet. A run that lands
in it fails to pull and succeeds on re-run.

Do not close that window by pinning the *previous* version in `action.yml`.
It removes the window at the cost of making `@vX.Y.Z` run the engine from
X.Y.Z-1 — a silent lie about which code reviewed the pull request, which is a
far worse trade than a few minutes of pull failures.

The dogfooding workflow is unaffected either way: after the first release it
uses `@v0`, not `./`, so it never reads the working tree's `action.yml`.

## The first release: bootstrapping v0.1.0

No image and no `v0` tag exist yet, so the steady-state order cannot be used
as written. Flipping `action.yml` to `docker://…` before any image is
published would break `uses: ./` in the dogfood workflow on that very pull
request — it would try to pull an image that does not exist.

Bootstrap across two tags instead.

**v0.1.0 — publish the first image**

1. Leave `action.yml` at `image: 'Dockerfile'`.
2. Tag `v0.1.0` on `main` and push it.
3. `release.yml` publishes `ghcr.io/threatcl/drift-action:v0.1.0` and creates
   `v0`. `uses: threatcl/drift-action@v0` now works — building from the
   Dockerfile, so correct but slow.

**v0.1.1 — switch to the published image**

4. Open one PR that does all of:
   - sets `action.yml` to `docker://ghcr.io/threatcl/drift-action@sha256:…`,
     the **digest of the v0.1.0 image** — the ghcr package page shows it, as
     does `gh api /orgs/threatcl/packages/container/drift-action/versions`.
     A digest, unlike a tag, cannot be repointed. It is available because
     v0.1.0 is already published, and it is honest because this PR changes
     no engine code — the image is just the static binary; the threat model
     and config are read from the workspace at runtime. This is not the
     previous-version pin forbidden above: that rule guards against an older
     engine lying under a newer tag, and these two engines are identical
   - changes `.github/workflows/threat-drift.yml` from `uses: ./` to
     `uses: threatcl/drift-action@v0`
   - flips the **"Pin the workflow to the released action"** control in
     `threatcl-drift-action.tm.hcl` to `implemented = true` and rewrites its
     implementation notes
   - drops the pre-release banner from the README and changes the usage
     examples from `@main` to `@v0`

   The dogfood job on this PR runs `@v0` — v0.1.0's engine, built from its
   Dockerfile — so it is green whether or not the v0.1.1 image exists yet.
5. Merge, tag `v0.1.1`, push. Steady state applies from here.

Step 4's threat-model edit is not bookkeeping. That control is
`implemented = false` today because `uses: ./` is a deliberate pre-release
choice. Ship the pin without flipping the flag and the action should report a
phantom control against its own threat model on the next pull request. That is
a fine way to find out, but a worse way than remembering.

## Before tagging

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `THREATCL_DRIFT_CORPUS=replay go test ./internal/corpus`
- [ ] `action.yml`'s image reference matches the tag about to be pushed
      (steady state — the v0.1.1 flip digest-pins the v0.1.0 image instead)
- [ ] the README's inputs and outputs tables match `action.yml`
- [ ] `prompts/upstream/SOURCE` is current if the prompt was re-vendored
- [ ] the `RELEASER_APP_ID` variable and `RELEASER_APP_PRIVATE_KEY` secret
      exist — the `major-alias` job pushes `v0` with a token minted from the
      release app, because the tag ruleset lets only that app move the alias.
      Without them the release publishes but the alias never moves
