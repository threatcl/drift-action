# Releasing

The action ships as a container image on ghcr. A release is a **workflow run,
not a tag push**: you dispatch `.github/workflows/release.yml` with the version
you want, and it publishes the image, writes that image's digest into
`action.yml` on `main`, tags that commit, and moves the `v0` alias onto it.

Pushing a `vX.Y.Z` tag by hand publishes nothing. Nothing in `release.yml`
triggers on a ref.

## What a consumer actually references

A consumer writes `uses: threatcl/drift-action@v0`. Git resolves `v0` to the
released commit, GitHub reads *that commit's* `action.yml`, and `action.yml`
names an exact image. The ref moves; the engine behind it stays pinned.

Pinned by **digest** — `docker://ghcr.io/threatcl/drift-action@sha256:…` — not
by version tag. A ghcr tag is itself a mutable pointer that anyone with
`packages: write` can repoint silently, the same class of problem as the
force-moved `v0` alias, one link further down the chain. A digest names one
immutable manifest and the runner rejects anything else.

That is the reason for the publish-before-tag order below. A digest can only
name an image that already exists, so the image has to be pushed before the
commit that names it is written, and that commit has to exist before it can be
tagged. The old order — tag first, build from the tag — could only ever pin
`:vX.Y.Z`, so every release after the v0.1.1 bootstrap would have shipped a
weaker pin than v0.1.1 did.

`image: 'Dockerfile'` works too, and is what the repo shipped pre-release, but
it makes every consumer build the container on every run: roughly seven minutes
before the review even starts, against seconds to pull. That gap is the whole
reason to cut a release.

## Steady-state release

1. Open a release PR for anything that has to change *with* the version — the
   README if the inputs, outputs or config surface moved, the threat model if
   a control did. **Not `action.yml`'s `image:`**: the workflow writes that
   line itself, and hand-editing it only creates a conflict with the commit it
   pushes.
2. Merge it, and let CI go green on `main`.
3. Actions → **release** → *Run workflow*, with `version` set to the version
   you are cutting (`v0.1.2`). Dispatch it from `main`; the ref decides which
   copy of the workflow runs, and the release is always cut from `main`'s tip
   regardless.
4. Approve the run if the `release` environment asks — see below.

The workflow then, in order:

- refuses if `vX.Y.Z` already exists — as a git tag, or as a published image
  tag left by an earlier run — before anything is published
- builds and pushes `ghcr.io/threatcl/drift-action:vX.Y.Z`, stamped with that
  version in both the OCI label and the binary's `main.version`
- reads the pushed digest back, rewrites `action.yml`'s `image:` line to name
  it, and commits that to `main`
- tags that commit `vX.Y.Z`
- moves `v0` onto it

So the tagged commit is the commit the image was built from, plus one line: the
digest of that image. The difference cannot affect the image, because
`action.yml` is metadata the *runner* reads and is never consulted inside the
container. The job refuses to continue if `main` moved between the build and
the commit, so the two never drift further apart than that line.

There is no longer a window where `@v0` resolves to an `action.yml` naming an
image that is not published yet. Publish happens first.

### Who can cut a release

Cutting a release used to require pushing a `vX.Y.Z` tag, which the *release
tags are immutable* ruleset restricts to repository admins. The workflow
creates that tag now, so two settings carry that gate instead. Both are
configured; both are prerequisites if this is ever rebuilt elsewhere.

- The **release app is a bypass actor on the *release tags are immutable*
  ruleset**, so it can create `refs/tags/v*.*.*`. Without it the release
  publishes an image and then fails at the tag push. Note what else it buys:
  a bypass list exempts an actor from the whole ruleset, not from one rule, so
  the app can also update or delete a released version tag. Nothing but the
  workflow's own restraint stops it.
- The **`release` environment requires a reviewer** before `publish-image`
  runs. An environment with no protection rules is inert, so this is the line
  between "anyone who can dispatch a workflow can cut a release" and the
  admin-only gate it replaced.

Not set, and worth setting: the environment's **deployment branch policy is
unrestricted**. The dispatch ref decides which copy of `release.yml` runs, and
the approval prompt does not show the reviewer which revision they are
approving — so restricting the environment to `main` is what stops a release
being cut from a branch carrying a modified workflow.

## When a release fails partway

Publishing is now the first irreversible step, so a failure after it leaves an
image nothing references. That is the recoverable direction, and it is
deliberate — the opposite order leaves a tag consumers resolve pointing at an
engine that does not exist.

| Fails at | State left behind | What to do |
|---|---|---|
| version validation, existing-tag check | nothing | fix the input, re-dispatch |
| build and push | possibly a partial image, no tags | re-dispatch; if `:vX.Y.Z` did land, delete it first or the guard refuses |
| digest rewrite, `main` moved, push to `main` | `:vX.Y.Z` published, unreferenced | re-dispatch the same version after deleting the ghcr image tag, or move to the next patch version |
| tag push | as above, plus the digest commit on `main` | usually the app is not allowed to create `v*.*.*` — fix the ruleset, then tag that commit by hand or re-dispatch as the next version |
| alias move | released, but `@v0` still names the previous release | re-run the job; the ancestry check passes once the commit is on `main` |

An unreferenced image is inert: no git ref names it, so no consumer can resolve
it. Clean it up or leave it, but do not repoint a published version tag at a
new build — re-dispatching *the same* version is refused for that reason, and
deleting the image tag first is what makes it possible.

## Registry tags this repository publishes

One per release, `:vX.Y.Z`, and nothing else.

There is deliberately no `:latest`. Nothing references it — not `action.yml`,
not this document, not any documented consumer path — so it was a mutable
pointer this repository published and nothing it shipped relied on. It was also
wrong for its whole life: the self-retriggered release run left `:latest`
pointing at a build stamped `v0` rather than at the v0.1.1 release image.
`flavor: latest=false` is the standing decision, not an oversight.

A stray mutable `:v0` image tag existed from that same run, sharing a manifest
with the mis-stamped `:latest`. Both were deleted on 2026-08-12 — in ghcr a
package version is a digest with tags attached and there is no untag-one
operation, so removing the version was what dropped them. No current path
republishes either: the workflow has no ref trigger to re-enter, and `:latest`
is off by decision rather than by accident.

## How v0.1.0 and v0.1.1 were bootstrapped

History, kept because it explains why v0.1.1's `action.yml` names the *v0.1.0*
image. No image and no `v0` tag existed, so the first release could not name a
digest at all.

- **v0.1.0** shipped with `image: 'Dockerfile'` and published the first image.
  Correct but slow: consumers built the container on every run.
- **v0.1.1** pinned that published image by digest, and in the same PR moved
  `.github/workflows/threat-drift.yml` from `uses: ./` to the v0.1.0 release
  commit SHA, flipped the **"Pin the workflow to the released action"** control
  in `threatcl-drift-action.tm.hcl` to `implemented = true`, and dropped the
  README's pre-release banner.

Naming the previous release's image was legitimate only because that PR changed
no engine code — the binary was identical, and the threat model and config are
read from the workspace at runtime. It is not a precedent: from v0.1.2 the
workflow names the image it just built, so no release pins a predecessor's
engine under a newer tag.

## Why this repo's own job does not use `@v0`

Consumers are pointed at `@v0` because following patches without editing a
workflow is what most repositories want. This repository's drift job is the
exception: it holds the Anthropic key and a token that can write to pull
requests, and the release moves `v0` every time. Pinning it to the alias would
trade a PR-controlled engine for a dispatch-controlled one rather than for a
fixed one — see the *Mutable major alias repointed at attacker-chosen code*
threat in `threatcl-drift-action.tm.hcl`.

So it pins a commit SHA, and Dependabot bumps it. Two consequences follow, both
accepted deliberately:

- The dogfood job no longer runs the pull request's own engine, so it has
  stopped being an end-to-end test of the code under review. That coverage now
  lives in `ci.yml` — the unit suite, the corpus replay, and the docker build.
- The pin lags one release, because the SHA of the release being cut does not
  exist while it is being cut. Under the new ordering it does not exist until
  the workflow creates it, so the lag is structural rather than procedural.

That threat-model edit is not bookkeeping. The control was `implemented = false`
for as long as `uses: ./` was a deliberate pre-release choice, and the flag has
to move in the same commit as the pin. Ship one without the other and the action
should report a phantom control against its own threat model on the next pull
request — a fine way to find out, but a worse way than remembering. The same
applies in reverse to anything that later loosens the pin.

## Before dispatching

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `THREATCL_DRIFT_CORPUS=replay go test ./internal/corpus`
- [ ] the README's inputs and outputs tables match `action.yml`
- [ ] `prompts/upstream/SOURCE` is current if the prompt was re-vendored
- [ ] `main` is at the commit you mean to release — the workflow builds its
      tip, not the dispatch ref
- [ ] the `RELEASER_APP_ID` variable and `RELEASER_APP_PRIVATE_KEY` secret
      exist, and the release app can create `refs/tags/v*.*.*` as well as move
      `refs/tags/v0`. Without the tag grant the release publishes an image and
      then fails with nothing tagged

`action.yml`'s image reference is no longer on this list. The workflow writes
it, so it cannot disagree with the tag being cut.
