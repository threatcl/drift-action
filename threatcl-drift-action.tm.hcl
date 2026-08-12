spec_version = "0.7.0"

backend "threatcl-cloud" {
  organization = "weyland"
  threatmodel = "threatcl-drift-action"
  # threatmodel slug is added automatically on first `threatcl cloud push`
}

threatmodel "threatcl-drift-action" {
  description = "Self-hosted GitHub Action that reviews pull requests for drift between what the code does and what the repo's Threatcl threat model asserts"
  author      = "Christian Frichot"

  attributes {
    new_initiative  = "true"
    internet_facing = "false"
    initiative_size = "Medium"
  }

  information_asset "repository source code" {
    description                = "Full contents of security-relevant repo files plus the PR diff, selected as context and transmitted to the LLM provider on every review"
    information_classification = "Confidential"
  }

  information_asset "review findings" {
    description                = "Drift findings posted as PR comments and check runs — an enumeration of gaps between the code and its threat model, visible to anyone who can read the PR"
    information_classification = "Confidential"
  }

  information_asset "action credentials" {
    description                = "The Anthropic API key, the OpenAI API key and the GitHub token the action holds at runtime; the token carries PR write permission. Both provider keys are forwarded into the container unconditionally by action.yml — deciding which to forward would need the config file read before the container starts — and the engine reads only the one its configured api_key_env names, so an unset input arrives as an empty string and counts as no key. Release time adds a second set, held by .github/workflows/release.yml rather than the engine: a packages: write token for the ghcr push, the RELEASER_APP_PRIVATE_KEY GitHub App private key secret and the RELEASER_APP_ID variable identifying the app, and the short-lived installation token minted from them by actions/create-github-app-token@v2 in the tag-release job — that job's own GITHUB_TOKEN is contents: read, and it is the installation token, persisted as the checkout push credential, that pushes the digest commit to main and can create and force-move tags in this repository, including the floating major alias consumers resolve. Any workflow run on a non-fork ref that can read RELEASER_APP_PRIVATE_KEY can mint that token"
    information_classification = "Restricted"
  }

  usecase {
    description = "A pull request triggers a drift review: the action fetches the diff via the GitHub compare API, sends it with targeted context to the LLM, and posts a sticky comment plus a check run describing any drift"
  }

  threat "Prompt injection via PR-controlled diff or context files" {
    ref         = "TCL-T-LLM-PROMPTINJ"
    description = "A PR author embeds instructions or counterfeit section markers in the diff or in repo files selected as context (internal/llm/sections.go builds the prompt from both) to suppress drift findings or forge evidence citations that the evidence sanitizer cannot distinguish from real ones"
    impacts     = ["Integrity"]
    stride      = ["Tampering", "Spoofing"]

    control "Schema-forced JSON and evidence sanitization" {
      ref            = "TCL-C-LLM-SCHEMA"
      description    = "Output must validate against the findings-v0 schema in internal/findings/validate.go; findings.Sanitize in internal/findings/schema.go drops evidence-free findings in code, not just in the prompt"
      implemented    = true
      risk_reduction = 40
    }

    control "Model output reaches only the report body" {
      ref            = "TCL-C-LLM-CONTAIN"
      description    = "LLM output influences nothing but the rendered comment body built in internal/render/comment.go; inference error text never reaches the comment (failureKind in cmd/drift-action/main.go)"
      implemented    = true
      risk_reduction = 70
    }
  }

  threat "PR-authored engine code runs in the privileged dogfooding job" {
    description            = "A pull request supplies the engine that reviews it, not merely the content being reviewed. Whenever .github/workflows/threat-drift.yml resolves the action from the pull request's own tree — uses: ./, or any ref an author can move — PR-authored changes to the Dockerfile, the entrypoint or any package under internal/ execute in a runner granted pull-requests: write and checks: write and handed secrets.ANTHROPIC_API_KEY, with that key in their environment and a token that can write comments and check runs. The 'Prompt injection via PR-controlled diff or context files' threat covers only what a pull request puts in the prompt; this covers what it puts in the program, which no schema or evidence sanitizer constrains. The workflow ran uses: ./ through v0.1.0 and now pins a released commit SHA, so the path is closed unless that pin is loosened"
    impacts                = ["Confidentiality", "Integrity"]
    stride                 = ["Elevation Of Privilege", "Tampering"]
    information_asset_refs = ["action credentials"]

    control "Fork pull requests receive no secrets" {
      description    = "GitHub withholds repository secrets from pull_request runs raised from a fork and issues a read-only GITHUB_TOKEN regardless of the workflow's permissions block, so for an untrusted author ANTHROPIC_API_KEY resolves empty and the write grants are inert. Platform behaviour rather than anything this repo enforces, and it does nothing for a branch PR from someone who already has write access — which is who raises every PR here today"
      implemented    = true
      risk_reduction = 50
    }

    control "Pin the workflow to the released action" {
      description          = ".github/workflows/threat-drift.yml resolves threatcl/drift-action at an immutable released commit SHA rather than building the pull request's own tree, so a fixed, published engine reviews every PR. Not @v1: the major alias is force-moved on every release, so pinning to it would leave the reviewing engine mutable"
      implemented          = true
      implementation_notes = "Done: .github/workflows/threat-drift.yml pins threatcl/drift-action to a released commit SHA, with the version in a trailing comment so Dependabot's github-actions ecosystem bumps it. Which release it sits on is recorded once, at the end of this note — naming it twice is how the two halves drifted apart the first time. Not @v1, deliberately — that alias is force-moved with git tag -f and git push origin -f on every release, so pinning to it would trade a PR-controlled engine for a tag-push-controlled one rather than for a fixed target; see the 'Mutable major alias repointed at attacker-chosen code' threat. Consumers are documented on @v1 for the usual reasons, but this privileged job holds the Anthropic key and a write-scoped token, so it takes the SHA. One consequence of the pin is worth knowing: the dogfooding job no longer runs the pull request's own engine, so it has stopped being an end-to-end test of the code under review — that coverage now rests on the unit suite, the corpus replay and the docker build in .github/workflows/ci.yml. The pin necessarily trails one release, since the SHA of the release being cut does not exist while it is being cut; it sits at v0.1.1, the first release whose action.yml names the image by digest, so the runner pulls rather than building it — the v0.1.0 pin spent 81 seconds per run compiling before the review could start"
      risk_reduction       = 60
    }
  }

  threat "Mutable major alias repointed at attacker-chosen code" {
    description = "Consumers pin uses: threatcl/drift-action@v1, and the tag-release job in .github/workflows/release.yml moves that alias on every release with git tag -f and git push origin -f. The alias is force-moved rather than immutable, so the major alias is a mutable pointer to whichever commit last claimed it — history is rewritten silently and there is no record on the tag of what it used to name. Who can trigger that move widened when the release stopped being a tag push: the workflow now runs on workflow_dispatch and creates the vX.Y.Z tag itself, so the 'release tags are immutable' ruleset — which restricts tag creation to repository admins — no longer stands between a person and a release. Anyone who can dispatch a workflow on this repository can cut one, and anyone who can alter .github/workflows/release.yml so the job computes a different target repoints the alias for every downstream consumer at once. The same run also pushes a commit to main, because the digest of the image it just published has to be written into action.yml before the commit is tagged; the job's own GITHUB_TOKEN is read-only and every push authenticates with a short-lived token minted from the org's release app, guarded by a version-shape check and an ancestry check that constrain what the alias can be moved onto but not who starts the run. Consumers observe nothing: the same @v1 string resolves to different code on their next run, which then executes in their runner with their own secrets and their own PR-write token. Scope: this threat and its controls are about git refs under refs/tags, and that is only the first half of the resolution chain — since action.yml line 56 stopped saying image: 'Dockerfile', resolving @v1 to a commit only gets a consumer to an action.yml that names a container image. Neither the ancestry check nor either tag ruleset reaches a registry tag. That half is modelled separately as 'Container image tag repointed under a released action.yml', where the digest pin — not anything here — is what closes it"
    impacts     = ["Integrity"]
    stride      = ["Tampering", "Elevation Of Privilege"]

    control "Release refs land only on commits reachable from main" {
      description          = "The tag-release job in .github/workflows/release.yml refuses to create either ref — the vX.Y.Z tag or the major alias — unless the released commit is an ancestor of origin/main (git merge-base --is-ancestor, over a full-history checkout so main is visible; a shallow fetch makes the check fail closed rather than pass, and the fetch names an explicit refspec so a stale remote-tracking ref cannot fail a sound release). It is worth less than it was, and it covers more. Under the tag-triggered flow a tag push could carry its own commit, so the check was the only thing stopping an alias move onto code that existed nowhere but the tag; under publish-before-tag the job pushes the digest commit to main itself and then tags it, so the check passes by construction. What it still does is fail closed if that push did not land, and it now runs before the version tag rather than only before the alias, so neither ref can name a commit main does not carry"
      implemented          = true
      implementation_notes = "The check constrains where a move can land, not how the code got there, and the new ordering means the job puts the code there. Since the 'Mint a release-app token' step the job authenticates its pushes with a GitHub App installation token persisted as the checkout credential, and the sibling 'Tag rulesets restrict release-tag creation and alias moves' control records that app as holding repository-wide contents read-write. contents read-write covers branches, not just tags — which the release now exercises as ordinary operation rather than as an abuse case: 'Commit the pin to main' runs git push origin HEAD:refs/heads/main on every release. That push is not forced, so it fails rather than rewriting history if main advanced under the build, and the release stops with an unreferenced image. A holder of RELEASER_APP_PRIVATE_KEY can do the same by hand and then cut the tag, and the ancestry check passes, because by then the commit genuinely is reachable from main. The pull-request gate a reader might infer from 'landed on main' is therefore not something this check provides; it would have to come from a branch ruleset on refs/heads/main requiring review, and no such ruleset exists. Verified 2026-08-11: repos/threatcl/drift-action/rulesets returns exactly two, 'release tags are immutable' and 'major alias moves only from the release workflow', both target: tag, and branches/main/protection returns 404 Branch not protected. That absence is now load-bearing in a way it was not: adding a main ruleset requiring pull requests would break every release unless the release app is on its bypass list, and putting it there returns the honest reading to what it already is — the alias names code an app-key holder chose, laundered through main"
      risk_reduction       = 20
    }

    control "Release dispatch gated by environment reviewers" {
      description          = "The publish-image job in .github/workflows/release.yml names a 'release' deployment environment carrying a required-reviewer rule, so a release run waits for approval before anything is published or tagged. This is what covers who starts a release now that the workflow creates the version tag itself and the admin-only tag ruleset no longer gates it — the sibling controls guard where a ref can land, not who triggers the run"
      implemented          = true
      implementation_notes = "Configured and verified 2026-08-12: repos/threatcl/drift-action/environments/release returns one protection rule, required_reviewers, with xntrik as the sole reviewer. It replaces like for like — a write-holder who is not that reviewer can dispatch the workflow but cannot make it publish, which is the same population the admin-only tag ruleset used to exclude. Two settings are permissive by choice, both matching what they replace rather than widening it: prevent_self_review is false, because with one maintainer requiring a second approver would make releases impossible, so for that maintainer the gate is a confirmation step rather than separation of duties; and can_admins_bypass is true, which is exactly the admin bypass the version-tag ruleset already granted. The residual worth knowing is deployment_branch_policy, currently null. The dispatch ref decides which copy of .github/workflows/release.yml runs, so a write-holder can push a branch carrying a modified workflow and dispatch from it, and the approval prompt does not show the reviewer which revision they are approving. Restricting the environment to main would close that, and is the one hardening this control is missing. The path this control guards is drawn in the 'review pipeline' diagram as the 'release dispatch' and 'release approval' flows, from the Release Operator element in the 'Repository maintainers' zone — the human the workflow_dispatch rewrite put in the diagram, where a v*.*.* tag push used to be"
      risk_reduction       = 40
    }

    control "Tag rulesets restrict release-tag creation and alias moves" {
      description          = "Two repository rulesets: refs/tags v*.*.* release tags are create-only — no update, no delete — and the major alias refs/tags v1 is creatable and movable only by the org's dedicated release app, whose short-lived token the tag-release job in .github/workflows/release.yml mints for both pushes. GitHub refuses to put the Actions identity itself on a bypass list — deliberately, since that would admit every workflow in the repo — and the refusal forces the stricter design: bypass names one installed app rather than a runner identity. Neither ruleset now decides who may cut a release: the workflow creates the version tag as well as the alias, so the release app is a bypass actor on both, and the admin restriction that used to be the trigger gate is carried by the environment control above instead. A GitHub bypass list exempts an actor from the whole ruleset rather than from one rule, so what the version-tag ruleset guarantees is immutability against everyone except its two bypass actors — the repository admin role, as before, and now the release app as well"
      implemented          = true
      implementation_notes = "Both rulesets are active on the repository. 'release tags are immutable' covers refs/tags/v*.*.* with creation, update, deletion and non-fast-forward rules, bypassed only by the repository admin role; 'major alias moves only from the release workflow' covers refs/tags/v0 and refs/tags/v1 with creation, update and deletion rules and a single Integration bypass actor — the release app, id 4558032. Admins are deliberately absent from that second list: an emergency manual alias move means editing the ruleset first, which is the audit trail working as intended. The app itself now exists, installed on this repository alone with contents read-write as its only permission, and its credentials are in place as the RELEASER_APP_ID variable and the RELEASER_APP_PRIVATE_KEY secret; the tag-release job in .github/workflows/release.yml mints an installation token from it unconditionally and runs with GITHUB_TOKEN downgraded to contents: read, so both tag pushes depend entirely on the app and have no fallback — if the app is uninstalled or the key rotated out, the release fails rather than quietly reverting to the Actions identity. Publish-before-tag makes the workflow create the version tag as well as move the alias, so the app was added to 'release tags are immutable' too; verified 2026-08-12, that ruleset's bypass_actors are RepositoryRole 5 (admin) and Integration 4558032, the same app the alias ruleset names. That grant costs more than the creation it was added for, because a bypass list is ruleset-wide: the app can now update, delete and force-move a released vX.Y.Z tag as well as create one, and the workflow's own restraint — a plain git push of a tag it just checked does not exist — is the only thing that stops it. A holder of RELEASER_APP_PRIVATE_KEY can rewrite release history that the ruleset was written to make immutable. Per-rule bypass is not something GitHub offers, so the alternatives are to accept it or to have a human push version tags, which is the ordering this rewrite exists to escape. Exercised as of v0.1.1, under the previous tag-triggered flow: that release's alias job minted an installation token and moved v0 onto the release commit against both live rulesets. v0.1.0 predates the app and moved the alias with GITHUB_TOKEN. The residual to know: anyone who can read that secret — any workflow run on a non-fork ref — can mint the token and move the major alias, so the moat is secrets access plus the ancestry check, which now constrains very little"
      risk_reduction       = 50
    }
  }

  threat "Container image tag repointed under a released action.yml" {
    description            = "The sibling threat 'Mutable major alias repointed at attacker-chosen code' covers refs/tags; this covers the link below it. Resolving uses: threatcl/drift-action@v1 to a commit does not by itself settle what runs, because that commit's action.yml names an image on ghcr rather than a Dockerfile to build. A ghcr tag is a mutable pointer exactly as a git tag is: anyone holding packages: write on this package can push a different manifest under the same tag, silently and with no record of what it used to name, and every consumer whose next run pulls that tag executes it with their own secrets and their own PR-write token. The git-ref controls do not reach it — the ancestry check inspects commits, and both rulesets target refs/tags — so a released, ruleset-protected, immutable git tag could still resolve to attacker-chosen code. What closes it is that action.yml names a digest rather than a tag, and since the publish-before-tag rewrite of .github/workflows/release.yml that is true of every release rather than of the v0.1.1 bootstrap alone. The two things that used to widen it are gone from the publishing path: the docker/metadata-action step now runs with flavor: latest=false, so no floating latest is moved on publish, and the workflow no longer triggers on a ref at all, so its own alias push cannot re-enter it and republish a mutable v0 image tag. Their residue has been cleared. Verified 2026-08-11 against ghcr, tags were v0.1.0, v0.1.1, v0 and latest: v0.1.0 is sha256:0f1807a1, the digest action.yml pins; v0.1.1 is sha256:6901212f; v0 and latest were both sha256:3b27afaa, a third image belonging to no version tag and stamped org.opencontainers.image.version=v0 by the self-retriggered run that built it. That package version was deleted on 2026-08-12, taking both tags with it — in ghcr a version is a digest with tags attached and there is no untag-one operation, so removing the version was the only way to drop the mis-stamped latest. Confirmed the same day on the package's versions page: two tagged versions, v0.1.0 and v0.1.1, and no floating pointer. The untagged versions listed beside them are the child manifests and attestations of those two indexes, not strays — deleting one would break the digest action.yml pins. Not re-verifiable from a checkout: reading package versions needs a token with read:packages, which the local one lacks"
    impacts                = ["Integrity"]
    stride                 = ["Tampering", "Elevation Of Privilege"]
    information_asset_refs = ["action credentials"]

    control "Engine image pinned by digest in action.yml" {
      description          = "action.yml line 56 names docker://ghcr.io/threatcl/drift-action@sha256:… rather than a version tag. A digest names one immutable manifest and the runner rejects anything else, so repointing a ghcr tag cannot change what a shipped release pulls. Held by the release process rather than by a reviewer's memory: .github/workflows/release.yml writes that line from the digest of the image it just pushed, so a release cannot name a tag even by mistake"
      implemented          = true
      implementation_notes = "This used to be true of v0.1.1 alone, by accident of the bootstrap: that release could digest-pin only because it named the already-published v0.1.0 image, and steady-state releases could not, because the commit was tagged before its image existed. The note recorded that the control was scheduled to become false at v0.1.2 unless the release flow was rewritten publish-before-tag. It has been. .github/workflows/release.yml now runs on workflow_dispatch: publish-image builds and pushes ghcr.io/threatcl/drift-action:vX.Y.Z and exposes steps.build.outputs.digest, then tag-release rewrites action.yml's image line to name that digest, commits it to main, tags that commit and moves the major alias onto it. Three properties make the pin trustworthy rather than merely present. The rewrite refuses unless action.yml holds exactly one image: line, and reads the file back afterwards rather than trusting sed's exit status, which is 0 whether or not anything matched. A build that produced no digest fails the step instead of writing a pin that names nothing. And tag-release refuses if main moved under the build, so the tagged commit is always the built commit plus that one line — a difference that cannot reach the image, since action.yml is metadata the runner reads and is never consulted inside the container. What remains untrue of the pin: the digest names the manifest, not the source, so it fixes what runs without evidencing what built it. Provenance attestation would be the next step and is not configured. Since v0.1.2 action.yml names the image built by the release that wrote the line, so the bootstrap's borrowed-digest caveat no longer applies"
      risk_reduction       = 70
    }

    control "packages: write is granted to one job and nothing else" {
      description          = ".github/workflows/release.yml sets a workflow-level permissions block of contents: read and adds packages: write only on the publish-image job, so no other job in the repository holds a token that can push to the package — including tag-release, which holds the app credential that writes refs. The push authenticates with that job's GITHUB_TOKEN — no long-lived registry credential is stored as a secret, so there is nothing to leak that would survive the run"
      implemented          = true
      implementation_notes = "This is least privilege within the workflows that exist, not a restriction on who can obtain the grant. Any new workflow file can request packages: write for itself, and the repository's own package inherits repository permissions by default, so the moat here is repository write access rather than anything package-specific — the same moat, and roughly the same set of people, as the release-tag rulesets. Unverified from this checkout: who else can push, and whether the package still has 'Inherit access from repository' set or has been given explicit collaborators. gh api /orgs/threatcl/packages/container/drift-action returns 403 without the read:packages scope, which the local gh token lacks; checking it needs a token with that scope or the package settings page. Worth doing once — a package granted to a person or an app outside this repository would move the moat without anything in the repository recording it"
      risk_reduction       = 30
    }

    control "Immutable ghcr tags" {
      description          = "Make published tags non-rewritable at the registry, so a version tag cannot be repointed at a different manifest once it names one. Defence in depth behind the digest pin rather than the thing that closes the threat — it would protect anyone who pulls :vX.Y.Z by hand, and any future release that named a tag"
      implemented          = false
      implementation_notes = "Not configured, and not yet established as available. GitHub's immutability guarantees are documented for actions and for tag rulesets over git refs; whether ghcr exposes an equivalent rule for container tags on an org-owned package needs checking against current docs and the package settings before this is treated as a plannable task rather than a wish — the same 403 that blocks the sibling control blocks reading the current setting. What has changed is that it would now have nothing to make an exception for. This repository publishes exactly one tag per release, :vX.Y.Z, and no floating pointer: latest was dropped with flavor: latest=false, and the v0 image tag was never intentional — it came from the alias push re-triggering a ref-triggered workflow, which the workflow_dispatch rewrite removed. The stray v0 and latest tags left by that loop were deleted on 2026-08-12, so an immutability rule would now have nothing to exclude and nothing to clean up first. Its urgency dropped with the same rewrite: this was the only control that fixed the residual while every release pinned a tag, and every release now pins a digest"
      risk_reduction       = 60
    }
  }

  threat "Repo source and diff shared with the LLM provider" {
    ref         = "TCL-T-LLM-DATASHARE"
    description = "Context stuffing transmits full contents of security-relevant repo files and the PR diff to the configured LLM provider as a condition of every review — the Anthropic API by default, or the OpenAI API when llm.provider selects it, each recorded as its own third_party_dependency. The files chosen are exactly the ones that back the model's controls and threats, so the disclosure is targeted rather than incidental. Which third party receives it is a repository's own configuration choice, and nothing in the engine constrains that choice beyond the provider having to be one it implements"
    impacts     = ["Confidentiality"]
    stride      = ["Info Disclosure"]
  }

  threat "Coverage gap renders as a clean review" {
    description = "Diff filtering, missing patches, or the max_diff_files cap silently shrink the review set, so a comment that reviewed little or nothing reads as no-drift — the worst outcome this action has, since a clean-looking result hides real drift"
    impacts     = ["Integrity"]
    stride      = ["Repudiation"]

    control "Above-the-fold coverage warnings" {
      ref            = "TCL-C-LLM-PROVENANCE"
      description    = "writeWarnings in internal/render/comment.go renders every coverage gap (narrowing, empty review set, missing patches, size cap) before the collapsed context block; a collapsed details block is never the only disclosure"
      implemented    = true
      risk_reduction = 70
    }
  }

  threat "Replayed fixture impersonates a live review" {
    description = "A recorded review replayed via THREATCL_DRIFT_REPLAY renders findings that were not produced from the current diff, and the recording itself is editable content under testdata/. The same player now has two callers: this one, which renders and can post, and the finding-quality corpus, which asserts inside a test and reaches no renderer. Only this caller can put a recording in front of a reader, so the corpus's own exposure is a different problem and is modelled separately as 'Corpus recordings edited to pass the finding-quality gate'"
    impacts     = ["Integrity"]
    stride      = ["Spoofing"]

    control "Replay disclosure and schema re-validation" {
      ref            = "TCL-C-LLM-PROVENANCE"
      description    = "Replayed runs set ContextInfo.Replayed, rendering an above-the-fold warning, and internal/llm/fixture/fixture.go re-validates the recorded report through findings.Parse in internal/findings/validate.go against the findings schema — a fixture is never trusted more than a live response. Both callers share that player, so the corpus replay path in internal/corpus/corpus_test.go re-validates against the schema identically; what does not carry over is the disclosure half, and it does not need to, because that path asserts in a test rather than rendering — a corpus recording can never influence a rendered pull request comment, a check run or an action output"
      implemented    = true
      risk_reduction = 60
    }
  }

  threat "Corpus recordings edited to pass the finding-quality gate" {
    description = "The corpus replay step in .github/workflows/ci.yml (THREATCL_DRIFT_CORPUS=replay running go test ./internal/corpus -v) is the only check in CI that speaks to finding quality rather than to whether the code compiles, and it decides its verdict entirely from files a pull request can edit: each case directory under testdata/corpus holds both the recorded review and the expectation that review is asserted against, so the same pull request that changes prompts/drift-ci.md, the severity rules or the context builder can also rewrite the evidence that its change did no harm. Replay calls no model, so the gate measures the recorded review and never the current engine. Both of its fail-open paths in internal/corpus/corpus_test.go are now closed — a case with no recording fails rather than being skipped, and a recording whose request fingerprint no longer matches the assembled request fails rather than being logged, so neither deleting the recordings nor changing how the request is built can leave a job exiting 0 having measured nothing or having measured a request the engine no longer sends. Distinct from the replayed-fixture threat above, whose harm is a reader believing a forged review — here nothing is rendered and nothing is posted, and what is lost is CI's assurance that finding quality has not regressed"
    impacts     = ["Integrity"]
    stride      = ["Tampering", "Repudiation"]

    control "Corpus replay is test-only and cannot reach a pull request" {
      description    = "internal/corpus/corpus_test.go assembles a review request, calls Provider.Review and asserts on the result; it imports neither internal/render nor the GitHub client, so no corpus recording has a path to a rendered comment, a check run or an action output. Recordings are read through the same player as a live-pipeline replay, so they are re-validated against the findings schema — which constrains an edited recording's shape but not its content, since a hand-written recording can be schema-valid and still say whatever the expectation demands. This bounds the blast radius to the CI verdict; it does not defend the gate itself"
      implemented    = true
      risk_reduction = 50
    }

    control "Fail the replay gate closed" {
      description          = "Make internal/corpus/corpus_test.go fail rather than log when a recording's request digest no longer matches the assembled prompt, and fail rather than skip when a case has no recording, so re-recording after a change to how the request is assembled is mandatory and a deleted recording is a red build instead of a quiet gap in coverage"
      implemented          = true
      implementation_notes = "Both halves are closed. internal/corpus/corpus_test.go fails when a case has no recording for the configured provider, so deleting recordings turns the gate red instead of quietly emptying it, and assertRecordingIsCurrent fails a replay whose recorded request fingerprint no longer matches the request the engine assembles. The digest half had been left open on a cost argument that turned out to be wrong: fixture.Digest covers ReviewRequest.Sections() and deliberately not its Prompt, so editing prompts/drift-ci.md stales nothing and the main iteration loop is untouched. What trips it is a change to assembly — internal/llm/sections.go, the line-number prefixes, deps.Render, context selection — or to a case's own inputs, and each of those changes what the model sees, so the old recording cannot speak to the new behaviour. No local opt-out was added: a developer mid-iteration simply does not set THREATCL_DRIFT_CORPUS, and the free TestCorpusAssembles still covers assembly on every go test, so an escape hatch would only be a bypass on the one check that speaks to finding quality. Residual: a fork contributor who changes assembly cannot re-record, having no key and no secrets on a fork run, so a maintainer re-records on the branch. Neither half defends against a pull request that re-records deliberately — that is what review of testdata/corpus diffs is for — but both close the case where the gate is defeated by omission rather than by intent"
      risk_reduction       = 40
    }
  }

  threat "Severity rubric flips or is gamed at the fail_mode gate" {
    ref         = "TCL-T-LLM-GATEGAME"
    description = "Nondeterministic severity scoring flips CI verdicts between identical runs, and the partial-contradiction cap in prompts/drift-ci.md lets a carefully framed change downgrade a real contradiction below the on-action-required threshold — the severity distinction is enforced only in the prompt, not in code"
    impacts     = ["Integrity", "Availability"]
    stride      = ["Tampering", "Denial Of Service"]
  }

  threat "Refusal or truncation misread as a clean review" {
    ref         = "TCL-T-LLM-REFUSAL"
    description = "A safeguards refusal arrives as HTTP 200 with stop_reason refusal and possibly empty content, a max_tokens truncation cuts the report mid-JSON, and a server-side fallback silently changes which model answered — any of these rendered as a normal result would present an unassessed PR as drift-free"
    impacts     = ["Integrity", "Availability"]
    stride      = ["Repudiation", "Denial Of Service"]

    control "Refusal, truncation and fallback handling" {
      description    = "Both providers check every terminal condition before any output is read, and both render a refusal as could-not-assess, never no-drift, with truncation a hard error rather than a half-review. internal/llm/anthropic/anthropic.go reads stop_reason, detects fallbacks from usage.iterations, and the comment names the model that actually served the review. internal/llm/openai/openai.go has no single stop reason to read: a refusal arrives either as a refusal content part alongside the text parts or as incomplete_details.reason content_filter, so it checks both, and it never sets ReviewResult.Fallback because that API has no server-side fallback to report — a synthesised one would misreport which model answered. Each provider's refusal and truncation paths are covered by unit tests against a recorded response rather than a live call"
      implemented    = true
      risk_reduction = 60
    }
  }

  third_party_dependency "Anthropic API" {
    description       = "Hosted LLM inference; receives the repository source excerpts and diff described by the 'repository source code' asset. The default provider, and the baseline the Anthropic corpus recordings (testdata/corpus/*/recording.anthropic.json, claude-opus-5) were made against. Recordings are per provider, so this baseline is unaffected by adding another"
    saas              = true
    uptime_dependency = "hard"
  }

  third_party_dependency "OpenAI API" {
    description       = "The alternative inference provider, selected by llm.provider in .threatcl-ci.hcl. It receives exactly the same repository source excerpts and diff as the Anthropic API when configured, so the disclosure boundary is identical and only the recipient changes — a repository choosing it is choosing which third party sees its code. Not reached at all unless configured, but a hard dependency for any repository that does. It has earned that place rather than merely compiling: a parallel set of corpus recordings (testdata/corpus/*/recording.openai.json, gpt-5.6-sol) is committed for it, one per drift category plus the clean case, and all seven pass"
    saas              = true
    uptime_dependency = "hard"
  }

  third_party_dependency "GitHub API" {
    description       = "Source of the PR diff via the compare endpoint, and the write surface for the sticky comment and check run"
    saas              = true
    uptime_dependency = "hard"
  }

  third_party_dependency "GitHub Container Registry (ghcr.io)" {
    description       = "Where the engine image lives, and — since action.yml line 56 replaced image: 'Dockerfile' with docker://ghcr.io/threatcl/drift-action@sha256:… — where every run of this action gets its program. The runner pulls that image before the entrypoint exists, so a registry outage, a deleted package or a revoked pull grant fails the review before any code of ours runs, with nothing to fall back on: the Dockerfile in the consumer's workspace is no longer built, so there is no local path to an engine. That is the trade for a pull measured in seconds rather than a per-run container build. Every release pins by digest rather than by tag — the publish-before-tag flow in .github/workflows/release.yml writes the line, so it cannot lapse into a tag — which means the registry is trusted for availability but not for integrity: a ghcr tag is a mutable pointer anyone with packages: write can repoint silently, while a digest names one immutable manifest and the runner rejects anything else. See docs/RELEASING.md. Distinct from the 'GitHub API' dependency: same vendor, different surface and different failure mode — that one is the diff and the comment, this one is whether the action starts at all"
    saas              = true
    uptime_dependency = "hard"
  }

  third_party_dependency "GitHub App token minting (actions/create-github-app-token)" {
    description       = "The tag-release job in .github/workflows/release.yml mints a short-lived installation token from the org's release app with the 'Mint a release-app token' step, feeding it vars.RELEASER_APP_ID and secrets.RELEASER_APP_PRIVATE_KEY. That token is persisted as the checkout push credential and is what performs every write the release makes to this repository: the digest commit onto main, the vX.Y.Z tag, and git push origin -f refs/tags/v1 — the alias ruleset bypass names the app, so nothing else in the workflow can move the alias. The action is currently pinned to the mutable @v2 major tag while receiving the private key: whoever controls what @v2 resolves to sees the app's signing key and can mint alias-moving tokens at will, which is the same mutable-pin exposure reasoned about in the 'Mutable major alias repointed at attacker-chosen code' threat, one level up the supply chain. Only the release workflow depends on it — a PR review never mints a token"
    saas              = true
    uptime_dependency = "operational"
  }

  data_flow_diagram_v2 "review pipeline" {
    # Everything the PR author controls. The workflow checks out the PR ref, so
    # this zone supplies the content under review. It no longer supplies the
    # engine that reviews it: that is pinned to a released commit.
    # Each element repeats its enclosing zone as an attribute. Nesting alone
    # does not populate it, and the assertion renderer reads the attribute, so
    # without this the zones list but nothing is attributed to them. Spec
    # rejects an attribute that disagrees with its enclosing block.
    trust_zone "PR-author controlled" {
      external_element "PR Author" {
        trust_zone = "PR-author controlled"
      }
    }

    # People with write access to this repository. A zone of its own rather
    # than a corner of "PR-author controlled", because the distinction is the
    # whole subject of the release threats above: a PR author supplies content
    # to a job that reviews it, while a maintainer starts the job that
    # publishes the engine and moves the refs consumers resolve. The rewrite
    # to workflow_dispatch is what put a human on this side of the line — the
    # release used to begin with a v*.*.* tag push, admin-restricted by
    # ruleset, and now begins with a dispatch that any write-holder can make.
    trust_zone "Repository maintainers" {
      external_element "Release Operator" {
        trust_zone = "Repository maintainers"
      }
    }

    # Jobs in this repo's workflows that hold a credential. Two of them, on
    # different triggers with different grants: the review job holds whichever
    # provider key is wired up — secrets.ANTHROPIC_API_KEY here, though
    # action.yml forwards an OpenAI key just as readily — and a
    # pull-requests/checks write-scoped
    # GITHUB_TOKEN on pull_request, and the release jobs run on a
    # workflow_dispatch — publish-image with packages: write, tag-release with
    # GITHUB_TOKEN at contents: read plus the RELEASER_APP_PRIVATE_KEY secret
    # it exchanges for a write-capable app installation token.
    trust_zone "Credentialed Actions runner" {
      # Runs here from pinned, released content — no longer built from the
      # untrusted zone above.
      process "Drift Review Engine" {
        trust_zone = "Credentialed Actions runner"
      }

      # .github/workflows/release.yml: publish-image builds and pushes the
      # container, then tag-release writes its digest into action.yml on main,
      # tags that commit and force-moves the major alias onto it.
      process "Release publisher" {
        trust_zone = "Credentialed Actions runner"
      }
    }

    # Where the runner's credentials are spent, and — for the release app —
    # where one of them is obtained.
    trust_zone "External APIs" {
      external_element "GitHub API" {
        trust_zone = "External APIs"
      }

      external_element "Anthropic API" {
        trust_zone = "External APIs"
      }

      # The alternative inference recipient, reached when llm.provider selects
      # it. Its own element rather than folded into the one above, because the
      # disclosure boundary is per-recipient: a repository choosing openai is
      # choosing which third party sees its source, and a diagram that showed
      # one box for "the LLM" would hide that choice. Exactly one of the two
      # review-request flows is exercised per run.
      external_element "OpenAI API" {
        trust_zone = "External APIs"
      }

      # ghcr.io, where the engine image is published and from where every run
      # now pulls it. Modelled apart from "GitHub API" because it is a
      # different surface with a different failure mode — that element carries
      # the diff and the comment, this one decides whether the action starts —
      # and because the release publisher writes here while every consumer
      # runner reads.
      external_element "GitHub Container Registry" {
        trust_zone = "External APIs"
      }

      # The org-owned GitHub App whose installation token moves the major alias.
      # Modelled separately from "GitHub API" because it is a distinct
      # identity with its own grant (contents read-write on this repository
      # alone) and its own credential — RELEASER_APP_PRIVATE_KEY, held as a
      # repository secret, plus the RELEASER_APP_ID variable. It is the only
      # actor the major-alias ruleset lets bypass, which is why the runner
      # identity's own token cannot make the push.
      external_element "Release App" {
        trust_zone = "External APIs"
      }
    }

    # Every repo that writes uses: threatcl/drift-action@v1. They never reach
    # this repository directly — they resolve the floating alias through
    # GitHub when their workflow starts, so whatever the alias was last force-moved
    # onto is what runs in their runner.
    trust_zone "Downstream consumers" {
      external_element "Consumer Workflow" {
        trust_zone = "Downstream consumers"
      }
    }

    flow "pull request content" {
      from = "PR Author"
      to   = "Drift Review Engine"
    }

    # Distinct from the flow above: not the diff being reviewed, but the
    # program doing the reviewing. This edge used to run from PR Author —
    # uses: ./ built the container from the PR head — and the SHA pin in
    # .github/workflows/threat-drift.yml moved its source to fixed, released
    # content fetched from GitHub. What crosses here is the pinned repository
    # tree: action.yml and the workspace files the engine reads at runtime.
    # Through v0.1.0 it was also the engine itself, because that action.yml
    # said image: 'Dockerfile' and the runner built the container from this
    # tree. It no longer is — v0.1.1's action.yml names a ghcr image, so the
    # program arrives over the "engine image pull" flow below and this edge
    # carries only the tree. The dogfooding workflow pins v0.1.1, so it pulls
    # rather than builds.
    flow "pinned engine fetch" {
      from = "GitHub API"
      to   = "Drift Review Engine"
    }

    # The runner pulling docker://ghcr.io/threatcl/drift-action, pinned by
    # digest at action.yml line 56, before the entrypoint exists. This is how
    # the engine binary reaches the credentialed zone now that no Dockerfile
    # is built in the consumer's workspace, which makes the registry a hard
    # dependency of every run and this the edge on which that failure lands.
    # The digest pin is what bounds its integrity: the runner will accept only
    # one manifest, so a repointed ghcr tag cannot change what crosses here.
    flow "engine image pull" {
      from = "GitHub Container Registry"
      to   = "Drift Review Engine"
    }

    flow "diff and context fetch" {
      from = "GitHub API"
      to   = "Drift Review Engine"
    }

    flow "review request with repo source" {
      from = "Drift Review Engine"
      to   = "Anthropic API"
    }

    # The same payload — prompt, model assertions, context files, diff — to
    # the other provider. Which edge a given run takes is decided by
    # llm.provider in .threatcl-ci.hcl, and never both in one review.
    flow "review request to openai" {
      from = "Drift Review Engine"
      to   = "OpenAI API"
    }

    flow "sticky comment and check run" {
      from = "Drift Review Engine"
      to   = "GitHub API"
    }

    # What now starts a release. Actions → release → Run workflow, carrying
    # the version input the whole run is stamped with: the image tag, the OCI
    # image.version label, the VERSION build-arg the binary reports as
    # main.version, and the git tag. The ref it is dispatched from does not
    # decide what gets built — publish-image checks out main and builds its
    # tip — but it does decide which copy of .github/workflows/release.yml
    # runs, so a write-holder can dispatch a modified workflow from a branch.
    # Restricting the release environment's deployment branches to main is
    # what would close that; it is unset, and the "Release dispatch gated by
    # environment reviewers" control records it as the residual.
    flow "release dispatch" {
      from = "Release Operator"
      to   = "Release publisher"
    }

    # The second half of the same control: the release environment named by
    # publish-image carries a required_reviewers rule, so the dispatched run
    # holds before its first step until a reviewer releases it. Mediated by
    # GitHub rather than sent operator-to-runner, and drawn as its own edge
    # because it is a distinct decision by a distinct person — except that
    # prevent_self_review is false, so today the dispatcher may be that
    # person. For a maintainer who is not the reviewer this is the gate that
    # replaced the admin-only tag ruleset; for the reviewer themselves it is a
    # confirmation step. Nothing crosses here but an approval, and nothing is
    # published or tagged until it does.
    flow "release approval" {
      from = "Release Operator"
      to   = "Release publisher"
    }

    # publish-image, before it publishes anything: git ls-remote --exit-code
    # origin refs/tags/$VERSION in the 'Refuse to re-release an existing
    # version' step, over the same checkout of main the image is built from.
    # Drawn because the publish-before-tag ordering leans on it — publishing
    # is the irreversible half, so the guard that a version has not already
    # been released has to read the ref namespace before the push rather than
    # after it. Distinct from the ancestry read in tag-release, which happens
    # after the image exists.
    flow "release tag existence check" {
      from = "GitHub API"
      to   = "Release publisher"
    }

    # The registry half of the same guard: docker buildx imagetools inspect
    # ghcr.io/<repo>:$VERSION in the 'Refuse to repoint a published image tag'
    # step. The git check above cannot see this case — a run that published
    # and then failed before tagging leaves an image tag with no git tag to
    # match — so without this read, re-dispatching that version would repoint
    # a published :vX.Y.Z at a different manifest, which is the exact move
    # this threat is about. The only edge on which the registry is read by
    # anything other than a consumer's runner.
    flow "published tag existence check" {
      from = "GitHub Container Registry"
      to   = "Release publisher"
    }

    # publish-image: build the container from main's tip and push it to ghcr
    # with a packages: write token. Retargeted from "GitHub API" onto the
    # registry element now that one exists — this is the write side of the
    # same surface every run reads over "engine image pull" above. It happens
    # before any ref names it: the digest it returns is what the pushes below
    # then commit and tag.
    flow "container image publish" {
      from = "Release publisher"
      to   = "GitHub Container Registry"
    }

    # tag-release, before the checkout: actions/create-github-app-token@v2
    # signs a JWT with secrets.RELEASER_APP_PRIVATE_KEY for the app named by
    # vars.RELEASER_APP_ID and exchanges it for an installation token
    # (.github/workflows/release.yml, the "Mint a release-app token" step).
    # The private key never leaves the runner; what crosses back is a
    # short-lived token, drawn as its own flow below.
    flow "release-app token mint" {
      from = "Release publisher"
      to   = "Release App"
    }

    # The minted token entering the credentialed zone, where the checkout
    # persists it as the push credential. This is the edge that upgrades the
    # job from contents: read to a ref-writing identity, so the release app's
    # grant — not the runner's permissions block — is what bounds the push
    # below.
    flow "installation token issue" {
      from = "Release App"
      to   = "Release publisher"
    }

    # tag-release's three writes, all authenticated with the app installation
    # token above rather than the runner's GITHUB_TOKEN, which is contents:
    # read here — the major-alias ruleset admits only the release app, and
    # GitHub refuses to put the Actions identity on a bypass list. In order:
    # the digest commit pushed to refs/heads/main (not forced, so it fails
    # rather than rewriting history if main moved under the build), the
    # release tag created on it, and git push origin -f refs/tags/v1. Distinct
    # from the publish above because the last of them rewrites a ref consumers
    # already resolve, rather than adding a new immutable artifact.
    flow "release commit and tag pushes" {
      from = "Release publisher"
      to   = "GitHub API"
    }

    # Where the moved alias lands. Nothing in this repo initiates it — the
    # consumer's own workflow run does, at whatever time it next fires.
    flow "major alias resolution" {
      from = "GitHub API"
      to   = "Consumer Workflow"
    }
  }
}
