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
    description                = "The Anthropic API key and GitHub token the action holds at runtime; the token carries PR write permission. Release time adds a second set, held by .github/workflows/release.yml rather than the engine: a packages: write token for the ghcr push, and a contents: write token in the major-alias job that can create and force-move tags in this repository — including the floating v0 alias consumers resolve"
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
    description            = "The dogfooding workflow .github/workflows/threat-drift.yml triggers on pull_request and runs uses: ./, so the action is built from the PR head — a pull request supplies the engine that reviews it, not just the content being reviewed. That job is granted pull-requests: write and checks: write and is handed secrets.ANTHROPIC_API_KEY, so PR-authored changes to the Dockerfile, the entrypoint or any package under internal/ execute in the runner with the Anthropic key in their environment and a token that can write comments and check runs. The existing 'Prompt injection via PR-controlled diff or context files' threat covers only what a PR puts in the prompt; this covers what a PR puts in the program, which no schema or evidence sanitizer constrains"
    impacts                = ["Confidentiality", "Integrity"]
    stride                 = ["Elevation Of Privilege", "Tampering"]
    information_asset_refs = ["action credentials"]

    control "Fork pull requests receive no secrets" {
      description    = "GitHub withholds repository secrets from pull_request runs raised from a fork and issues a read-only GITHUB_TOKEN regardless of the workflow's permissions block, so for an untrusted author ANTHROPIC_API_KEY resolves empty and the write grants are inert. Platform behaviour rather than anything this repo enforces, and it does nothing for a branch PR from someone who already has write access — which is who raises every PR here today"
      implemented    = true
      risk_reduction = 50
    }

    control "Pin the workflow to the released action" {
      description          = "Replace uses: ./ in .github/workflows/threat-drift.yml with an immutable pin — the release commit SHA, or failing that a vX.Y.Z tag — so a fixed, published engine reviews PRs instead of each PR's own build. Not @v0: the major alias is force-moved on every release, so pinning to it would leave the reviewing engine mutable"
      implemented          = false
      implementation_notes = "The release plumbing this depends on is now in place: the major-alias job in .github/workflows/release.yml publishes the v0 alias after release-image succeeds, so the tag consumers pin is produced by the release workflow rather than by hand. The only remaining blocker is the first tagged release — no vX.Y.Z tag exists yet. The switch is recorded in a comment in .github/workflows/threat-drift.yml; until it happens uses: ./ is deliberate, since it makes the job an end-to-end test of the PR's engine, and this control stays unimplemented. Whichever pin lands, it should not be @v0 — that alias is force-moved with git tag -f and git push origin -f on every release, so pinning to it trades a PR-controlled build for a tag-push-controlled one rather than for a fixed target; see the 'Mutable major alias repointed at attacker-chosen code' threat. Consumers are documented on @v0 for the usual reasons, but this repo's own privileged dogfooding job is the case where the mutability matters most, so it takes the SHA pin"
      risk_reduction       = 60
    }
  }

  threat "Mutable major alias repointed at attacker-chosen code" {
    description = "Consumers pin uses: threatcl/drift-action@v0, and the major-alias job in .github/workflows/release.yml moves that alias on every vX.Y.Z tag push with git tag -f and git push origin -f. The alias is force-moved rather than immutable, so v0 is a mutable pointer to whichever commit last claimed it — history is rewritten silently and there is no record on the tag of what it used to name. Anyone able to push a vX.Y.Z tag, or to alter .github/workflows/release.yml so the job computes a different target, repoints v0 for every downstream consumer at once; the job runs with contents: write, and its only guard is a tag-shape check that refuses a tag containing no dot. Consumers observe nothing: the same @v0 string resolves to different code on their next run, which then executes in their runner with their own secrets and their own PR-write token"
    impacts     = ["Integrity"]
    stride      = ["Tampering", "Elevation Of Privilege"]
  }

  threat "Repo source and diff shared with the LLM provider" {
    ref         = "TCL-T-LLM-DATASHARE"
    description = "Context stuffing transmits full contents of security-relevant repo files and the PR diff to the Anthropic API as a condition of every review — the files chosen are exactly the ones that back the model's controls and threats"
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
    description = "The corpus replay step in .github/workflows/ci.yml (THREATCL_DRIFT_CORPUS=replay running go test ./internal/corpus -v) is the only check in CI that speaks to finding quality rather than to whether the code compiles, and it decides its verdict entirely from files a pull request can edit: each case directory under testdata/corpus holds both the recorded review and the expectation that review is asserted against, so the same pull request that changes prompts/drift-ci.md, the severity rules or the context builder can also rewrite the evidence that its change did no harm. Replay calls no model, so the gate measures the recorded review and never the current engine. It also fails open twice over in internal/corpus/corpus_test.go: a recording whose request digest no longer matches the assembled prompt is reported with t.Logf and still passes, and a case with no recording is skipped rather than failed, so deleting one silently removes that case from the gate while the job exits 0. Distinct from the replayed-fixture threat above, whose harm is a reader believing a forged review — here nothing is rendered and nothing is posted, and what is lost is CI's assurance that finding quality has not regressed"
    impacts     = ["Integrity"]
    stride      = ["Tampering", "Repudiation"]

    control "Corpus replay is test-only and cannot reach a pull request" {
      description    = "internal/corpus/corpus_test.go assembles a review request, calls Provider.Review and asserts on the result; it imports neither internal/render nor the GitHub client, so no corpus recording has a path to a rendered comment, a check run or an action output. Recordings are read through the same player as a live-pipeline replay, so they are re-validated against the findings schema — which constrains an edited recording's shape but not its content, since a hand-written recording can be schema-valid and still say whatever the expectation demands. This bounds the blast radius to the CI verdict; it does not defend the gate itself"
      implemented    = true
      risk_reduction = 50
    }

    control "Fail the replay gate closed" {
      description          = "Make internal/corpus/corpus_test.go fail rather than log when a recording's request digest no longer matches the assembled prompt, and fail rather than skip when a case has no recording, so re-recording after a prompt change is mandatory and a deleted recording is a red build instead of a quiet gap in coverage"
      implemented          = false
      implementation_notes = "Both fail-open behaviours are deliberate today and were chosen before the replay ran in CI. The skip exists because recordings accumulate one paid run at a time, so a newly added case has no recording until someone pays for one — failing closed needs a way to mark a case as not-yet-recorded, or the first commit of any new case breaks the build. The digest log exists because -v was judged enough disclosure when a human was reading the output; in CI nobody reads a passing job's log, which is what makes it fail-open rather than merely quiet. Neither change defends against a pull request that re-records deliberately — that is what review of testdata/corpus diffs is for — but both close the case where the gate is defeated by omission rather than by intent"
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
      description    = "internal/llm/anthropic/anthropic.go checks stop_reason before content is read and a refusal renders as could-not-assess, never no-drift; truncation is a hard error, never a half-review; fallbacks are detected from usage.iterations and the comment names the model that actually served the review"
      implemented    = true
      risk_reduction = 60
    }
  }

  third_party_dependency "Anthropic API" {
    description       = "Hosted LLM inference for every review; receives the repository source excerpts and diff described by the 'repository source code' asset. The only inference provider in v0"
    saas              = true
    uptime_dependency = "hard"
  }

  third_party_dependency "GitHub API" {
    description       = "Source of the PR diff via the compare endpoint, and the write surface for the sticky comment and check run"
    saas              = true
    uptime_dependency = "hard"
  }

  data_flow_diagram_v2 "review pipeline" {
    # Everything the PR author controls. The workflow checks out the PR ref and
    # runs uses: ./, so this zone supplies both the content under review and the
    # engine binary that reviews it.
    # Each element repeats its enclosing zone as an attribute. Nesting alone
    # does not populate it, and the assertion renderer reads the attribute, so
    # without this the zones list but nothing is attributed to them. Spec
    # rejects an attribute that disagrees with its enclosing block.
    trust_zone "PR-author controlled" {
      external_element "PR Author" {
        trust_zone = "PR-author controlled"
      }
    }

    # Jobs in this repo's workflows that hold a credential. Two of them, on
    # different triggers with different grants: the review job holds
    # secrets.ANTHROPIC_API_KEY and a pull-requests/checks write-scoped
    # GITHUB_TOKEN on pull_request, and the release jobs hold packages: write
    # and contents: write on a v* tag push.
    trust_zone "Credentialed Actions runner" {
      # The engine is built here from source that crossed in from the
      # untrusted zone above.
      process "Drift Review Engine" {
        trust_zone = "Credentialed Actions runner"
      }

      # .github/workflows/release.yml: release-image builds and pushes the
      # container, then major-alias force-moves the v0 tag onto that release.
      process "Release publisher" {
        trust_zone = "Credentialed Actions runner"
      }
    }

    # Where the runner's two credentials are spent.
    trust_zone "External APIs" {
      external_element "GitHub API" {
        trust_zone = "External APIs"
      }

      external_element "Anthropic API" {
        trust_zone = "External APIs"
      }
    }

    # Every repo that writes uses: threatcl/drift-action@v0. They never reach
    # this repository directly — they resolve the floating alias through
    # GitHub when their workflow starts, so whatever v0 was last force-moved
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
    # program doing the reviewing. actions/checkout@v6 plus uses: ./ in
    # .github/workflows/threat-drift.yml builds the container from the PR head,
    # so this edge carries PR-author-controlled code into the credentialed zone.
    flow "engine source and container build" {
      from = "PR Author"
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

    flow "sticky comment and check run" {
      from = "Drift Review Engine"
      to   = "GitHub API"
    }

    # release-image: build the container from the tagged source and push it to
    # ghcr with a packages: write token.
    flow "container image publish" {
      from = "Release publisher"
      to   = "GitHub API"
    }

    # major-alias: git push origin -f refs/tags/v0 with a contents: write
    # token. Distinct from the publish above because it rewrites a ref
    # consumers already resolve, rather than adding a new immutable artifact.
    flow "major alias tag move" {
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
