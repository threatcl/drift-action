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
    description                = "The Anthropic API key and GitHub token the action holds at runtime; the token carries PR write permission"
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
    description = "A recorded review replayed via THREATCL_DRIFT_REPLAY renders findings that were not produced from the current diff, and the recording itself is editable content under testdata/"
    impacts     = ["Integrity"]
    stride      = ["Spoofing"]

    control "Replay disclosure and schema re-validation" {
      ref            = "TCL-C-LLM-PROVENANCE"
      description    = "Replayed runs set ContextInfo.Replayed, rendering an above-the-fold warning, and internal/llm/fixture/fixture.go re-validates the recorded report against the findings schema — a fixture is never trusted more than a live response"
      implemented    = true
      risk_reduction = 60
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
    external_element "PR Author" {}

    external_element "GitHub API" {}

    external_element "Anthropic API" {}

    process "Drift Review Engine" {}

    flow "pull request content" {
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
  }
}
