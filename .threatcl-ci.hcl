# Drift review config for this repository's own dogfooding.
#
# prompts/ is on the trigger list because .md files are noise to the diff
# filter — right for ordinary repos, wrong here: the prompt is the reviewer's
# brain, and a PR that only edits prompts/drift-ci.md must still be reviewed.
trigger_paths = ["prompts/"]
