// Package prompts carries the drift prompts compiled into the binary.
//
// upstream/ is a verbatim vendored copy of the claude-plugin's /threat-drift
// command at the commit recorded in upstream/SOURCE — never hand-edit it;
// re-vendor and update SOURCE instead. drift-ci.md is the CI-adapted
// derivative; the deltas are documented in ADAPTATIONS.md.
package prompts

import _ "embed"

//go:embed drift-ci.md
var DriftCI string

//go:embed upstream/threat-drift.md
var UpstreamThreatDrift string

//go:embed upstream/SOURCE
var UpstreamSource string
