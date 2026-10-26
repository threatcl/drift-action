package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/config"
)

// CloudInfo is what cloud-connected mode learned, for the comment. A nil
// *CloudInfo on ContextInfo renders nothing, which is what keeps local-mode
// comments unchanged.
type CloudInfo struct {
	// Degraded is the "not connected" reason. When set, it is the only thing
	// rendered: one ℹ️ line in "Context used", and the comment is otherwise
	// the local one.
	Degraded string
	// Org is the token's organisation slug.
	Org string
	// Models is every linked model with the server's answer about it.
	Models []CloudModel
	// Unlinked lists set files that joined no model.
	Unlinked []string
	Library  LibraryInfo
	// PolicyFailMode is the configured gate, which decides whether an
	// unavailable policy evaluation is a warning.
	PolicyFailMode string
}

// CloudModel is one linked model: the files that make it up and the context
// the server returned for it.
type CloudModel struct {
	Files   []string
	Context cloud.ContextModel
}

// LibraryInfo describes the org library that was sent to the model. Names
// maps reference id to name; a finding's refs render from here, never from
// the model's own spelling.
type LibraryInfo struct {
	Threats   int
	Controls  int
	Truncated bool
	Names     map[string]string
}

// PolicyGate is what CheckConclusion needs to know about policy evaluation.
type PolicyGate struct {
	// Mode is cloud.policy_fail_mode.
	Mode string
	// Blocking counts enforced, error-severity violations across models.
	Blocking int
	// Unavailable means the gate could not be applied: cloud mode degraded,
	// or a linked model came back with no policy verdict.
	Unavailable bool
}

// Gate derives the policy gate from the cloud outcome. With no cloud info
// the gate is off and nothing is unavailable — local mode has no policies.
func (c *CloudInfo) Gate() PolicyGate {
	if c == nil {
		return PolicyGate{Mode: config.PolicyFailNever}
	}
	gate := PolicyGate{Mode: c.PolicyFailMode}
	if gate.Mode == "" {
		gate.Mode = config.PolicyFailNever
	}
	if c.Degraded != "" {
		gate.Unavailable = true
		return gate
	}
	for _, m := range c.Models {
		if m.Context.Policy == nil {
			gate.Unavailable = true
			continue
		}
		gate.Blocking += m.Context.Policy.Blocking
	}
	return gate
}

// policyTotals sums the per-model verdicts for the counts row and the
// context line. evaluated is false when no model returned a verdict.
func (c *CloudInfo) policyTotals() (evaluated bool, totals cloud.PolicyContext) {
	for _, m := range c.Models {
		if p := m.Context.Policy; p != nil {
			evaluated = true
			totals.Evaluated += p.Evaluated
			totals.Enforced += p.Enforced
			totals.Violated += p.Violated
			totals.Blocking += p.Blocking
		}
	}
	return evaluated, totals
}

// syncing reports the state the server returns as conflict when the head
// already equals cloud's current version: the base matched an older version,
// so both sides moved, but they moved to the same place. The delta is then
// present and empty. Nothing needs merging, so it is not rendered as a
// conflict — the pull request is the sync.
func syncing(a cloud.Alignment) bool {
	return a.State == cloud.StateConflict && a.Delta != nil && len(a.Delta) == 0
}

// needsSync reports whether the model gets a Model sync block.
func needsSync(m CloudModel) bool {
	switch m.Context.Alignment.State {
	case cloud.StateBehind:
		return true
	case cloud.StateConflict:
		return !syncing(m.Context.Alignment)
	}
	return false
}

func version(v *string) string {
	if v == nil || *v == "" {
		return "?"
	}
	return oneLine(strings.ReplaceAll(*v, "`", "'"))
}

func versions(n int) string {
	if n == 1 {
		return "1 version"
	}
	return fmt.Sprintf("%d versions", n)
}

// fileList renders model file paths. They come from model_paths in the pull
// request's own .threatcl-ci.hcl, so each goes in its own stripped code span.
func fileList(files []string) string {
	if len(files) == 0 {
		return "the repo copy"
	}
	quoted := make([]string, len(files))
	for i, f := range files {
		quoted[i] = code(f)
	}
	return strings.Join(quoted, ", ")
}

// alignmentPhrase words a model's state for the ☁️ line.
func alignmentPhrase(m CloudModel) string {
	a := m.Context.Alignment
	current := version(m.Context.Version)
	switch a.State {
	case cloud.StateAligned:
		return fmt.Sprintf("repo copy matches cloud v%s", current)
	case cloud.StateAhead:
		return fmt.Sprintf("this PR changes the model; it becomes the next cloud version after v%s when pushed on merge", current)
	case cloud.StateBehind:
		return fmt.Sprintf("repo copy is %s behind cloud v%s (last synced at v%s) — see Model sync below",
			versions(a.VersionsBehind), current, version(a.BaseMatches))
	case cloud.StateConflict:
		if syncing(a) {
			return fmt.Sprintf("repo copy was %s behind; this PR brings it up to cloud v%s",
				versions(a.VersionsBehind), current)
		}
		return fmt.Sprintf("repo copy and cloud have both changed since v%s (cloud is now v%s) — see Model sync below",
			version(a.BaseMatches), current)
	case cloud.StateUnsynced:
		return fmt.Sprintf("no committed copy matches a cloud version (cloud is at v%s) — pushed from the cloud editor, or never pushed from this repository", current)
	case cloud.StateNotInCloud:
		return "no model with this slug in the organisation"
	default:
		return fmt.Sprintf("alignment state %q", oneLine(a.State))
	}
}

// noteText words a server note for the reader. Unknown notes render
// generically rather than failing: the set is closed today, but the server
// may add to it.
func noteText(m CloudModel, note string) string {
	slug := m.Context.Slug
	switch {
	case note == cloud.NoteOrgMismatch:
		return fmt.Sprintf("Threatcl Cloud: the backend block for %s names a different organisation from the API token's; the token's organisation was used", code(slug))
	case note == cloud.NoteRepositoryMismatch:
		return fmt.Sprintf("Threatcl Cloud: model %s declares repositories, and this repository is not among them — check the link", code(slug))
	case note == cloud.NoteNoPolicies:
		return fmt.Sprintf("Threatcl Cloud: the organisation has no enabled policies, so %s was not policy-checked", code(slug))
	case note == cloud.NotePolicyUnavailable:
		return fmt.Sprintf("Threatcl Cloud: policies could not be evaluated against %s", code(slug))
	case note == cloud.NoteHeadParseError:
		return fmt.Sprintf("Threatcl Cloud: the pull request's copy of %s did not parse on the server, so no delta or policy verdict is available for it", code(slug))
	case note == cloud.NotePartialSet:
		return fmt.Sprintf("Threatcl Cloud: %s has segments on cloud this repository did not submit; policies were evaluated on the submitted ones only", code(slug))
	case note == cloud.NoteNotInCloud:
		return "" // said on the ☁️ line already
	case strings.HasPrefix(note, cloud.NoteUnplacedFile+":"):
		return fmt.Sprintf("Threatcl Cloud: %s could not be placed in %s and contributed to neither alignment nor policy",
			code(strings.TrimPrefix(note, cloud.NoteUnplacedFile+":")), code(slug))
	default:
		return fmt.Sprintf("Threatcl Cloud: %s — %s", code(slug), code(note))
	}
}

// writeCloudWarnings adds cloud mode's above-the-fold lines: a real conflict,
// a policy gate that could not be applied, and blocking violations that fail
// the check.
func writeCloudWarnings(lines []string, info ContextInfo) []string {
	c := info.Cloud
	if c == nil {
		return lines
	}
	gate := c.Gate()
	if c.Degraded != "" {
		if gate.Mode == config.PolicyFailOnEnforcedViolation {
			lines = append(lines, fmt.Sprintf(
				"⚠️ Policy gate: `policy_fail_mode` is `%s`, but Threatcl Cloud was %s, so this run was not policy-gated",
				gate.Mode, c.Degraded))
		}
		return lines
	}
	for _, m := range c.Models {
		if m.Context.Alignment.State == cloud.StateConflict && !syncing(m.Context.Alignment) {
			lines = append(lines, fmt.Sprintf(
				"⚠️ Model sync: %s and Threatcl Cloud %s have both changed since v%s — pushing on merge would overwrite the cloud edits; see Model sync below",
				fileList(m.Files), code(m.Context.Slug), version(m.Context.Alignment.BaseMatches)))
		}
	}
	if gate.Mode == config.PolicyFailOnEnforcedViolation {
		for _, m := range c.Models {
			if m.Context.Policy == nil {
				lines = append(lines, fmt.Sprintf(
					"⚠️ Policy gate: `policy_fail_mode` is `%s`, but policies could not be evaluated for %s, so this run was not policy-gated",
					gate.Mode, code(m.Context.Slug)))
			}
		}
		if gate.Blocking > 0 {
			lines = append(lines, fmt.Sprintf(
				"⚠️ Policy: %d enforced policy violation(s) fail this check — see Policy violations below", gate.Blocking))
		}
	}
	return lines
}

// writeCloudContext adds cloud mode's lines to "Context used".
func writeCloudContext(b *strings.Builder, info ContextInfo) {
	c := info.Cloud
	if c == nil {
		return
	}
	if c.Degraded != "" {
		fmt.Fprintf(b, "- ℹ️ Threatcl Cloud: %s\n", c.Degraded)
		return
	}
	for _, m := range c.Models {
		v := ""
		if m.Context.Alignment.State != cloud.StateNotInCloud {
			v = " v" + version(m.Context.Version)
		}
		fmt.Fprintf(b, "- ☁️ Threatcl Cloud: %s — %s%s (%s): %s\n",
			escapeText(c.Org), code(m.Context.Slug), v, fileList(m.Files), alignmentPhrase(m))
	}
	if len(c.Models) == 0 {
		fmt.Fprintf(b, "- ☁️ Threatcl Cloud: %s — no model linked; library and review record only\n", escapeText(c.Org))
	}
	if c.Library.Threats+c.Library.Controls == 0 {
		b.WriteString("- 📚 Org library: no referenceable entries, so none were sent\n")
	} else {
		truncated := ""
		if c.Library.Truncated {
			truncated = " (truncated by the server; not every entry was sent)"
		}
		fmt.Fprintf(b, "- 📚 Org library: %d threats, %d controls sent%s\n", c.Library.Threats, c.Library.Controls, truncated)
	}
	if evaluated, totals := c.policyTotals(); evaluated {
		fmt.Fprintf(b, "- ⚖️ Policies: %d evaluated, %d enforced, %d violated\n",
			totals.Evaluated, totals.Enforced, totals.Violated)
	}
	if len(c.Unlinked) > 0 {
		fmt.Fprintf(b, "- ℹ️ Threatcl Cloud: %s declare no backend address and `cloud.model` is unset, so they were not compared with a cloud model\n",
			fileList(c.Unlinked))
	}
	for _, m := range c.Models {
		for _, note := range m.Context.Notes {
			if text := noteText(m, note); text != "" {
				fmt.Fprintf(b, "- ℹ️ %s\n", text)
			}
		}
	}
}

// deltaLabels names each delta category in prose, singular, in render order.
var deltaLabels = []struct{ key, noun string }{
	{"threats", "threat"},
	{"controls", "control"},
	{"assets", "information asset"},
	{"usecases", "use case"},
	{"exclusions", "exclusion"},
	{"tpds", "third-party dependency"},
	{"dfds", "data flow diagram"},
}

// describeDelta renders the entity-level delta as three sentences at most:
// what cloud has that this copy lacks, what was modified in cloud, and what
// this copy has that cloud lacks. A category the server adds later renders
// under its key.
func describeDelta(delta cloud.Delta) []string {
	keys := make([]string, 0, len(delta))
	known := map[string]bool{}
	for _, l := range deltaLabels {
		known[l.key] = true
		if _, ok := delta[l.key]; ok {
			keys = append(keys, l.key)
		}
	}
	var extra []string
	for key := range delta {
		if !known[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	keys = append(keys, extra...)

	noun := func(key string, n int) string {
		name := key
		for _, l := range deltaLabels {
			if l.key == key {
				name = l.noun
			}
		}
		if n == 1 {
			return name
		}
		if strings.HasSuffix(name, "y") {
			return strings.TrimSuffix(name, "y") + "ies"
		}
		return name + "s"
	}
	collect := func(pick func(cloud.EntityChange) []string) []string {
		var parts []string
		for _, key := range keys {
			items := pick(delta[key])
			if len(items) == 0 {
				continue
			}
			quoted := make([]string, len(items))
			for i, item := range items {
				quoted[i] = `"` + escapeText(item) + `"`
			}
			parts = append(parts, fmt.Sprintf("%s %s", noun(key, len(items)), strings.Join(quoted, ", ")))
		}
		return parts
	}

	var lines []string
	if removed := collect(func(c cloud.EntityChange) []string { return c.Removed }); len(removed) > 0 {
		lines = append(lines, "Cloud has, and this copy lacks: "+strings.Join(removed, "; ")+".")
	}
	if modified := collect(func(c cloud.EntityChange) []string { return c.Modified }); len(modified) > 0 {
		lines = append(lines, "Modified in cloud: "+strings.Join(modified, "; ")+".")
	}
	if added := collect(func(c cloud.EntityChange) []string { return c.Added }); len(added) > 0 {
		lines = append(lines, "This copy has, and cloud lacks: "+strings.Join(added, "; ")+".")
	}
	return lines
}

// writeModelSync renders a Model sync block per model that is behind or in
// conflict. It is not a finding and not one of the six categories: it is a
// coverage statement about the model, like narrowing, that carries a
// remediation — and our code writes it, never the model.
func writeModelSync(b *strings.Builder, info ContextInfo) {
	c := info.Cloud
	if c == nil || c.Degraded != "" {
		return
	}
	for _, m := range c.Models {
		if !needsSync(m) {
			continue
		}
		a := m.Context.Alignment
		current := version(m.Context.Version)
		files := fileList(m.Files)

		var summary string
		if a.State == cloud.StateBehind {
			summary = fmt.Sprintf("Model sync — %s is %s behind Threatcl Cloud %s v%s",
				files, versions(a.VersionsBehind), code(m.Context.Slug), current)
		} else {
			summary = fmt.Sprintf("Model sync — %s and Threatcl Cloud %s have both changed since v%s",
				files, code(m.Context.Slug), version(a.BaseMatches))
		}
		fmt.Fprintf(b, "\n<details>\n<summary>%s</summary>\n\n", summary)

		if a.State == cloud.StateConflict {
			fmt.Fprintf(b, "Cloud is now v%s. This branch's copy was edited from v%s, so pushing it on merge would overwrite what changed in cloud since.\n\n",
				current, version(a.BaseMatches))
		} else {
			fmt.Fprintf(b, "Cloud moved on since this repository last synced at v%s. The review above checked the code against this copy's assertions, which the organisation has already changed; discount findings about anything listed here.\n\n",
				version(a.BaseMatches))
		}

		switch {
		case m.Context.HasNote(cloud.NoteHeadParseError):
			b.WriteString("What differs could not be listed: the pull request's copy did not parse on the server.\n\n")
		case len(a.Delta) == 0:
			b.WriteString("The server listed no entity-level differences.\n\n")
		default:
			for _, line := range describeDelta(a.Delta) {
				fmt.Fprintf(b, "%s\n", line)
			}
			b.WriteString("\n")
		}

		if len(a.Segments) > 1 {
			parts := make([]string, 0, len(a.Segments))
			for _, s := range a.Segments {
				parts = append(parts, fmt.Sprintf("%s %s at v%s", code(s.Segment), escapeText(s.State), version(s.BaseMatches)))
			}
			fmt.Fprintf(b, "Segments: %s.\n\n", strings.Join(parts, "; "))
		}

		b.WriteString("<details>\n<summary>Agent prompt</summary>\n\n```text\n")
		fmt.Fprintf(b, "Bring %s up to Threatcl Cloud model %q version %s before editing it further on this branch: "+
			"export the current cloud version with `threatcl cloud export`, merge the differences listed in the Model sync block of the drift review "+
			"(cloud has: what this copy lacks; modified in cloud; this copy has: what cloud lacks) into the repository copy, keep this branch's own edits, "+
			"then re-run /threat-drift.\n",
			strings.ReplaceAll(strings.Join(m.Files, ", "), "`", "'"), strings.ReplaceAll(m.Context.Slug, "`", "'"), current)
		b.WriteString("```\n\n</details>\n\n</details>\n")
	}
}

// policyMessageCap bounds an org-authored message that may interpolate model
// content, which the pull request controls.
const policyMessageCap = 240

// escapeInline renders untrusted text inside a single code span: backticks
// and newlines cannot break out of it, and the length is capped.
func escapeInline(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "`", "'")), " ")
	if len(s) > policyMessageCap {
		s = s[:policyMessageCap] + "…"
	}
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

// writePolicyViolations lists every failed policy result per model. Results
// never pass through the LLM; they are rendered straight from the server's
// answer, escaped.
func writePolicyViolations(b *strings.Builder, info ContextInfo) {
	c := info.Cloud
	if c == nil || c.Degraded != "" {
		return
	}
	var lines []string
	for _, m := range c.Models {
		if m.Context.Policy == nil {
			continue
		}
		for _, r := range m.Context.Policy.Results {
			if r.Passed {
				continue
			}
			flags := r.Severity
			if r.Enforced {
				flags += ", enforced"
			}
			icon := "⚠️"
			if r.Enforced && r.Severity == "error" {
				icon = "❌"
			}
			line := fmt.Sprintf("- %s **%s** on %s (%s)", icon, escapeText(r.PolicyName), code(m.Context.Slug), escapeText(flags))
			if msg := escapeInline(r.Message); msg != "" {
				line += " — " + msg
			}
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("\n### Policy violations\n\n")
	b.WriteString("Evaluated by Threatcl Cloud against this pull request's copy of the threat model. Enforced `error` results block when `policy_fail_mode` is `on-enforced-violation`.\n\n")
	for _, line := range lines {
		b.WriteString(line + "\n")
	}
}

// escapeText neutralises markdown in a short org-authored string rendered
// outside a code span.
func escapeText(s string) string {
	s = oneLine(s)
	replacer := strings.NewReplacer("*", `\*`, "_", `\_`, "`", "'", "[", `\[`, "]", `\]`, "<", "&lt;", ">", "&gt;")
	return replacer.Replace(s)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// code renders a server identifier — org slug, model slug, segment name — in
// a code span. The server validates them as identifiers, but a backtick or a
// newline in one would still break the span, so both are removed.
func code(s string) string {
	return "`" + strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s) + "`"
}

// libraryMatches renders a finding's refs from our index. A ref outside it
// is never printed — PruneLibraryRefs has already dropped it, and this is
// the second line of that defence.
func libraryMatches(refs []string, info ContextInfo) string {
	if info.Cloud == nil || len(refs) == 0 {
		return ""
	}
	var parts []string
	for _, ref := range refs {
		name, ok := info.Cloud.Library.Names[ref]
		if !ok {
			continue
		}
		parts = append(parts, fmt.Sprintf("`%s` — %s", ref, escapeText(name)))
	}
	return strings.Join(parts, "; ")
}
