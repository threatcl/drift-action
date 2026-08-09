package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/threatcl/spec"
)

// Summary counts what the model asserts. It drives the "Context used" block,
// which is rendered on every run so readers can judge the findings.
type Summary struct {
	Path                string
	Names               []string
	Threats             int
	Controls            int
	ImplementedControls int
	Assets              int
	Dependencies        int
	Diagrams            int
}

func (s Summary) String() string {
	parts := []string{
		plural(s.Threats, "threat"),
		fmt.Sprintf("%s (%d implemented)", plural(s.Controls, "control"), s.ImplementedControls),
	}
	if s.Assets > 0 {
		parts = append(parts, plural(s.Assets, "information asset"))
	}
	if s.Dependencies > 0 {
		parts = append(parts, plural(s.Dependencies, "third-party dependency"))
	}
	if s.Diagrams > 0 {
		parts = append(parts, plural(s.Diagrams, "data flow diagram"))
	}
	return strings.Join(parts, ", ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	switch {
	case strings.HasSuffix(noun, "y"):
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(noun, "y"))
	default:
		return fmt.Sprintf("%d %ss", n, noun)
	}
}

// Summary counts the model's assertions.
func (a *Assertions) Summary() Summary {
	s := Summary{Path: a.Source}
	for _, tm := range a.Models() {
		s.Names = append(s.Names, tm.Name)
		s.Threats += len(tm.Threats)
		s.Assets += len(tm.InformationAssets)
		s.Dependencies += len(tm.ThirdPartyDependencies)
		s.Diagrams += len(tm.DataFlowDiagrams)
		if tm.LegacyDfd != nil {
			s.Diagrams++
		}
		for _, threat := range tm.Threats {
			for _, control := range allControls(threat) {
				s.Controls++
				if control.Implemented {
					s.ImplementedControls++
				}
			}
		}
	}
	return s
}

func allControls(threat *spec.Threat) []*spec.Control {
	controls := make([]*spec.Control, 0, len(threat.Controls)+len(threat.ExpandedControls))
	controls = append(controls, threat.Controls...)
	controls = append(controls, threat.ExpandedControls...)
	return controls
}

// Render writes the model's assertions as the THREAT MODEL ASSERTIONS section
// of the drift prompt. Every assertion carries its file:line so the model can
// cite it — a finding whose excerpt cannot be located is not verifiable.
func (a *Assertions) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Threat model file: %s\n", a.Source)

	for _, tm := range a.Models() {
		fmt.Fprintf(&b, "\n## Threat model %q%s\n", tm.Name,
			a.ref("threatmodel", tm.Name))
		if tm.Description != "" {
			fmt.Fprintf(&b, "%s\n", strings.TrimSpace(tm.Description))
		}

		a.renderThreats(&b, tm)
		a.renderAssets(&b, tm)
		a.renderDependencies(&b, tm)
		a.renderDiagrams(&b, tm)
	}
	return b.String()
}

func (a *Assertions) renderThreats(b *strings.Builder, tm spec.Threatmodel) {
	if len(tm.Threats) == 0 {
		fmt.Fprintf(b, "\n### Threats\n(none)\n")
		return
	}
	fmt.Fprintf(b, "\n### Threats\n")
	for _, threat := range tm.Threats {
		fmt.Fprintf(b, "\n- threat %q%s\n", threat.Name,
			a.ref("threatmodel", tm.Name, "threat", threat.Name))
		writeField(b, "  description", threat.Description)
		if len(threat.Stride) > 0 {
			fmt.Fprintf(b, "  stride: %s\n", strings.Join(threat.Stride, ", "))
		}
		if len(threat.ImpactType) > 0 {
			fmt.Fprintf(b, "  impacts: %s\n", strings.Join(threat.ImpactType, ", "))
		}
		if len(threat.InformationAssetRefs) > 0 {
			fmt.Fprintf(b, "  information assets: %s\n",
				strings.Join(threat.InformationAssetRefs, ", "))
		}

		for _, control := range threat.Controls {
			a.renderControl(b, tm, threat, "control", control)
		}
		for _, control := range threat.ExpandedControls {
			a.renderControl(b, tm, threat, "expanded_control", control)
		}
	}
}

func (a *Assertions) renderControl(b *strings.Builder, tm spec.Threatmodel,
	threat *spec.Threat, blockType string, control *spec.Control) {

	fmt.Fprintf(b, "  - %s %q implemented=%t%s\n", blockType, control.Name, control.Implemented,
		a.ref("threatmodel", tm.Name, "threat", threat.Name, blockType, control.Name))
	writeField(b, "    description", control.Description)
	writeField(b, "    implementation notes", control.ImplementationNotes)
}

func (a *Assertions) renderAssets(b *strings.Builder, tm spec.Threatmodel) {
	if len(tm.InformationAssets) == 0 {
		fmt.Fprintf(b, "\n### Information assets\n(none)\n")
		return
	}
	fmt.Fprintf(b, "\n### Information assets\n")
	for _, asset := range tm.InformationAssets {
		classification := asset.InformationClassification
		if classification == "" {
			classification = "unclassified"
		}
		fmt.Fprintf(b, "- information_asset %q classification=%s%s\n",
			asset.Name, classification,
			a.ref("threatmodel", tm.Name, "information_asset", asset.Name))
		writeField(b, "  description", asset.Description)
	}
}

func (a *Assertions) renderDependencies(b *strings.Builder, tm spec.Threatmodel) {
	if len(tm.ThirdPartyDependencies) == 0 {
		fmt.Fprintf(b, "\n### Third-party dependencies\n(none)\n")
		return
	}
	fmt.Fprintf(b, "\n### Third-party dependencies\n")
	for _, dep := range tm.ThirdPartyDependencies {
		fmt.Fprintf(b, "- third_party_dependency %q uptime_dependency=%s%s\n",
			dep.Name, dep.UptimeDependency,
			a.ref("threatmodel", tm.Name, "third_party_dependency", dep.Name))
		writeField(b, "  description", dep.Description)
	}
}

func (a *Assertions) renderDiagrams(b *strings.Builder, tm spec.Threatmodel) {
	if len(tm.DataFlowDiagrams) == 0 && tm.LegacyDfd == nil {
		fmt.Fprintf(b, "\n### Data flow diagrams\n(none)\n")
		return
	}
	fmt.Fprintf(b, "\n### Data flow diagrams\n")
	for _, dfd := range tm.DataFlowDiagrams {
		fmt.Fprintf(b, "- data_flow_diagram_v2 %q%s\n", dfd.Name,
			a.ref("threatmodel", tm.Name, "data_flow_diagram_v2", dfd.Name))
		writeDiagramBody(b, dfd.Processes, dfd.ExternalElements, dfd.DataStores,
			dfd.Flows, dfd.TrustZones)
	}
	if tm.LegacyDfd != nil {
		fmt.Fprintf(b, "- data_flow_diagram (legacy)%s\n",
			a.ref("threatmodel", tm.Name, "data_flow_diagram"))
		writeDiagramBody(b, tm.LegacyDfd.Processes, tm.LegacyDfd.ExternalElements,
			tm.LegacyDfd.DataStores, tm.LegacyDfd.Flows, tm.LegacyDfd.TrustZones)
	}
}

func writeDiagramBody(b *strings.Builder, processes []*spec.DfdProcess,
	externals []*spec.DfdExternal, stores []*spec.DfdData, flows []*spec.DfdFlow,
	zones []*spec.DfdTrustZone) {

	for _, zone := range zones {
		fmt.Fprintf(b, "  trust_zone %q\n", zone.Name)
		processes = append(processes, zone.Processes...)
		externals = append(externals, zone.ExternalElements...)
		stores = append(stores, zone.DataStores...)
	}
	for _, p := range processes {
		fmt.Fprintf(b, "  process %q%s\n", p.Name, inZone(p.TrustZone))
	}
	for _, e := range externals {
		fmt.Fprintf(b, "  external_element %q%s\n", e.Name, inZone(e.TrustZone))
	}
	for _, s := range stores {
		line := fmt.Sprintf("  data_store %q%s", s.Name, inZone(s.TrustZone))
		if s.IaLink != "" {
			line += fmt.Sprintf(" information_asset=%q", s.IaLink)
		}
		fmt.Fprintln(b, line)
	}
	for _, f := range flows {
		fmt.Fprintf(b, "  flow %q: %s -> %s\n", f.Name, f.From, f.To)
	}
}

func inZone(zone string) string {
	if zone == "" {
		return ""
	}
	return fmt.Sprintf(" trust_zone=%q", zone)
}

func writeField(b *strings.Builder, label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	// Keep multi-line descriptions readable and unambiguously attributed.
	value = strings.ReplaceAll(value, "\n", "\n"+strings.Repeat(" ", len(label)+2))
	fmt.Fprintf(b, "%s: %s\n", label, value)
}

// ref renders " (payments.tm.hcl:84)" for an addressable block, or "" when the
// line is unknown. Never emit ":0" — a fake citation is worse than none.
func (a *Assertions) ref(address ...string) string {
	line := a.Lines.Line(address...)
	if line == 0 {
		return ""
	}
	return fmt.Sprintf(" (%s:%d)", a.Source, line)
}

// pathPattern matches things in prose that look like repo paths: at least one
// slash or a recognisable source extension. Deliberately conservative — these
// paths widen the diff filter, so a false positive costs tokens.
var pathPattern = regexp.MustCompile(`[\w.\-/]+\.(?:go|js|ts|tsx|jsx|py|rb|java|kt|cs|php|rs|c|h|cpp|hcl|tf|ya?ml|json|sql|sh)\b`)

// ReferencedPaths extracts file paths the model's prose mentions, so the diff
// filter keeps changes to code the model makes claims about even when the path
// looks unremarkable to the built-in heuristic.
func (a *Assertions) ReferencedPaths() []string {
	seen := map[string]bool{}
	collect := func(text string) {
		for _, match := range pathPattern.FindAllString(text, -1) {
			match = strings.TrimPrefix(match, "./")
			if match != "" && !seen[match] {
				seen[match] = true
			}
		}
	}

	for _, tm := range a.Models() {
		collect(tm.Description)
		for _, threat := range tm.Threats {
			collect(threat.Description)
			for _, control := range allControls(threat) {
				collect(control.Description)
				collect(control.ImplementationNotes)
			}
		}
		for _, asset := range tm.InformationAssets {
			collect(asset.Description)
		}
	}

	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
