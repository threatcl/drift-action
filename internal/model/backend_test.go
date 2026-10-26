package model

import (
	"reflect"
	"strings"
	"testing"
)

const backendParent = `spec_version = "0.8.0"

backend "threatcl-cloud" {
  organization = "acme"
  threatmodel  = "payments"
}

threatmodel "payments" {
  id     = "payments"
  author = "@acme"
}
`

const backendChild = `spec_version = "0.8.0"

threatmodel "payments api" {
  id      = "payments.api"
  extends = "payments"
  author  = "@acme"
}
`

// On the single-file route the block comes from spec's validated parse; on the
// set route each block is attributed to the file it is physically in, and a
// file without one has no entry.
func TestBackendsPerFile(t *testing.T) {
	root := t.TempDir()
	writeModel(t, root, "parent.tm.hcl", backendParent)
	writeModel(t, root, "child.tm.hcl", backendChild)
	writeModel(t, root, "other.tm.hcl", strings.ReplaceAll(backendParent, `"payments"`, `"ledger"`))

	single, err := LoadIn(root, "parent.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	if want := []Backend{{File: "parent.tm.hcl", Org: "acme", Model: "payments"}}; !reflect.DeepEqual(single.Backends(), want) {
		t.Errorf("single-file Backends = %+v, want %+v", single.Backends(), want)
	}

	set, err := LoadSet(root, []string{"child.tm.hcl", "parent.tm.hcl"})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if want := []Backend{{File: "parent.tm.hcl", Org: "acme", Model: "payments"}}; !reflect.DeepEqual(set.Backends(), want) {
		t.Errorf("set Backends = %+v, want the parent's block attributed to the parent: %+v", set.Backends(), want)
	}

	// The address is where a model lives, not what it asserts: it must not
	// reach the prompt, whose text is every recording's fingerprint.
	if strings.Contains(set.Render(), "acme") || strings.Contains(single.Render(), "backend") {
		t.Errorf("backend address leaked into the rendered assertions:\n%s", set.Render())
	}
}

func TestBackendsNoneDeclared(t *testing.T) {
	a, err := LoadIn(testdataRoot, "simple.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	if got := a.Backends(); len(got) != 0 {
		t.Errorf("Backends = %+v, want none", got)
	}
}

// A block that names the organisation alone — a model never pushed — still
// counts as an address with an empty slug.
func TestBackendsOrgOnly(t *testing.T) {
	root := t.TempDir()
	writeModel(t, root, "m.tm.hcl", strings.Replace(backendParent, `  threatmodel  = "payments"`+"\n", "", 1))

	a, err := LoadIn(root, "m.tm.hcl")
	if err != nil {
		t.Fatalf("LoadIn: %v", err)
	}
	if want := []Backend{{File: "m.tm.hcl", Org: "acme"}}; !reflect.DeepEqual(a.Backends(), want) {
		t.Errorf("Backends = %+v, want %+v", a.Backends(), want)
	}
}
