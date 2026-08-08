package model

import "testing"

func TestLoadSimpleModel(t *testing.T) {
	a, err := Load("../../testdata/simple.tm.hcl")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(a.Wrapped.Threatmodels); got != 1 {
		t.Fatalf("threat models = %d, want 1", got)
	}
	tm := a.Wrapped.Threatmodels[0]
	if len(tm.Threats) != 1 {
		t.Fatalf("threats = %d, want 1", len(tm.Threats))
	}
	if len(tm.Threats[0].Controls) != 1 || !tm.Threats[0].Controls[0].Implemented {
		t.Errorf("expected one implemented control, got %+v", tm.Threats[0].Controls)
	}
	if len(tm.InformationAssets) != 1 {
		t.Errorf("information assets = %d, want 1", len(tm.InformationAssets))
	}
	if len(tm.ThirdPartyDependencies) != 1 {
		t.Errorf("third party dependencies = %d, want 1", len(tm.ThirdPartyDependencies))
	}
}
