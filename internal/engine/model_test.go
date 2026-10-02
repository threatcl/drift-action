package engine

import (
	"errors"
	"reflect"
	"testing"

	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/model"
)

// Several model_paths are one set. This path used to stop at "not supported
// yet" in main while the corpus quietly loaded only the first file.
func TestLoadModelLoadsEveryConfiguredFile(t *testing.T) {
	cfg := config.Default()
	cfg.ModelPaths = []string{"set/parent.tm.hcl", "set/child.tm.hcl"}

	assertions, err := LoadModel("../../testdata", cfg)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if !reflect.DeepEqual(assertions.Sources, cfg.ModelPaths) {
		t.Errorf("Sources = %v, want every configured file %v", assertions.Sources, cfg.ModelPaths)
	}
}

// main maps ErrNoModel to a skip, so it has to arrive unwrapped enough for
// errors.Is: a repo that has not adopted threatcl must not fail every PR.
func TestLoadModelNoModel(t *testing.T) {
	_, err := LoadModel(t.TempDir(), config.Default())
	if !errors.Is(err, model.ErrNoModel) {
		t.Errorf("LoadModel error = %v, want model.ErrNoModel", err)
	}
}
