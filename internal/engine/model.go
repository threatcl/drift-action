package engine

import (
	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/model"
)

// LoadModel resolves which threat model files cfg selects in workspace and
// loads them as one set. model.ErrNoModel comes back unwrapped, so the action
// can skip a repo that has not adopted threatcl rather than fail it.
//
// The corpus calls this too, for the same reason it calls AssembleRequest. It
// once resolved the model itself and loaded only the first path, while the
// action refused several outright — two loaders that disagreed on what a
// repo's model is, so a multi-file corpus case would have measured a review
// the action never ran.
func LoadModel(workspace string, cfg config.Config) (*model.Assertions, error) {
	paths, err := model.Resolve(workspace, cfg.ModelPaths)
	if err != nil {
		return nil, err
	}
	return model.LoadSet(workspace, paths)
}
