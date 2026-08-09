package findings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaID identifies the embedded schema to the compiler. It is never
// fetched: the document is supplied directly, and the 2020-12 metaschema ships
// with the validator.
const schemaID = "https://threatcl.dev/schemas/findings-v0.schema.json"

var (
	schemaOnce     sync.Once
	schemaCompiled *jsonschema.Schema
	schemaErr      error
)

func compiledSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(SchemaJSON))
		if err != nil {
			schemaErr = fmt.Errorf("reading the embedded findings schema: %w", err)
			return
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(schemaID, doc); err != nil {
			schemaErr = fmt.Errorf("loading the embedded findings schema: %w", err)
			return
		}
		schemaCompiled, schemaErr = compiler.Compile(schemaID)
	})
	return schemaCompiled, schemaErr
}

// ErrInvalidOutput marks output that did not survive validation. Callers match
// on it rather than on the message: the underlying validator error quotes the
// offending instance, which is model output shaped by an attacker-controlled
// diff, so it belongs in the run log and never in the pull request comment.
var ErrInvalidOutput = errors.New("invalid model output")

// Parse validates raw provider output against the embedded schema and decodes
// it into a Report.
//
// Structured outputs already constrain the model to this schema at generation
// time; this is the check that the constraint actually held, and it runs
// before anything reaches the renderer. The schema file stays the single
// source of truth — it is both what the API is given and what output is
// checked against. Nothing that has not been through here may be rendered.
func Parse(raw []byte) (*Report, error) {
	schema, err := compiledSchema()
	if err != nil {
		return nil, err
	}

	raw = bytes.TrimSpace(raw)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: it is not valid JSON: %w", ErrInvalidOutput, err)
	}
	if err := schema.Validate(instance); err != nil {
		return nil, fmt.Errorf("%w: it does not match the findings schema: %w", ErrInvalidOutput, err)
	}

	var report Report
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("%w: it did not decode: %w", ErrInvalidOutput, err)
	}
	return &report, nil
}
