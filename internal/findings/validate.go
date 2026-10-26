package findings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaID identifies an embedded schema to the compiler. It is never
// fetched: the document is supplied directly, and the 2020-12 metaschema ships
// with the validator.
const schemaID = "https://threatcl.dev/schemas/findings.schema.json"

// compiledSchema compiles each embedded schema once. Keyed by the document's
// bytes: the two schemas this package ships are both embedded, so the key is
// stable and the cache holds at most two entries.
var (
	schemaMu  sync.Mutex
	schemaFor = map[string]*compiledEntry{}
)

type compiledEntry struct {
	once   sync.Once
	schema *jsonschema.Schema
	err    error
}

func compiledSchema(doc []byte) (*jsonschema.Schema, error) {
	schemaMu.Lock()
	entry, ok := schemaFor[string(doc)]
	if !ok {
		entry = &compiledEntry{}
		schemaFor[string(doc)] = entry
	}
	schemaMu.Unlock()

	entry.once.Do(func() {
		parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
		if err != nil {
			entry.err = fmt.Errorf("reading the embedded findings schema: %w", err)
			return
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(schemaID, parsed); err != nil {
			entry.err = fmt.Errorf("loading the embedded findings schema: %w", err)
			return
		}
		entry.schema, entry.err = compiler.Compile(schemaID)
	})
	return entry.schema, entry.err
}

// ErrInvalidOutput marks output that did not survive validation. Callers match
// on it rather than on the message: the underlying validator error quotes the
// offending instance, which is model output shaped by an attacker-controlled
// diff, so it belongs in the run log and never in the pull request comment.
var ErrInvalidOutput = errors.New("invalid model output")

// Parse validates raw provider output against the local-mode schema
// (SchemaJSON) and decodes it into a Report. See ParseWith.
func Parse(raw []byte) (*Report, error) {
	return ParseWith(SchemaJSON, raw)
}

// ParseWith validates raw against the schema the request carried and decodes
// it into a Report.
//
// Structured outputs already constrain the model to the schema at generation
// time; this is the check that the constraint actually held, and it runs
// before anything reaches the renderer. The schema the provider was sent is
// the schema the output is checked against — v0 in local mode, the cloud
// variant when a library was sent — so a cloud-mode answer is held to the
// library_refs requirement and a local-mode answer is refused for carrying
// one. An empty schema means SchemaJSON. Nothing that has not been through
// here may be rendered.
func ParseWith(schemaDoc, raw []byte) (*Report, error) {
	if len(schemaDoc) == 0 {
		schemaDoc = SchemaJSON
	}
	schema, err := compiledSchema(schemaDoc)
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
