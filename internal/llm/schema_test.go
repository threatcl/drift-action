package llm

import (
	"testing"

	"github.com/threatcl/drift-action/internal/findings"
)

func TestPortableSchemaRewritesConst(t *testing.T) {
	schema, err := PortableSchema(findings.SchemaJSON)
	if err != nil {
		t.Fatalf("translating the schema: %v", err)
	}

	if _, ok := schema["$schema"]; ok {
		t.Error("$schema should be dropped: it describes the dialect, not the instance")
	}

	properties, _ := schema["properties"].(map[string]any)
	version, _ := properties["schema_version"].(map[string]any)
	if version == nil {
		t.Fatalf("schema_version property missing: %v", properties)
	}
	if _, ok := version["const"]; ok {
		t.Error("const survived the translation")
	}
	enum, _ := version["enum"].([]any)
	if len(enum) != 1 || enum[0] != "0.1" {
		t.Errorf("const did not become an equivalent single-value enum: %v", version)
	}
	if version["type"] != "string" {
		t.Errorf("a const-only property must gain a type: %v", version)
	}

	// The properties the real schema already gets right must survive intact.
	if schema["additionalProperties"] != false {
		t.Error("additionalProperties:false was lost")
	}
	if required, ok := schema["required"].([]any); !ok || len(required) != 4 {
		t.Errorf("required list was lost: %v", schema["required"])
	}
}

func TestPortableSchemaRejectsMalformedJSON(t *testing.T) {
	if _, err := PortableSchema([]byte(`{"type": `)); err == nil {
		t.Fatal("a malformed schema must be an error, not an empty schema sent to the API")
	}
}
