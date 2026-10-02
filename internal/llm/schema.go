package llm

import (
	"encoding/json"
	"fmt"
)

// PortableSchema translates the shared findings schema into the subset that
// providers with a constrained schema dialect accept. The shared schema is
// left alone: it is the validation source of truth and the Anthropic provider
// sends it verbatim, so the translation belongs to the providers that need it
// — and two of them need exactly the same one, which is why it lives here
// rather than in either.
//
// The schema is already strict-shaped in every expensive way — every object
// sets additionalProperties:false and lists all its properties as required —
// so this is deliberately a narrow rewrite rather than a general converter. It
// does two things, and anything else it silently passes through:
//
//   - const is in neither OpenAI strict mode's nor Gemini's accepted subset,
//     so a const becomes a single-value enum, which is exactly equivalent and
//     is accepted by both.
//   - a property given only a const carries no type, which strict mode
//     requires, so the type is taken from the constant itself.
//
// $schema is dropped: it describes the schema's own dialect rather than the
// instance, so it is meaningless to the API and only risks being rejected as
// an unrecognised keyword.
func PortableSchema(raw []byte) (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("the findings schema is not valid JSON: %w", err)
	}
	delete(root, "$schema")
	return rewriteSchema(root), nil
}

func rewriteSchema(node map[string]any) map[string]any {
	if value, ok := node["const"]; ok {
		delete(node, "const")
		node["enum"] = []any{value}
		if _, typed := node["type"]; !typed {
			if name := jsonTypeOf(value); name != "" {
				node["type"] = name
			}
		}
	}

	for key, child := range node {
		switch typed := child.(type) {
		case map[string]any:
			node[key] = rewriteSchema(typed)
		case []any:
			for i, element := range typed {
				if object, ok := element.(map[string]any); ok {
					typed[i] = rewriteSchema(object)
				}
			}
		}
	}
	return node
}

// jsonTypeOf names the JSON type of a decoded constant. Numbers decode to
// float64 whether or not they were written with a fraction, so an integer
// const is reported as "number" — the wider of the two, and never wrong.
func jsonTypeOf(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return ""
}
