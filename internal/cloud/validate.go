package cloud

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

// Validate enforces the record's struct tags: every string is a member of its
// enum or matches its pattern, and pr_number is positive. The server runs the
// same checks and refuses on failure; running them here turns a rejected
// write-back into a local error with the field named, before the token is
// spent on it.
func (r ReviewRecord) Validate() error {
	if r.PRNumber < 1 {
		return fmt.Errorf("review record: pr_number must be at least 1, got %d", r.PRNumber)
	}
	if len(r.Models) > MaxModels {
		return fmt.Errorf("review record: %d models, over the limit of %d", len(r.Models), MaxModels)
	}
	if err := validateStrings(reflect.ValueOf(r), ""); err != nil {
		return fmt.Errorf("review record: %w", err)
	}
	return nil
}

var (
	patternMu sync.Mutex
	patterns  = map[string]*regexp.Regexp{}
)

func compiled(pattern string) *regexp.Regexp {
	patternMu.Lock()
	defer patternMu.Unlock()
	re, ok := patterns[pattern]
	if !ok {
		re = regexp.MustCompile(pattern)
		patterns[pattern] = re
	}
	return re
}

// validateStrings walks v, checking each string field against its enum or
// pattern tag. Nil pointers are optional fields left unset and pass.
func validateStrings(v reflect.Value, prefix string) error {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return validateStrings(v.Elem(), prefix)
	case reflect.Slice:
		for i := range v.Len() {
			if err := validateStrings(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			field := t.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if prefix != "" {
				name = prefix + "." + name
			}
			value := v.Field(i)
			if stringField(field.Type) {
				if err := checkString(field, value, name); err != nil {
					return err
				}
				continue
			}
			if err := validateStrings(value, name); err != nil {
				return err
			}
		}
	}
	return nil
}

func stringField(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind() == reflect.String
}

func checkString(field reflect.StructField, value reflect.Value, name string) error {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	s := value.String()
	if enum := field.Tag.Get("enum"); enum != "" {
		for _, allowed := range strings.Split(enum, "|") {
			if s == allowed {
				return nil
			}
		}
		return fmt.Errorf("%s must be one of %s, got %q", name, enum, s)
	}
	if pattern := field.Tag.Get("pattern"); pattern != "" {
		if !compiled(pattern).MatchString(s) {
			return fmt.Errorf("%s %q does not match %s", name, s, pattern)
		}
		return nil
	}
	// Unreachable while TestReviewRecordHasNoFreeText passes; refusing here
	// keeps a field that slipped past it from carrying free text anyway.
	return fmt.Errorf("%s carries neither an enum nor a pattern tag", name)
}
