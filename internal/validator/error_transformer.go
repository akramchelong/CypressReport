package validator

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
)

// errorTransformer takes an errorbag and returns a pretty error.
type errorTransformer struct {
	templates *template.Template
}

// placeholders contains the fields that are used as placeholders.
type placeholders struct {
	Field string
	Rule  string
}

// NewErrorTransformer returns a new error transformer. This function panics if
// the provided templates does not have a default template.
func NewErrorTransformer(templates *template.Template) *errorTransformer {
	// Make sure that the templates at least have a default
	if templates.Lookup("default") == nil {
		logger.Fatal("Validation templates must at least have a \"default\" template")
	}

	return &errorTransformer{templates}
}

// BagToString returns all errors, transformed, as a single string, separated
// by provided separator.
func (t errorTransformer) BagToString(errorBag ErrorBag, separator string) string {
	return strings.Join(t.BagToSlice(errorBag), separator)
}

// BagToSlice returns all errors, transformed, as a slice. The resulting array
// is sorted so that an error bag with the same errors will always be returned
// in the same order.
func (t errorTransformer) BagToSlice(errorBag ErrorBag) []string {
	errors := []string{}

	for _, err := range errorBag {
		errors = append(errors, t.getCustomError(err.Tag, err.Field))
	}

	sort.Strings(errors)

	return errors
}

// getCustomError returns a pretty error message given a tag and a field.
//
// tag is from the validation rule, e.g. "unique", "required", etc.
// field is from the client, e.g. "code", "response_type", etc.
func (t errorTransformer) getCustomError(tag, field string) string {
	presentTemplate := t.templates.Lookup(tag)
	if presentTemplate == nil {
		presentTemplate = t.templates.Lookup("default")
	}

	customError := new(bytes.Buffer)
	err := presentTemplate.Execute(customError, placeholders{
		Field: field,
		Rule:  tag,
	})

	if err != nil {
		logger.Error("Unable to execute template for tag: %q, field: %q", tag, field)
		return fmt.Sprintf("%q is invalid", field)
	}

	return customError.String()
}
