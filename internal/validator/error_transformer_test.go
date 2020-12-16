package validator

import (
	"fmt"
	"testing"
	"text/template"
)

func TestGetCustomError(t *testing.T) {
	templates := template.Must(
		template.New("rules").Parse(`
			{{define "unique"}}{{.Field}} must be unique{{end}}
			{{define "default"}}{{.Field}} failed on the {{.Rule}} rule{{end}}
		`),
	)
	errorConv := NewErrorTransformer(templates)

	type input struct {
		tag   string
		field string
	}
	tests := []struct {
		name string
		in   input
		want string
	}{
		{"Test get default error message", input{"minimum", "name"}, "name failed on the minimum rule"},
		{"Test get specific error message ", input{"unique", "email"}, "email must be unique"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errorConv.getCustomError(tt.in.tag, tt.in.field)
			if got != tt.want {
				t.Errorf("\ngot:\n\t%q\nwant:\n\t%q", got, tt.want)
			}
		})
	}
}

func TestGetErrorAsString(t *testing.T) {
	templates := template.Must(
		template.New("rules").Parse(`
			{{define "min"}}{{.Field}} contains too few elements{{end}}
			{{define "default"}}{{.Field}} failed on the {{.Rule}} rule{{end}}
		`),
	)
	errorConv := NewErrorTransformer(templates)

	errorBag := make(ErrorBag)
	errorBag.Add(&validationError{
		Field:       "code",
		StructField: "Code",
		Value:       "supersecret",
		Tag:         "min",
		Param:       "30",
	})
	errorBag.Add(&validationError{
		Field:       "email",
		StructField: "Email",
		Value:       "bob@example.com",
		Tag:         "email",
		Param:       "",
	})

	firstMessage := "code contains too few elements"
	secondMessage := "email failed on the email rule"

	separator := "#"

	got := errorConv.BagToString(errorBag, separator)

	// Since order isn't guaranteed, test both cases
	if got != fmt.Sprintf("%s%s%s", firstMessage, separator, secondMessage) && got != fmt.Sprintf("%s%s%s", secondMessage, separator, firstMessage) {
		t.Errorf("Expected error string to contain %q and %q separated by %q, got %q", firstMessage, secondMessage, separator, got)
	}
}
