package validator

import "testing"

func TestFailedOn(t *testing.T) {
	errorBag := make(ErrorBag)
	errorBag.Add(&validationError{
		Field:       "code",
		StructField: "Code",
		Value:       "supersecret",
		Tag:         "min",
		Param:       "30",
	})

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"Test field that did not fail", "redirect_uri", false},
		{"Test error in error bag ", "code", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errorBag.FailedOn(tt.in)
			if got != tt.want {
				t.Errorf("\ngot:\n\t%t\nwant:\n\t%t", got, tt.want)
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	errorBag := make(ErrorBag)

	want := true
	got := errorBag.Empty()
	if got != want {
		t.Errorf("Expected bag empty status to be %t. Got %t", want, got)
	}
}

func TestGetErrorsFor(t *testing.T) {
	errorBag := make(ErrorBag)
	errorBag.Add(&validationError{
		Field:       "code",
		StructField: "Code",
		Value:       "supersecret",
		Tag:         "min",
		Param:       "30",
	})

	errorBag.Add(&validationError{
		Field:       "name",
		StructField: "Node",
		Value:       "Bob",
		Tag:         "max",
		Param:       "255",
	})
	errorBag.Add(&validationError{
		Field:       "email",
		StructField: "Email",
		Value:       "bob@example.com",
		Tag:         "email",
		Param:       "",
	})

	smallerErrorBag := errorBag.GetErrorsFor("code", "email", "non-existing-field")

	if _, exists := smallerErrorBag["code"]; !exists {
		t.Error("Expected code to be within the smaller error bag. ")
	}

	if _, exists := smallerErrorBag["email"]; !exists {
		t.Error("Expected code to be within the smaller error bag. ")
	}

	if _, exists := smallerErrorBag["non-existing-field"]; exists {
		t.Error("Did not expect 'non-existing-field' to be included in the smaller error bag since no such validation error error exist.")
	}
}
