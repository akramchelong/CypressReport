package validator

import (
	"context"
	"reflect"
	"strings"
	"text/template"

	externalValidator "github.com/go-playground/validator/v10"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
)

type ctxKey int

const (
	ResponseTypes ctxKey = iota
	GrantTypes
	ApplicationType
	Database
	ClientID
)

type Validator struct {
	validate *externalValidator.Validate

	*errorTransformer
}

func New() *Validator {
	validate := externalValidator.New()

	// Register custom validators.
	_ = validate.RegisterValidation("validRedirectURI", isSecureRedirectURI)
	_ = validate.RegisterValidationCtx("validResponseTypes", isValidResponseType)
	_ = validate.RegisterValidationCtx("validGrantTypes", isValidGrantType)
	_ = validate.RegisterValidationCtx("validApplicationTypes", isValidApplicationType)
	_ = validate.RegisterValidationCtx("clientHasRedirectURI", redirectURIBelongsToClient)
	_ = validate.RegisterValidationCtx("clientExist", clientExists)
	_ = validate.RegisterValidationCtx("clientHasResponseType", clientHasResponseType)
	_ = validate.RegisterValidationCtx("authSessionIDIsValid", clientHasAuthSessionID)

	// Use the JSON struct names instead of the field names.
	// E.g. use "redirect_uris" instead of "RedirectURIs".
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	// create templates for some rules
	templates := template.Must(
		template.New("rules").Parse(`
			{{define "unique"}}{{.Field}} must be unique{{end}}
			{{define "required"}}{{.Field}} must have a value{{end}}
			{{define "required_if"}}{{.Field}} must have a value{{end}}
			{{define "min"}}{{.Field}} does not contain enough elements{{end}}
			{{define "max"}}{{.Field}} contains too many elements{{end}}
			{{define "oneof"}}{{.Field}} has an invalid value{{end}}
			{{define "uuid4"}}{{.Field}} must be a valid uuid v4{{end}}
			{{define "clientExist"}}{{.Field}} does not exist{{end}}
			{{define "clientHasRedirectURI"}}{{.Field}} is not registered on the client{{end}}
			{{define "clientHasResponseType"}}{{.Field}} is not registered on the client{{end}}
			{{define "validRedirectURI"}}{{.Field}} is not valid{{end}}
			{{define "validGrantTypes"}}{{.Field}} contains an invalid grant type{{end}}
			{{define "authSessionIDIsValid"}}{{.Field}} is not valid, potentially timed out{{end}}
			{{define "validApplicationTypes"}}Value for {{.Field}} is not a valid application type{{end}}
			{{define "default"}}{{.Field}} failed on the {{.Rule}} rule{{end}}
		`),
	)
	errorConv := NewErrorTransformer(templates)

	return &Validator{
		validate,
		errorConv,
	}
}

func (v Validator) ValidatePostClientRequest(client *PostClientRequest, responseTypes, grantTypes, applicationTypes []string) ErrorBag {
	ctx := context.WithValue(context.Background(), ResponseTypes, responseTypes)
	ctx = context.WithValue(ctx, GrantTypes, grantTypes)
	ctx = context.WithValue(ctx, ApplicationType, applicationTypes)

	errs := v.validate.StructCtx(ctx, client)
	errorBag := getErrorBag(errs)

	return errorBag
}

func (v Validator) ValidatePostLoginRequest(loginRequest *PostLoginRequest, db *database.Database) ErrorBag {
	ctx := context.WithValue(context.Background(), Database, db)
	ctx = context.WithValue(ctx, ClientID, loginRequest.ClientID)

	errs := v.validate.StructCtx(ctx, loginRequest)
	errorBag := getErrorBag(errs)

	return errorBag
}

// ValidatePostTokenRequest validates the request for exchanging/creating a token.
func (v Validator) ValidatePostTokenRequest(request *PostTokenRequest) ErrorBag {
	errs := v.validate.Struct(request)
	errorBag := getErrorBag(errs)

	return errorBag
}

// ValidateGetLogin validates the GET login request.
func (v Validator) ValidateGetLoginRequest(loginRequest *GetLoginRequest, db *database.Database) ErrorBag {
	ctx := context.WithValue(context.Background(), Database, db)
	ctx = context.WithValue(ctx, ClientID, loginRequest.ClientID)

	errs := v.validate.StructCtx(ctx, loginRequest)
	errorBag := getErrorBag(errs)

	return errorBag
}

// ValidateVariable validates a single variable given a validation tag.
// E.g. ValidateVariable(id, "required,uuid4")
func (v Validator) ValidateVariable(field interface{}, tag string) ErrorBag {
	errs := v.validate.Var(field, tag)
	errorBag := getErrorBag(errs)

	return errorBag
}

// Transform errors from external validator to an error bag. If the provider
// error is nil (meaning no validation errors), then an empty error bag is
// returned.
func getErrorBag(errs error) ErrorBag {
	errorBag := make(ErrorBag)
	if errs == nil {
		return errorBag
	}
	for _, err := range errs.(externalValidator.ValidationErrors) {
		errorBag.Add(&validationError{
			Field:       err.Field(),
			StructField: err.StructField(),
			Value:       err.Value(),
			Param:       err.Param(),
			Tag:         err.Tag(),
		})
	}

	return errorBag
}
