package validator

import (
	"context"
	"regexp"

	externalValidator "github.com/go-playground/validator/v10"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

var (
	validSecureRegex        = regexp.MustCompile(`https://\w+`)
	validUnsecureLocalRegex = regexp.MustCompile(`http://(localhost|127.0.0.1):\w*`)
)

func isValidResponseType(ctx context.Context, fl externalValidator.FieldLevel) bool {
	responseTypes := ctx.Value(ResponseTypes).([]string)
	input := fl.Field().String()

	return util.Contains(responseTypes, input)
}

func isValidGrantType(ctx context.Context, fl externalValidator.FieldLevel) bool {
	grantTypes := ctx.Value(GrantTypes).([]string)
	input := fl.Field().String()

	return util.Contains(grantTypes, input)
}

func isValidApplicationType(ctx context.Context, fl externalValidator.FieldLevel) bool {
	applicationTypes := ctx.Value(ApplicationType).([]string)
	input := fl.Field().String()

	return util.Contains(applicationTypes, input)
}

// clientHasAuthSessionID checks if the auth session exists in the database
// and if it belongs to the client.
func clientHasAuthSessionID(ctx context.Context, fl externalValidator.FieldLevel) bool {
	db := ctx.Value(Database).(*database.Database)
	clientID := ctx.Value(ClientID).(string)
	authSessionID := fl.Field().String()

	authSession := db.FindAuthenticationSession(authSessionID)
	if authSession == nil {
		logger.Debug("AuthSessionIDValidation: login attempt does not exist")
		return false
	}

	if authSession.ClientID != clientID {
		logger.Debug("AuthSessionIDValidation: login attempt is not bound to this client")
		return false
	}

	return true
}

func clientHasResponseType(ctx context.Context, fl externalValidator.FieldLevel) bool {
	clientID := ctx.Value(ClientID).(string)
	db := ctx.Value(Database).(*database.Database)

	client := db.FindClient(clientID)
	if client == nil {
		return false
	}

	responseType := fl.Field().String()

	return util.Contains(client.ResponseTypes, responseType)
}

// clientExists validates if the client exists in the database.
func clientExists(ctx context.Context, fl externalValidator.FieldLevel) bool {
	db := ctx.Value(Database).(*database.Database)
	input := fl.Field().String()

	return db.ClientExists(input)
}

// redirectURIBelongsToClient validates if the redirect URI is registered on
// the client. The client id must be in the context.
func redirectURIBelongsToClient(ctx context.Context, fl externalValidator.FieldLevel) bool {
	db := ctx.Value(Database).(*database.Database)
	clientID := ctx.Value(ClientID).(string)
	redirectURI := fl.Field().String()

	client := db.FindClient(clientID)
	if client == nil {
		return false
	}

	return util.Contains(client.RedirectURIs, redirectURI)
}

// isSecureRedirectURI validates that a redirect URI fulfills
// the specification.
func isSecureRedirectURI(fl externalValidator.FieldLevel) bool {
	return redirectURIValid(fl.Field().String())
}

// validateRedirectURI returns true if redirectURI is valid. False otherwise.
// Validates a redirectURI according to
// https://tools.ietf.org/html/rfc7591#section-5 which has three
// requirements, of which the first two are applicable:
// 1. Remote websites must be protected by TLS.
// 2. Web sites hosted on local machines can use http
func redirectURIValid(redirectURI string) bool {
	if validUnsecureLocalRegex.MatchString(redirectURI) {
		return true
	}

	return validSecureRegex.MatchString(redirectURI)
}
