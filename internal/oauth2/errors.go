package oauth2

const (
	// Any specific value for the error parameter in case of a internal server
	// error is not mentioned in RFC6749 section-5.2, so we'll assume any
	// arbitrary error value is valid. We'll use server_error since that is
	// recognized from the authorization error response. This should be
	// returned with a 5xx server error.
	errorServer            = "server_error"
	errorServerDescription = "Internal server error"
)

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

var (
	// Client authentication failed (e.g., unknown client, no client
	// authentication included, or unsupported authentication method). The
	// authorization server MUST return an HTTP 401 (Unauthorized) status code to
	// indicate which HTTP authentication schemes are supported.
	// (rfc6749#section-5.2)
	invalidClientError = oauthError{
		"invalid_client",
		"Missing or invalid authorization header",
	}

	// The access token provided is expired, revoked, malformed, or invalid for
	// other reasons. The resource SHOULD respond with the HTTP 401
	// (Unauthorized) status code. The client MAY request a new access token and
	// retry the protected resource request.
	// (rfc6750#section-3.1)
	invalidTokenError = oauthError{
		"invalid_token",
		"Missing or invalid authorization header",
	}

	// The authorization grant type is not supported by the authorization
	// server. Note that an unknown grant type should use this specific error
	// instead of the invalid_request. Must be returned with a 400 (Bad
	// Request).
	// (rfc6749#section-5.2)
	unsupportedGrantError = oauthError{
		"unsupported_grant_type",
		"The authorization grant type is not supported",
	}

	// See errorServer
	internalServerError = oauthError{
		errorServer,
		errorServerDescription,
	}

	// Requested a path or resource that does not exist. Should be returned with
	// a 404 (Not Found).
	notFoundError = oauthError{
		"not_found",
		"Not Found",
	}
)

// The provided authorization grant (e.g., authorization code, resource owner
// credentials) or refresh token is invalid, expired, revoked, does not match
// the redirection URI used in the authorization request, or was issued to
// another client. Must be returned with a 400 (Bad Request).
// (rfc6749#section-5.2)
//
// This error is also used when PKCE validation failed due to that the values
// are not equal.
// (rfc7636#section-4.6)
func invalidGrantError(description string) *oauthError {
	return &oauthError{
		"invalid_grant",
		description,
	}
}

// The value of one of the client metadata fields is invalid and the server has
// rejected this request. Note that an authorization server MAY choose to
// substitute a valid value for any requested parameter of a client's metadata.
// Must be returned with a 400 (Bad Request).
// (rfc7591#section-3.2.2)
func invalidClientMetadata(description string) oauthError {
	return oauthError{
		"invalid_client_metadata",
		description,
	}
}

// The request is missing a required parameter, includes an unsupported
// parameter value (other than grant type), repeats a parameter, includes
// multiple credentials, utilizes more than one mechanism for authenticating the
// client, or is otherwise malformed. Must be returned with a 400 (Bad Request).
// (rfc6749#section-5.2)
func invalidRequestError(description string) oauthError {
	return oauthError{
		"invalid_request",
		description,
	}
}
