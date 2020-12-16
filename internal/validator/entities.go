package validator

// PostClientRequest contains the go-playground/validator struct tags that
// validates a new client.
type PostClientRequest struct {
	RedirectURIs            []string `json:"redirect_uris" validate:"required,min=1,max=10,unique,dive,max=2000,validRedirectURI"`
	ResponseTypes           []string `json:"response_types" validate:"required,min=1,max=10,dive,max=255,validResponseTypes"`
	GrantTypes              []string `json:"grant_types" validate:"required,min=1,max=10,dive,max=255,validGrantTypes"`
	ApplicationType         string   `json:"application_type" validate:"omitempty,max=255,validApplicationTypes"`
	ClientName              string   `json:"client_name" validate:"required,min=1,max=70"`
	ClientDescription       string   `json:"client_description" validate:"omitempty,min=1,max=255"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" validate:"omitempty,oneof=client_secret_basic"`
}

// PostLoginRequest contains the go-playground/validator struct tags that validates
// a login request.
type PostLoginRequest struct {
	ClientID      string `json:"client_id" validate:"required,uuid4,clientExist"`
	RedirectURI   string `json:"redirect_uri" validate:"required,max=2000,clientHasRedirectURI"`
	Username      string `json:"username" validate:"max=255"`
	Password      string `json:"password" validate:"max=255"`
	AuthSessionID string `json:"auth_session_id" validate:"required,uuid4,authSessionIDIsValid"`
}

// GetLoginRequest contains the go-playground/validator struct tags that
// validates a login request. The json tags are used to return the correct
// field names.
type GetLoginRequest struct {
	ClientID                string   `json:"client_id" validate:"required,uuid4,clientExist"`
	RedirectURI             string   `json:"redirect_uri" validate:"required,max=2000,clientHasRedirectURI"`
	Nonce                   string   `json:"nonce" validate:"omitempty,min=10,max=255"`
	Scopes                  []string `json:"scope" validate:"required,min=1,dive,max=255,oneof=openid"`
	ResponseTypes           []string `json:"response_type" validate:"required,min=1,dive,max=255,clientHasResponseType"`
	PKCECodeChallenge       string   `json:"code_challenge" validate:"required,min=43,max=128"`
	PKCECodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256"`
	State                   string   `json:"state" validate:"omitempty,min=1,max=1000"`
}

// PostTokenRequest contains rules for validating a token request
type PostTokenRequest struct {
	Code             string `json:"code" validate:"required_if=GrantType authorization_code,max=100"`
	GrantType        string `json:"grant_type" validate:"required,oneof=authorization_code refresh_token"`
	PKCECodeVerifier string `json:"code_verifier" validate:"required_if=GrantType authorization_code,max=255"`
	RedirectURI      string `json:"redirect_uri" validate:"required_if=GrantType authorization_code,max=2000"`
	RefreshToken     string `json:"refresh_token" validate:"required_if=GrantType refresh_token,max=255"`
}
