package oauth2

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/form3tech-oss/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/models"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/random"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/validator"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/net"
	"golang.org/x/crypto/bcrypt"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
)

// Server instance
type Server struct {
	loginHandler             auth.LoginHandler
	database                 *database.Database
	signingKeys              []*rsa.PrivateKey
	loginTmpl                *template.Template
	serviceDocTmpl           *template.Template
	supportedResponseTypes   []string
	supportedGrantTypes      []string
	supportedApplicationType []string
	supportedScopes          []string
	supportedSigningAlg      []string
	requiredScopes           []string
	*validator.Validator
}

// NewServer creates new Server instance
func NewServer(lh auth.LoginHandler, db *database.Database, fileStoragePath string, validator *validator.Validator) (*Server, error) {
	signKeys, err := util.GetPrivateKeys(fileStoragePath)
	if err != nil {
		return nil, err
	}
	loginTemplatePath := filepath.Join(fileStoragePath, "ui", "templates", "login.tmpl")
	serviceDocTemplatePath := filepath.Join(fileStoragePath, "ui", "templates", "service_documentation.tmpl")

	loginTemplateFile, err := template.ParseFiles(loginTemplatePath)
	if err != nil {
		return nil, err
	}
	serviceDocTemplateFile, err := template.ParseFiles(serviceDocTemplatePath)
	if err != nil {
		return nil, err
	}

	server := &Server{
		loginHandler:             lh,
		database:                 db,
		signingKeys:              signKeys,
		loginTmpl:                template.Must(loginTemplateFile, nil),
		serviceDocTmpl:           template.Must(serviceDocTemplateFile, nil),
		supportedResponseTypes:   []string{"code"},
		supportedGrantTypes:      []string{"authorization_code", "refresh_token"},
		supportedApplicationType: []string{"web"},
		supportedScopes:          []string{"openid"},
		supportedSigningAlg:      []string{"RS256"},
		requiredScopes:           []string{"openid"},
		Validator:                validator,
	}

	go server.cleanupOldAuthenticationSessions()
	go server.cleanupOldCodeExchangeSession()

	return server, nil
}

// GetOpenIDConfiguration implements the .well-known openid-configuration route
// that returns metadata
func (s *Server) GetOpenIDConfiguration(responseWriter http.ResponseWriter, request *http.Request) {
	host := fmt.Sprintf("https://%s", request.Host)
	metadata := struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		JWKSURI                          string   `json:"jwks_uri"`
		RegistrationEndpoint             string   `json:"registration_endpoint"`
		ServiceDocumentation             string   `json:"service_documentation"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
		ScopesSupported                  []string `json:"scopes_supported"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
		CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
		TokenAuthMethodsSupported        []string `json:"token_endpoint_auth_methods_supported"`
		AuthResponseIssParamSupported    string   `json:"authorization_response_iss_parameter_supported"`
		ClaimsSupported                  []string `json:"claims_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
	}{
		host,
		fmt.Sprintf("%s/v1/authorize", host),
		fmt.Sprintf("%s/v1/keys", host),
		fmt.Sprintf("%s/v1/clients", host),
		fmt.Sprintf("%s/v1/service-documentation", host),
		fmt.Sprintf("%s/v1/token", host),
		fmt.Sprintf("%s/v1/userinfo", host),
		s.supportedScopes,
		s.supportedResponseTypes,
		s.supportedSigningAlg,
		[]string{"S256"},
		[]string{"client_secret_basic"},
		"true",
		[]string{"iss", "iat", "sub", "aud", "exp", "nbf", "jti", "azp", "nonce", "purpose", "userSID", "username", "groups", "groupsNiceName"},
		[]string{"public"},
	}

	net.SendJSON(responseWriter, metadata, http.StatusOK)
}

// PostClientsRoute implements the client registration route
func (s *Server) PostClientsRoute(responseWriter http.ResponseWriter, request *http.Request) {
	var newClientRequest validator.PostClientRequest

	// set default
	newClientRequest.ApplicationType = "web"

	err := json.NewDecoder(request.Body).Decode(&newClientRequest)
	if err != nil {
		logger.Debug("PostClientsRoute: Could not decode json")
		net.SendJSON(responseWriter, invalidClientMetadata("Invalid body"), http.StatusBadRequest)
		return
	}

	errors := s.ValidatePostClientRequest(&newClientRequest,
		s.supportedResponseTypes,
		s.supportedGrantTypes,
		s.supportedApplicationType,
	)

	if !errors.Empty() {
		// if len(validationErrors) > 0 {
		// according to rfc7591#section-3.2.2, error response should contain a
		// single error object. Therefore we concatenate multiple errors if
		// needed. Status code 400 (Bad Request) should be used.
		net.SendJSON(responseWriter, invalidClientMetadata(s.BagToString(errors, ";")), http.StatusBadRequest)
		return
	}

	clientSecret := random.String(40)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Could not hash client secret: %s", err.Error())
		net.SendJSON(responseWriter, internalServerError, http.StatusInternalServerError)
		return
	}

	newClient := models.Client{
		RedirectURIs:       newClientRequest.RedirectURIs,
		ResponseTypes:      newClientRequest.ResponseTypes,
		GrantTypes:         newClientRequest.GrantTypes,
		ApplicationType:    newClientRequest.ApplicationType,
		ClientName:         newClientRequest.ClientName,
		ClientDescription:  newClientRequest.ClientDescription,
		HashedClientSecret: hashedSecret,

		// 0 means that the secret doesn't expire
		ClientSecretExpiresAt: 0,
	}

	newClient.ID = uuid.New()
	s.database.AddClient(&newClient)
	logger.Debug("PostClientsRoute: Created client with id %s", newClient.ID)

	net.SendJSON(responseWriter, models.Client{
		ID:                    newClient.ID,
		RedirectURIs:          newClient.RedirectURIs,
		ResponseTypes:         newClient.ResponseTypes,
		GrantTypes:            newClient.GrantTypes,
		ApplicationType:       newClient.ApplicationType,
		ClientName:            newClient.ClientName,
		ClientDescription:     newClient.ClientDescription,
		ClientSecretExpiresAt: newClient.ClientSecretExpiresAt,
		// Return the unhashed client secret to the client
		ClientSecret: clientSecret,
	}, http.StatusCreated)
	logger.Audit("Client with ID %q created", newClient.ID)
}

// DeleteClientsRoute implements the delete clients route. 401 Unauthorized is
// returned instead of a more detailed 404 when the client isn't found in the
// database, as long as the id is in a valid format.
func (s *Server) DeleteClientsRoute(responseWriter http.ResponseWriter, request *http.Request) {
	clientID, clientSecret, ok := request.BasicAuth()
	if !ok {
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	id := mux.Vars(request)["id"]

	errs := s.ValidateVariable(id, "required,uuid4")
	if !errs.Empty() {
		net.SendJSON(responseWriter, notFoundError, http.StatusNotFound)
		return
	}

	if id != clientID {
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	client := s.database.FindClient(clientID)
	if client == nil {
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	// Validate that the client has the client secret
	if bcrypt.CompareHashAndPassword(client.HashedClientSecret, []byte(clientSecret)) != nil {
		logger.Debug("DeleteClientsRoute: attempt to remove client with incorrect client secret")
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	// All good, remove client and tokens belonging to client
	s.database.DeleteClient(clientID)
	s.database.DeleteRefreshTokensForClient(clientID)

	// Authsessions and code exchange sessions will be cleaned up at regular
	// intervals, so is skipped here as to avoid two costly loops (but would
	// not be costly if we have a real SQL database, so potentially change in
	// the future).

	logger.Debug("Client and refresh tokens are removed for client %q", clientID)

	responseWriter.WriteHeader(http.StatusNoContent)
	logger.Audit("Client with ID %q deleted", clientID)
}

// GetJwksRoute implements the jwks route
func (s *Server) GetJwksRoute(responseWriter http.ResponseWriter, request *http.Request) {
	keys := GetJwks(s.signingKeys)

	net.SendJSON(responseWriter, keys, http.StatusOK)
}

// PostTokenRoute implements the token endpoint route
// (openid-connect-core-1_0.html#TokenEndpoint)
func (s *Server) PostTokenRoute(responseWriter http.ResponseWriter, request *http.Request) {
	clientID, clientSecret, ok := request.BasicAuth()
	if !ok {
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	redirectURI := request.PostFormValue("redirect_uri")
	code := request.PostFormValue("code")
	grantType := request.PostFormValue("grant_type")
	codeVerifier := request.PostFormValue("code_verifier")
	refreshToken := request.PostFormValue("refresh_token")

	// Validate request so that it is in the correct format
	tokenRequest := validator.PostTokenRequest{
		Code:             code,
		GrantType:        grantType,
		PKCECodeVerifier: codeVerifier,
		RedirectURI:      redirectURI,
		RefreshToken:     refreshToken,
	}

	validationErrs := s.ValidatePostTokenRequest(&tokenRequest)
	if validationErrs.FailedOn("grant_type") {
		net.SendJSON(responseWriter, unsupportedGrantError, http.StatusBadRequest)
		return
	}
	if !validationErrs.Empty() {
		net.SendJSON(responseWriter, invalidRequestError(s.BagToString(validationErrs, ";")), http.StatusBadRequest)
		return
	}

	client := s.database.FindClient(clientID)

	if client == nil {
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	// Validate that the client has the client secret
	if bcrypt.CompareHashAndPassword(client.HashedClientSecret, []byte(clientSecret)) != nil {
		logger.Debug("PostTokenRoute: Client secret does not match what is stored for client %q", client.ID)
		net.SendUnauthorizedJSON(responseWriter, invalidClientError, net.AuthMethodBasic)
		return
	}

	var rtID string
	var oerr *oauthError
	var refreshTokenSession *models.RefreshTokenSession
	if grantType == "authorization_code" {

		rtID, refreshTokenSession, oerr = s.handleAuthCodeExchange(client, redirectURI, clientID, code, codeVerifier)
		if oerr != nil {
			net.SendJSON(responseWriter, oerr, http.StatusBadRequest)
			return
		}

	} else if grantType == "refresh_token" {

		rtID, refreshTokenSession, oerr = s.handleRefreshTokenExchange(refreshToken, clientID)
		if oerr != nil {
			net.SendJSON(responseWriter, oerr, http.StatusBadRequest)
			return
		}

	} else {
		logger.Error("Unsupported grant_type %q passed validation", grantType)
		net.SendJSON(responseWriter, internalServerError, http.StatusInternalServerError)
		return
	}

	userInfo := refreshTokenSession.UserInfo
	nonce := refreshTokenSession.Nonce

	signingKey := s.signingKeys[0]
	tokenFactory := NewJwtFactory(signingKey)

	// Create ID Token
	idToken, err := tokenFactory.NewIDToken(
		userInfo.Username,
		request.Host,
		clientID,
		nonce,
	)
	if err != nil {
		logger.Error(err.Error())
		net.SendJSON(responseWriter, internalServerError, http.StatusInternalServerError)
		return
	}

	// Create Access Token
	accessToken, err := tokenFactory.NewAccessToken(
		userInfo.UserSID,
		userInfo.Username,
		request.Host,
		clientID,
		nonce,
		userInfo.Groups,
	)
	if err != nil {
		logger.Error(err.Error())
		net.SendJSON(responseWriter, internalServerError, http.StatusInternalServerError)
		return
	}

	net.SendJSON(responseWriter, struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IdToken      string `json:"id_token"`
		Scope        string `json:"scope"`
	}{
		accessToken,
		"Bearer",
		int(config.AccessTokenExpiry.Seconds()),
		rtID,
		idToken,
		"openid",
	}, http.StatusOK)

	logger.Audit("Client %q performed a token exchange with grant_type %q for user %q", clientID, grantType, userInfo.Username)
}

func (s *Server) handleAuthCodeExchange(client *models.Client, redirectURI, clientID, code, codeVerifier string) (string, *models.RefreshTokenSession, *oauthError) {
	// Validate that the client has the redirect uri registered
	if !util.Contains(client.RedirectURIs, redirectURI) {
		logger.Debug("PostTokenRoute: Redirect URI %q is not registered on client %q", redirectURI, clientID)
		return "", nil, invalidGrantError("Redirect URI is not registered on the client")
	}

	hashedCode := util.HashSHA3(code)
	codeExchangeSession := s.database.TakeOutCodeExchangeSession(hashedCode)

	// Validate the code
	if codeExchangeSession == nil {
		logger.Debug("PostTokenRoute: login attempt with expired/non-existing authorization code")
		return "", nil, invalidGrantError("Code is invalid or has expired")
	}
	if codeExchangeSession.HasExpired(config.CodeExchangeExpiry) || clientID != codeExchangeSession.ClientID {
		logger.Debug("PostTokenRoute: Invalid authentication code usage. User client %q, authentication code client %q, created at %q", clientID, codeExchangeSession.ClientID, codeExchangeSession.CreatedAt)
		return "", nil, invalidGrantError("Code is invalid or has expired")
	}

	if codeExchangeSession.RedirectURI != redirectURI {
		logger.Debug("PostTokenRoute: Redirect URI %q was not used for the initial authorization request (%q)", redirectURI, codeExchangeSession.RedirectURI)
		return "", nil, invalidGrantError("Redirect URI was not used for the authorization request")
	}

	// Validate the code_verifier (PKCE)
	assumedCodeChallenge := determineCodeChallenge(codeVerifier)
	if assumedCodeChallenge != codeExchangeSession.CodeChallenge {
		logger.Debug("PostTokenRoute: PKCE code verification failed")
		return "", nil, invalidGrantError("Invalid code_verifier")
	}

	userInfo := codeExchangeSession.UserInfo
	nonce := codeExchangeSession.Nonce

	// clean up old code exchange session
	s.database.DeleteCodeExchangeSession(codeExchangeSession.ID)
	logger.Debug("PostTokenRoute: Removed CodeExchangeSession for client %q", clientID)

	// Create Refresh Token
	id, refreshTokenSession := models.NewRefreshTokenSession(
		clientID,
		nonce,
		userInfo,
	)
	s.database.AddRefreshTokenSession(refreshTokenSession)

	return id, refreshTokenSession, nil
}

func (s *Server) handleRefreshTokenExchange(refreshToken, clientID string) (string, *models.RefreshTokenSession, *oauthError) {
	hashed := util.HashSHA3(refreshToken)
	refreshTokenSession := s.database.TakeOutRefreshTokenSession(hashed)
	if refreshTokenSession == nil {
		// Session does not exist, check if it has been previously rotated
		oldRefreshTokenSession := s.database.FindRotatedRefreshTokenSession(hashed)
		if oldRefreshTokenSession != nil {
			logger.Warning("An old refresh token has been used for client %q", clientID)
			logger.Warning("Deleting refresh token session for user %q", oldRefreshTokenSession.UserInfo.Username)
			s.database.DeleteRefreshTokenSession(oldRefreshTokenSession.ID)
		}

		logger.Debug("PostTokenRoute: login attempt with expired/non-existing refresh token")
		return "", nil, invalidGrantError("Refresh token is invalid or has expired")
	}

	if refreshTokenSession.HasExpired(config.RefreshTokenTimeout) || clientID != refreshTokenSession.ClientID {
		logger.Debug("PostTokenRoute: Invalid refresh token usage. User client %q, refresh token client %q, created at %q", clientID, refreshTokenSession.ClientID, refreshTokenSession.CreatedAt)
		return "", nil, invalidGrantError("Refresh token is invalid or has expired")
	}

	id, _ := refreshTokenSession.Rotate()
	s.database.AddRefreshTokenSession(refreshTokenSession)

	return id, refreshTokenSession, nil
}

// GetLoginRoute implements the authorization endpoint
// (openid-connect-core-1_0.html#AuthorizationEndpoint)
func (s *Server) GetLoginRoute(responseWriter http.ResponseWriter, request *http.Request) {
	clientID := request.FormValue("client_id")
	redirectURI := request.FormValue("redirect_uri")
	nonce := request.FormValue("nonce")
	scopeValue := request.FormValue("scope")
	scopes := strings.Split(scopeValue, " ")
	pkceCodeChallenge := request.FormValue("code_challenge")
	pkceCodeChallengeMethod := request.FormValue("code_challenge_method")
	responseTypeValue := request.FormValue("response_type")
	state := request.FormValue("state")
	responseTypes := strings.Split(responseTypeValue, " ")

	loginRequest := validator.GetLoginRequest{
		ClientID:                clientID,
		RedirectURI:             redirectURI,
		Nonce:                   nonce,
		Scopes:                  scopes,
		ResponseTypes:           responseTypes,
		PKCECodeChallenge:       pkceCodeChallenge,
		PKCECodeChallengeMethod: pkceCodeChallengeMethod,
		State:                   state,
	}

	errs := s.ValidateGetLoginRequest(&loginRequest, s.database)

	if errs.FailedOn("client_id") || errs.FailedOn("redirect_uri") {
		// Return errors from ClientID and RedirectURI as plain/http
		// (rfc6749#section-4.1.2.1)
		errs = errs.GetErrorsFor("client_id", "redirect_uri")
		http.Error(responseWriter, s.BagToString(errs, "\n"), http.StatusBadRequest)
		return
	}

	if !errs.Empty() {
		// If invalid request the error should be a query parameter in the redirect
		// response (rfc6749#section-4.1.2.1)

		// Authentication error response (except for redirect_uri and
		// client_id) should return as 302 Found
		// (openid-connect-core-1_0.html#AuthError)
		rUrl, err := url.Parse(redirectURI)
		if err != nil {
			logger.Info("Client used malformed redirect_uri")
			http.Error(responseWriter, "Malformed redirect_uri", http.StatusBadRequest)
			return
		}

		q := rUrl.Query()
		q.Add("iss", fmt.Sprintf("https://%s", request.Host))
		if len(state) > 0 {
			// If the state parameter was present in the auth request, it is
			// required to be in the redirect (openid-connect-core-1_0 section
			// 3.1.2.6).
			q.Add("state", state)
		}
		q.Add("error", "invalid_request")
		q.Add("error_description", s.BagToString(errs, ","))
		rUrl.RawQuery = q.Encode()

		http.Redirect(responseWriter, request, rUrl.String(), http.StatusFound)
		return
	}

	authenticationSession := models.NewAuthenticationSession(pkceCodeChallenge, clientID, nonce, state, redirectURI)
	s.database.AddAuthenticationSession(authenticationSession)
	logger.Debug("Created AuthenticationSession for client %q", clientID)

	client := s.database.FindClient(clientID)
	data := struct {
		ClientID             string
		RedirectURI          string
		AuthSessionID        string
		ClientName           string
		ClientDescription    string
		IncorrectCredentials bool
	}{
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		AuthSessionID:        authenticationSession.ID,
		ClientName:           client.ClientName,
		ClientDescription:    client.ClientDescription,
		IncorrectCredentials: false,
	}

	_ = s.loginTmpl.Execute(responseWriter, data)
	logger.Audit("Client %q initiated a login", clientID)
}

// PostLoginRoute handles the posted form from the authorization endpoint
// (openid-connect-core-1_0.html#AuthorizationEndpoint)
func (s *Server) PostLoginRoute(responseWriter http.ResponseWriter, request *http.Request) {
	authSessionID := request.PostFormValue("auth_session_id")
	redirectURI := request.PostFormValue("redirect_uri")
	uname := request.PostFormValue("username")
	password := request.PostFormValue("password")
	clientID := request.PostFormValue("client_id")
	username := uname
	domain := "."
	if strings.Contains(uname, "\\") {
		parts := strings.Split(uname, "\\")
		domain = parts[0]
		username = parts[1]
	}
	logger.Debug("Attempting to login user %s", username)

	loginRequest := validator.PostLoginRequest{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Username:      username,
		Password:      password,
		AuthSessionID: authSessionID,
	}

	errs := s.ValidatePostLoginRequest(&loginRequest, s.database)

	if errs.FailedOn("client_id") || errs.FailedOn("redirect_uri") {
		// Validate client ID and redirect URI. According to rfc6749#section-4.1.2.1
		// these should NOT be included in the redirect and instead shown to the
		// resource owner (user).
		http.Error(responseWriter, s.BagToString(errs, "\n"), http.StatusBadRequest)
		return
	}
	rUrl, err := url.Parse(redirectURI)
	if err != nil {
		logger.Info("Client used malformed redirect_uri")
		http.Error(responseWriter, "Malformed redirect_uri", http.StatusBadRequest)
		return
	}

	q := rUrl.Query()
	q.Add("iss", fmt.Sprintf("https://%s", request.Host))

	// Check login attempt. If it doesn't exist, return with error.
	authSession := s.database.FindAuthenticationSession(authSessionID)
	if authSession == nil {
		// check if it is nil in the offchance that it was removed since we did the AuthSessionIDValidation.
		logger.Info("Login attempted with invalid session id.")
		q.Add("error", "invalid_request")
		q.Add("error_description", "Login attempt timed out. Please try again.")
		rUrl.RawQuery = q.Encode()

		http.Redirect(responseWriter, request, rUrl.String(), http.StatusFound)
		return
	}

	if authSession.RedirectURI != redirectURI {
		logger.Info("Redirect URI used for post login route is not the same as the flow was initiated with.")
		// Validate redirect URI. According to rfc6749#section-4.1.2.1 the
		// authorization server MUST not automatically redirect and instead
		// inform the resource owner (user).
		http.Error(responseWriter, "Redirect URI used is not the same as authorization request was initiated with", http.StatusBadRequest)
		return
	}

	if len(authSession.State) > 0 {
		// state is required if the state parameter is present in the
		// Authorization Request (RFC 6749 section-4.1.2 and
		// openid-connect-core-1_0 section 3.1.2.6).
		q.Add("state", authSession.State)
	}

	if !errs.Empty() {
		logger.Debug("Validation failed for PostLoginRoute")
		// Return errors from ClientID and RedirectURI as plain/http
		// (rfc6749#section-4.1.2.1)

		// Authentication error response (except for redirect_uri and
		// client_id) should return as 302 Found
		// (openid-connect-core-1_0.html#AuthError)
		s.database.DeleteAuthenticationSession(authSessionID)
		q.Add("error", "invalid_request")
		q.Add("error_description", s.BagToString(errs, ","))
		rUrl.RawQuery = q.Encode()

		http.Redirect(responseWriter, request, rUrl.String(), http.StatusFound)
		return
	}
	client := s.database.FindClient(authSession.ClientID)
	if client == nil {
		logger.Info("Could not find client %q belonging to auth session.", authSession.ClientID)
		// According to rfc6749#section-4.1.2.1, a missing client id should not
		// result in a redirect but instead be shown to the resource owner
		// (user)
		http.Error(responseWriter, "client_id does not exist\n", http.StatusBadRequest)
		return
	}

	userSID, err := s.loginHandler.Verify(username, domain, password)
	if err != nil {
		logger.Info("Login attempt failed for user %s. Error: %s", username, err.Error())

		data := struct {
			ClientID             string
			RedirectURI          string
			AuthSessionID        string
			ClientName           string
			ClientDescription    string
			IncorrectCredentials bool
		}{
			ClientID:             authSession.ClientID,
			RedirectURI:          authSession.RedirectURI,
			AuthSessionID:        authSession.ID,
			ClientName:           client.ClientName,
			ClientDescription:    client.ClientDescription,
			IncorrectCredentials: true,
		}

		_ = s.loginTmpl.Execute(responseWriter, data)
		return
	}

	userGroups, err := s.loginHandler.GetUserGroups(uname)
	if err != nil {
		logger.Error(err.Error())
		s.database.DeleteAuthenticationSession(authSessionID)
		net.SendErrorResponse(responseWriter, request, errorServer, errorServerDescription, http.StatusInternalServerError)
		return
	}

	ui := models.UserInfo{
		Groups:   userGroups,
		UserSID:  userSID,
		Username: username,
	}

	authorizationCode, codeExchangeSession := models.NewCodeExchangeSession(clientID, authSession.CodeChallenge, authSession.Nonce, authSession.RedirectURI, &ui)
	s.database.AddCodeExchangeSession(codeExchangeSession)
	logger.Debug("Created CodeExchangeSession for client %q", clientID)

	// clean up authentication session, no longer needed
	s.database.DeleteAuthenticationSession(authSessionID)
	logger.Debug("Removed AuthenticationSession for client %q", clientID)

	logger.Debug("Login attempt for user %s was successful", username)

	q.Add("code", authorizationCode)
	rUrl.RawQuery = q.Encode()

	http.Redirect(responseWriter, request, rUrl.String(), http.StatusFound)

	logger.Audit("Client %q finished a login for user %q", clientID, username)
}

// GetUserInfoRoute implements the userinfo endpoint
// (openid-connect-core-1_0.html#UserInfo)
func (s *Server) GetUserInfoRoute(responseWriter http.ResponseWriter, request *http.Request) {
	authHeader := request.Header.Get("authorization")
	splitHeader := strings.Split(authHeader, "Bearer ")
	if len(splitHeader) != 2 {
		logger.Debug("Missing or invalid authorization header")
		net.SendUnauthorizedJSON(responseWriter, invalidTokenError, net.AuthMethodBearer)
		return
	}
	accessToken := splitHeader[1]
	for _, key := range s.signingKeys {
		token, err := Verify(accessToken, &key.PublicKey)
		if err == nil {
			// Access token validated

			if !token.Valid {
				logger.Debug("UserInfo endpoint accessed using invalid/expired JWT")
				net.SendUnauthorizedJSON(responseWriter, invalidTokenError, net.AuthMethodBearer)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				logger.Warning("Unable to parse access token claims: %v", token.Claims)
				net.SendJSON(responseWriter, internalServerError, http.StatusInternalServerError)
				return
			}

			sub, subOK := claims["sub"].(string)
			groups, groupsOK := claims["groupsNiceName"].(string)
			if !subOK || !groupsOK {
				// Access token signed by one of our private keys, but is missing desired claims.
				// This can happen if the JWT is an ID token or the same key is used for multiple services.
				logger.Warning("UserInfo endpoint accessed using JWT with missing claims, had %v", claims)
				net.SendUnauthorizedJSON(responseWriter, invalidTokenError, net.AuthMethodBearer)
				return
			}

			groupsSlice := strings.Split(groups, ",")
			net.SendJSON(responseWriter, struct {
				Sub    string   `json:"sub"`
				Groups []string `json:"groups"`
			}{
				Sub:    sub,
				Groups: groupsSlice,
			}, http.StatusOK)

			logger.Audit("UserInfo for user %q requested", sub)
			return
		}
	}
	logger.Debug("UserInfo endpoint accessed using access token signed by other key than one stored on the server")
	net.SendUnauthorizedJSON(responseWriter, invalidTokenError, net.AuthMethodBearer)
}

// GetServiceDocumentationRoute implements the get service documentation route
// that returns a html template.
func (s *Server) GetServiceDocumentationRoute(responseWriter http.ResponseWriter, request *http.Request) {
	data := struct {
		Host string
	}{
		Host: request.Host,
	}
	_ = s.serviceDocTmpl.Execute(responseWriter, data)
}

// cleanupOldAuthenticationSessions will delete authSessions older than 20 minutes.
// This means that the user have 20 minutes to login after the login page is
// shown.
func (s *Server) cleanupOldAuthenticationSessions() {
	cleanupInterval := 1 * time.Minute

	for {
		time.Sleep(cleanupInterval)
		logger.Debug("Running cleanupOldSessions (authSessions older than %s will be removed)", config.AuthSessionExpiry.String())

		oldAuthenticationSessions := s.database.GetOldAuthenticationSessions(config.AuthSessionExpiry)
		for _, authSession := range oldAuthenticationSessions {
			logger.Debug("Deleting AuthenticationSession created at %q", authSession.CreatedAt.String())
			s.database.DeleteAuthenticationSession(authSession.ID)
		}
	}
}

// cleanupOldCodeExchangeSession will delete old token exchange sessions.
// This method does not run as frequent as cleanupOldAuthenticationSessions,
// since token exchange sessions are only created after correct login attempts.
// Since this runs infrequently, the database could still contain old token
// exchange sessions and session code should therefore be checked if it is
// valid before using it.
func (s *Server) cleanupOldCodeExchangeSession() {
	cleanupInterval := 10 * time.Minute

	for {
		time.Sleep(cleanupInterval)
		logger.Debug("Running cleanupOldCodeExchangeSession (CodeExchangesSessions older than %s will be removed)", config.CodeExchangeExpiry.String())

		oldCodeExchangeSessions := s.database.GetOldCodeExchangeSession(config.CodeExchangeExpiry)
		for _, oldCodeExchangeSession := range oldCodeExchangeSessions {
			logger.Debug("Deleting CodeExchangeSession created at %q", oldCodeExchangeSession.CreatedAt.String())
			s.database.DeleteCodeExchangeSession(oldCodeExchangeSession.ID)
		}
	}
}
