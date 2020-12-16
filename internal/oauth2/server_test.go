// +build !windows

package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/validator"
)

func TestNewServer(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	validator := validator.New()
	_, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}
}

func TestGetOpenIDConfiguration(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	validator := validator.New()
	server, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.GetOpenIDConfiguration)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected %d, got %d", http.StatusOK, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"id_token_signing_alg_values_supported":["RS256"]`) {
		t.Error("Expected valid body, got:")
		t.Log(rr.Body.String())
	}
}

func TestServiceDocRoute(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	validator := validator.New()
	server, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	req, _ := http.NewRequest("GET", "/v1/service_documentation", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.GetServiceDocumentationRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected %d, got %d", http.StatusOK, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `<h1 id="service-documentation-developer-overview">Service Documentation (developer overview)</h1>`) {
		t.Error("Expected valid body, got:")
		t.Log(rr.Body.String())
	}
}

func TestGetJwksRoute(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	validator := validator.New()
	server, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	req, _ := http.NewRequest("GET", "/v1/keys", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.GetJwksRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected %d, got %d", http.StatusOK, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"alg":"RS256"`) || !strings.Contains(rr.Body.String(), `"kty":"RSA"`) {
		t.Error("Expected valid body, got:")
		t.Log(rr.Body.String())
	}
}

func TestGetUserInfoRoute(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	validator := validator.New()
	server, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	userSID := "1-2-3-567"
	username := "sts"
	host := "https://axis.com"
	clientID := "40d2700d-0bfe-461b-943d-432e58518a71"
	nonce := "d2372a22-5654-460f-97e3-8771fdcb410c"
	groups := []auth.Group{
		{
			NiceName: "administrators",
			SID:      "1-2-4-567-8-098",
		},
		{
			NiceName: "users",
			SID:      "1-2-4-5-8-098",
		},
	}

	f := NewJwtFactory(server.signingKeys[0])
	accessToken, _ := f.NewAccessToken(userSID, username, host, clientID, nonce, groups)

	req, _ := http.NewRequest("GET", "/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.GetUserInfoRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected %d, got %d", http.StatusOK, rr.Code)
	}
	var response struct {
		Sub    string   `json:"sub"`
		Groups []string `json:"groups"`
	}

	err = json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}
	if response.Sub != username {
		t.Errorf("Expected username %q, got %q", username, response.Sub)
	}
	if !util.Contains(response.Groups, "administrators") || !util.Contains(response.Groups, "users") {
		t.Errorf("Expected groups %q, got %q", "administrators, users", strings.Join(response.Groups, ", "))
	}
}

func TestPostClientRoute(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	validator := validator.New()
	server, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	body := struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ResponseTypes           []string `json:"response_types"`
		GrantTypes              []string `json:"grant_types"`
		ApplicationType         string   `json:"application_type"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}{
		[]string{"https://www.axis.com"},
		[]string{"code"},
		[]string{"authorization_code"},
		"web",
		"Axis Web VMS",
		"client_secret_basic",
	}
	jsonValue, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/v1/clients", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.PostClientsRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected %d, got %d", http.StatusCreated, rr.Code)
	}
	match, err := regexp.MatchString(`"client_id":"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"`, rr.Body.String())
	if !match || err != nil {
		t.Error("Expected valid body, got:")
		t.Log(rr.Body.String())
	}
}

func TestCompleteFlow(t *testing.T) {
	dir := prepareDir()
	defer os.RemoveAll(dir)

	// CREATE NEW SERVER

	validator := validator.New()
	server, err := NewServer(auth.LoginHandler{}, database.NewDatabase(), dir, validator)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	// REGISTER NEW CLIENT

	body := struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ResponseTypes           []string `json:"response_types"`
		GrantTypes              []string `json:"grant_types"`
		ApplicationType         string   `json:"application_type"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}{
		[]string{"https://www.axis.com"},
		[]string{"code"},
		[]string{"authorization_code"},
		"web",
		"AXIS Web VMS",
		"client_secret_basic",
	}
	jsonValue, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/v1/clients", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.PostClientsRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected %d, got %d", http.StatusCreated, rr.Code)
	}

	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	clientID := fmt.Sprintf("%v", result["client_id"])
	nonce := "n-0S6_WzA2Mj"

	// SEND GET REQUEST TO LOGIN
	pkceCodeChallenge := "BmuXBE7laREJ5SzfMZxymVSUjZ4uV18s7nAiLIzYze0"

	loginQuery := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://www.axis.com"},
		"scope":                 {"openid"},
		"response_type":         {"code"},
		"code_challenge":        {pkceCodeChallenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {nonce},
	}

	req, _ = http.NewRequest("GET", "/v1/authorize", nil)
	req.URL.RawQuery = loginQuery.Encode()
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(server.GetLoginRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected %d, got %d", http.StatusOK, rr.Code)
		t.Log(rr.Body.String())
	}

	// POST FORM DATA TO LOGIN
	// TODO: Actually submit form, or send values from form if it is not submittable

	rrBody, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatal("Could not read request body")
	}
	htmlBody := string(rrBody)

	re := regexp.MustCompile(`auth_session_id" value="([a-zA-Z0-9-]+)">`)

	// Submatch 0 is the match of the entire expression, submatch 1 is the
	// first parenthesized subexpression, in this case the actual login attempt id.
	authSessionID := re.FindStringSubmatch(htmlBody)[1]

	form := url.Values{}
	form.Add("redirect_uri", "https://www.axis.com")
	form.Add("username", "sts")
	form.Add("password", "Hejsan123")
	form.Add("auth_session_id", authSessionID)
	form.Add("client_id", clientID)

	req, _ = http.NewRequest("POST", "/v1/authorize/handle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(server.PostLoginRoute)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d, got %d", http.StatusFound, rr.Code)
		t.Logf("Headers contains %+v", rr.Header())
	}
	location := rr.Header().Get("Location")
	u, _ := url.Parse(location)
	queryParam := u.Query()
	authCode := queryParam.Get("code")

	// CHECK CODE RETURNED FROM SERVER

	if len(authCode) < 20 {
		t.Errorf("Expected a sufficiently long auth code, got %q", authCode)
	}
}

func prepareDir() string {
	dir, _ := ioutil.TempDir("", "")
	loginTmplDest := filepath.Join(dir, "ui", "templates", "login.tmpl")
	_ = os.MkdirAll(filepath.Dir(loginTmplDest), os.ModePerm)
	_ = ioutil.WriteFile(loginTmplDest, getLoginTmplContent(), os.ModePerm)

	serviceDocTmplDest := filepath.Join(dir, "ui", "templates", "service_documentation.tmpl")
	_ = os.MkdirAll(filepath.Dir(serviceDocTmplDest), os.ModePerm)
	_ = ioutil.WriteFile(serviceDocTmplDest, getServiceDocTmplContent(), os.ModePerm)
	return dir
}

func getServiceDocTmplContent() []byte {
	s := `
<!DOCTYPE html>
<html>
<body>
<article class="markdown-body">
<h1 id="service-documentation-developer-overview">Service Documentation (developer overview)</h1>
<p>This service is an OpenID Connect (OIDC) identity provider (sometimes referred to as an authorization server).</p>
<p>Before a client can authenticate a user the client needs to be registered. Once registered, the user can authenticate and if the credentials are valid a JWT is returned to the client. The JWT is signed and can be used by other services to validate that the user is authenticated.</p>
<p>This authorization server implements open id connect with the authorization code flow, using PKCE. To authenticate a user, a PKCE code verifier and challenge must be created by the client. The only transformation that is supported for the code challenge is S256. For more information, see <a href="https://tools.ietf.org/html/rfc7636#section-4.1">this</a> section in the RFC for PKCE.</p>
<h2 id="register-a-client">Register A Client</h2>
<p>To register a client, send a POST request to <strong>/v1/clients</strong>. The endpoint expects the following attributes as JSON:</p>
<ul>
<li><code>redirect_uris</code>: An array of redirect_uris. Redirect URIs are validated according to <a href="https://tools.ietf.org/html/rfc7591#section-5">rfc7591#section-5</a>. Notably, remote websites must be protected by TLS.</li>
<li><code>response_types</code>: An array of response types. Currently only <code>code</code> is supported.</li>
<li><code>grant_types</code>: An array of grant types. Currently only <code>authorization_code</code> and <code>refresh_token</code> is supported.</li>
<li><code>application_type</code>: Must be <code>web</code> or <code>native</code>.</li>
<li><code>client_name</code>: A string containing the client name. Will be shown as a title on the login page.</li>
<li><code>client_description</code>: An optional string containing a client description. If present it will be shown on the login page.</li>
<li><code>token_endpoint_auth_method</code>: Is the requested authentication method. Only <code>client_secret_basic</code> is supported.</li>
</ul>
<p>Example request:</p>
<div class="sourceCode" id="cb1"><pre class="sourceCode bash"><code class="sourceCode bash"><span id="cb1-1"><a href="#cb1-1"></a><span class="ex">curl</span> --location --request POST <span class="st">&#39;localhost:50120/v1/clients&#39;</span> \</span>
<span id="cb1-2"><a href="#cb1-2"></a>--header <span class="st">&#39;Content-Type: application/json&#39;</span> \</span>
<span id="cb1-3"><a href="#cb1-3"></a>--data-raw <span class="st">&#39;{</span></span>
<span id="cb1-4"><a href="#cb1-4"></a><span class="st">    &quot;redirect_uris&quot;: [&quot;https://oidcdebugger.com/debug&quot;],</span></span>
<span id="cb1-5"><a href="#cb1-5"></a><span class="st">    &quot;response_types&quot;: [&quot;code&quot;],</span></span>
<span id="cb1-6"><a href="#cb1-6"></a><span class="st">    &quot;grant_types&quot;: [&quot;authorization_code&quot;, &quot;refresh_token&quot;],</span></span>
<span id="cb1-7"><a href="#cb1-7"></a><span class="st">    &quot;application_type&quot;: &quot;web&quot;,</span></span>
<span id="cb1-8"><a href="#cb1-8"></a><span class="st">    &quot;client_name&quot;: &quot;AXIS VMS Web Client&quot;,</span></span>
<span id="cb1-9"><a href="#cb1-9"></a><span class="st">    &quot;client_description&quot;: &quot;Axis VMS Web Client version 1.0&quot;</span></span>
<span id="cb1-10"><a href="#cb1-10"></a><span class="st">}&#39;</span></span></code></pre></div>
<h2 id="authenticate-a-user">Authenticate A User</h2>
<p>When the user requests to login, the client should retrieve the login form by requesting <strong>localhost:50120/v1/authorize</strong> (using either GET or POST) which will return a HTML page with a login form.</p>
<p><strong>localhost:50120/v1/authorize</strong> expects the following parameters (which should be query parameter for GET and form parameters for POST):</p>
<ul>
<li><code>client_id</code>: The client id. To obtain a client id, register a client using the register client request.</li>
<li><code>redirect_uri</code>: Where the client should be redirected once the authentication is done. Must be a redirect uri that was provided when the client was created.</li>
<li><code>scope</code>: What kind of OAuth scope that is requested. Only <code>openid</code> is supported as of now.</li>
<li><code>response_type</code>: Must be the response_type used when registering the client.</li>
</ul>
<p>If the user credentials is valid, the user is redirected to the <code>redirect_uri</code> with the authorization code as a query parameter. If invalid, the user will be redirected to the <code>redirect_uri</code> along with an error.</p>
</article>
</body>
</html>
	`
	return []byte(s)
}

func getLoginTmplContent() []byte {
	s := `
<!DOCTYPE html>
<html>
<body>

<h2>Login</h2>
<form action="/v1/authorize" method="post">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <label for="uname">Username:</label><br>
  <input type="text" id="uname" name="uname"><br>
  <label for="password">Password:</label><br>
  <input type="password" id="password" name="password"><br><br>
  <input type="submit" value="Login">
  <input type="hidden" name="auth_session_id" value="{{.AuthSessionID}}">
</form>

</body>
</html>
	`
	return []byte(s)
}
