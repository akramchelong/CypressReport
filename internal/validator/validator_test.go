package validator

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/database"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/models"
)

func TestValidatePostClientRequest(t *testing.T) {
	type testInput struct {
		client                PostClientRequest
		validResponseTypes    []string
		validGrantTypes       []string
		validApplicationTypes []string
	}

	type testCase struct {
		name string
		in   testInput
		want string
	}

	tests := []testCase{
		{
			name: "Missing redirect uris",
			in: testInput{
				PostClientRequest{[]string{}, []string{"id_token"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "redirect_uris does not contain enough elements",
		},
		{
			name: "Missing response types",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "response_types does not contain enough elements",
		},
		{
			name: "Missing grant types",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "grant_types does not contain enough elements",
		},
		{
			name: "Optional application type is valid",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "",
		},
		{
			name: "Missing client name",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "web", "", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "client_name must have a value",
		},
		{
			name: "Incorrect (unsecure) redirect uri",
			in: testInput{
				PostClientRequest{[]string{"http://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "redirect_uris[0] is not valid",
		},
		{
			name: "Incorrect (multiple non-unique) redirect uris",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback", "https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "redirect_uris must be unique",
		},
		{
			name: "Incorrect (too long) redirect uris",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback", "https://example.com/auth/verylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurl"}, []string{"id_token"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "redirect_uris[1] contains too many elements",
		},
		{
			name: "Incorrect (wrong) response type",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"idToken"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "response_types[0] failed on the validResponseTypes rule",
		},
		{
			name: "Incorrect (too long) response type",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token", "emailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemail"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "response_types[1] contains too many elements",
		},
		{
			name: "Incorrect (wrong) grant type",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"explicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "grant_types[0] contains an invalid grant type",
		},
		{
			name: "Incorrect (too long) grant type",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicitimplicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "grant_types[0] contains too many elements",
		},
		{
			name: "Incorrect (wrong) application type",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "native", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "Value for application_type is not a valid application type",
		},
		{
			name: "Incorrect (too long) application type",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "webwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebwebweb", "VMS Client", "VMS Client 1.0", "client_secret_basic"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "application_type contains too many elements",
		},
		{
			name: "Incorrect token endpoint auth method",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_post"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "token_endpoint_auth_method has an invalid value",
		},
		{
			name: "Incorrect token auth method",
			in: testInput{
				PostClientRequest{[]string{"https://example.com/auth/callback"}, []string{"id_token"}, []string{"implicit"}, "web", "VMS Client", "VMS Client 1.0", "client_secret_post"},
				[]string{"id_token"},
				[]string{"implicit"},
				[]string{"web"},
			},
			want: "token_endpoint_auth_method has an invalid value",
		},
	}

	v := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorBag := v.ValidatePostClientRequest(&tt.in.client, tt.in.validResponseTypes, tt.in.validGrantTypes, tt.in.validApplicationTypes)
			got := v.BagToString(errorBag, ";")
			if got != tt.want {
				t.Errorf("\ngot\n\t%q\nwant\n\t%q", got, tt.want)
			}
		})
	}
}

func TestPostLoginRequest(t *testing.T) {
	type testInput struct {
		loginRequest PostLoginRequest
		db           *database.Database
	}

	type testCase struct {
		name string
		in   testInput
		want []string
	}

	db := database.NewDatabase()

	testClient := models.Client{}
	testClient.ID = uuid.New()
	testClient.RedirectURIs = []string{"https://auth.axis.com/callback"}

	db.AddClient(&testClient)

	pkceCodeChallenge := "BmuXBE7laREJ5SzfMZxymVSUjZ4uV18s7nAiLIzYze0"
	authSession := models.NewAuthenticationSession(pkceCodeChallenge, testClient.ID.String(), "abcdefghijk", "home", "http://auth.axis.com/callback")
	db.AddAuthenticationSession(authSession)

	v := New()

	tests := []testCase{
		{
			name: "Test valid request",
			in: testInput{
				PostLoginRequest{
					ClientID:      testClient.ID.String(),
					RedirectURI:   testClient.RedirectURIs[0],
					Username:      "bob",
					Password:      "correcthorsebatterystaple",
					AuthSessionID: authSession.ID,
				},
				db,
			},
			want: []string{},
		},
		{
			name: "Test too long username",
			in: testInput{
				PostLoginRequest{
					ClientID:      testClient.ID.String(),
					RedirectURI:   testClient.RedirectURIs[0],
					Username:      "verylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylong",
					Password:      "correcthorsebatterystaple",
					AuthSessionID: authSession.ID,
				},
				db,
			},
			want: []string{"username contains too many elements"},
		},
		{
			name: "Test too long password",
			in: testInput{
				PostLoginRequest{
					ClientID:      testClient.ID.String(),
					RedirectURI:   testClient.RedirectURIs[0],
					Username:      "bob",
					Password:      "verylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylongverylong",
					AuthSessionID: authSession.ID,
				},
				db,
			},
			want: []string{"password contains too many elements"},
		},
		{
			name: "Client does not exist in db",
			in: testInput{
				PostLoginRequest{
					ClientID:      "fb2981e2-ff2d-4e98-94ea-b7ce3e4a7760",
					RedirectURI:   "https://auth.axis.com/callback",
					Username:      "bob",
					Password:      "correcthorsebatterystaple",
					AuthSessionID: authSession.ID,
				},
				db,
			},
			want: []string{"client_id does not exist", "redirect_uri is not registered on the client", "auth_session_id is not valid, potentially timed out"},
		},
		{
			name: "Client has no such redirect URI",
			in: testInput{
				PostLoginRequest{
					ClientID:      testClient.ID.String(),
					RedirectURI:   "https://auth.example.com/callback",
					Username:      "bob",
					Password:      "correcthorsebatterystaple",
					AuthSessionID: authSession.ID,
				},
				db,
			},
			want: []string{"redirect_uri is not registered on the client"},
		},
		{
			name: "Too long redirect uri",
			in: testInput{
				PostLoginRequest{
					ClientID:      testClient.ID.String(),
					RedirectURI:   "https://example.com/auth/verylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurl",
					Username:      "bob",
					Password:      "correcthorsebatterystaple",
					AuthSessionID: authSession.ID,
				},
				db,
			},
			want: []string{"redirect_uri contains too many elements"},
		},
		{
			name: "Session ID does not exist",
			in: testInput{
				PostLoginRequest{
					ClientID:      testClient.ID.String(),
					RedirectURI:   "https://auth.axis.com/callback",
					Username:      "bob",
					Password:      "correcthorsebatterystaple",
					AuthSessionID: uuid.New().String(),
				},
				db,
			},
			want: []string{"auth_session_id is not valid, potentially timed out"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorBag := v.ValidatePostLoginRequest(&tt.in.loginRequest, tt.in.db)
			got := v.BagToSlice(errorBag)

			if !strSliceEqual(got, tt.want) {
				t.Errorf("\ngot:\n\t%q\nwant:\n\t%q", got, tt.want)
			}
		})
	}
}

func TestPostTokenRequest(t *testing.T) {
	type testCase struct {
		name string
		in   PostTokenRequest
		want []string
	}

	code := "8Tblqgqx90jhEoiNne2TDrYiquret05yJFaNjUZi"
	pkceCodeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	v := New()

	tests := []testCase{
		{
			name: "Test valid request (grant type is authorization code)",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "authorization_code",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
			},
			want: []string{},
		},
		{
			name: "Test valid request (grant type is refresh token)",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "refresh_token",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
				RefreshToken:     uuid.New().String(),
			},
			want: []string{},
		},
		{
			name: "Test missing refresh token",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "refresh_token",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
				RefreshToken:     "",
			},
			want: []string{"refresh_token must have a value"},
		},
		{
			name: "Test invalid (too long) refresh_token ",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "refresh_token",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
				RefreshToken:     "loremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsum",
			},
			want: []string{"refresh_token contains too many elements"},
		},
		{
			name: "Test invalid (missing) code ",
			in: PostTokenRequest{
				Code:             "",
				GrantType:        "authorization_code",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
			},
			want: []string{"code must have a value"},
		},
		{
			name: "Test invalid (too long) code ",
			in: PostTokenRequest{
				Code:             "loremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsum",
				GrantType:        "authorization_code",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
			},
			want: []string{"code contains too many elements"},
		},
		{
			name: "Test incorrect grant type",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "auth_code",
				PKCECodeVerifier: pkceCodeVerifier,
				RedirectURI:      "https://auth.axis.com/callback",
			},
			want: []string{"grant_type has an invalid value"},
		},
		{
			name: "Test incorrect (too long) pkce code verifier",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "authorization_code",
				PKCECodeVerifier: "loremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsumloremipsum",
				RedirectURI:      "https://auth.axis.com/callback",
			},
			want: []string{"code_verifier contains too many elements"},
		},
		{
			name: "Test missing redirect URI",
			in: PostTokenRequest{
				Code:             code,
				GrantType:        "authorization_code",
				PKCECodeVerifier: pkceCodeVerifier,
			},
			want: []string{"redirect_uri must have a value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorBag := v.ValidatePostTokenRequest(&tt.in)
			got := v.BagToSlice(errorBag)

			if !strSliceEqual(got, tt.want) {
				t.Errorf("\ngot:\n\t%q\nwant:\n\t%q", got, tt.want)
			}
		})
	}
}

func TestValidateGetLogin(t *testing.T) {
	type testInput struct {
		loginRequest         GetLoginRequest
		db                   *database.Database
		fieldsToGetErrorsFor []string
	}

	type testCase struct {
		name string
		in   testInput
		want []string
	}

	db := database.NewDatabase()

	testClient := models.Client{}
	testClient.ID = uuid.New()
	testClient.RedirectURIs = []string{"https://auth.axis.com/callback"}
	testClient.ResponseTypes = []string{"id_token"}

	pkceCodeChallenge := "BmuXBE7laREJ5SzfMZxymVSUjZ4uV18s7nAiLIzYze0"

	db.AddClient(&testClient)

	tests := []testCase{
		{
			name: "Include subset",
			in: testInput{
				GetLoginRequest{
					ClientID:      uuid.New().String(),
					RedirectURI:   testClient.RedirectURIs[0],
					Nonce:         "zxy_Ge99ucxjp",
					Scopes:        []string{"profile"},
					ResponseTypes: []string{"code"},
				},
				db,
				[]string{"client_id", "redirect_uri"},
			},
			want: []string{"client_id does not exist", "redirect_uri is not registered on the client"},
		},
		{
			name: "Non existing client",
			in: testInput{
				GetLoginRequest{
					ClientID:                uuid.New().String(),
					RedirectURI:             testClient.RedirectURIs[0],
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"code"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"client_id does not exist", "redirect_uri is not registered on the client"},
		},
		{
			name: "Invalid client ID",
			in: testInput{
				GetLoginRequest{
					ClientID:                "#aoeu",
					RedirectURI:             testClient.RedirectURIs[0],
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"code"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"client_id must be a valid uuid v4", "redirect_uri is not registered on the client"},
		},
		{
			name: "Redirect URI is not registered on client",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.example.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"code"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"redirect_uri is not registered on the client"},
		},
		{
			name: "Too long redirect URI",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://example.com/auth/verylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurlverylongurl",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"redirect_uri contains too many elements"},
		},
		{
			name: "Nonce is missing",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{},
		},
		{
			name: "Nonce is too short",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "aoeu",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"nonce does not contain enough elements"},
		},
		{
			name: "Nonce is too long",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "anoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenoncenonce",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"nonce contains too many elements"},
		},
		{
			name: "Scopes is missing",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{"client_id", "redirect_uri", "nonce", "scope", "response_type", "code_challenge", "code_challenge_method"},
			},
			want: []string{"scope does not contain enough elements"},
		},
		{
			name: "Scopes is invalid",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"user"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{},
			},
			want: []string{"scope[0] has an invalid value"},
		},
		{
			name: "Scopes is too long",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid", "ascopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescopescope"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{},
			},
			want: []string{"scope[1] contains too many elements"},
		},
		{
			name: "Invalid response type",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"code"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{},
			},
			want: []string{"response_type[0] is not registered on the client"},
		},
		{
			name: "Response type is too long",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token", "aemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemailemail"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{},
			},
			want: []string{"response_type[1] contains too many elements"},
		},
		{
			name: "PKCE Code challenge is too short",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       "abrakadabra",
					PKCECodeChallengeMethod: "S256",
				},
				db,
				[]string{},
			},
			want: []string{"code_challenge does not contain enough elements"},
		},
		{
			name: "PKCE Code challenge method is incorrect",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "plain",
				},
				db,
				[]string{},
			},
			want: []string{"code_challenge_method has an invalid value"},
		},
		{
			name: "State is too long",
			in: testInput{
				GetLoginRequest{
					ClientID:                testClient.ID.String(),
					RedirectURI:             "https://auth.axis.com/callback",
					Nonce:                   "zxy_Ge99ucxjp",
					Scopes:                  []string{"openid"},
					ResponseTypes:           []string{"id_token"},
					PKCECodeChallenge:       pkceCodeChallenge,
					PKCECodeChallengeMethod: "S256",
					State:                   "homehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehomehome",
				},
				db,
				[]string{},
			},
			want: []string{"state contains too many elements"},
		},
	}

	v := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorBag := v.ValidateGetLoginRequest(&tt.in.loginRequest, tt.in.db)
			if len(tt.in.fieldsToGetErrorsFor) != 0 {
				errorBag = errorBag.GetErrorsFor(tt.in.fieldsToGetErrorsFor...)
			}
			got := v.BagToSlice(errorBag)
			if !strSliceEqual(got, tt.want) {
				t.Errorf("\ngot:\n\t%q\nwant:\n\t%q", got, tt.want)
			}
		})
	}
}

func TestValidateVariable(t *testing.T) {
	type testInput struct {
		field string
		tag   string
	}

	tests := []struct {
		name string
		in   testInput
		want bool
	}{
		{
			name: "Test valid input",
			in: testInput{
				field: "bob@example.com",
				tag:   "email",
			},
			want: true,
		},
		{
			name: "Test invalid input",
			in: testInput{
				field: "boo",
				tag:   "required,min=5,max=50",
			},
			want: false,
		},
	}

	v := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errBag := v.ValidateVariable(tt.in.field, tt.in.tag)
			got := errBag.Empty()

			if got != tt.want {
				t.Errorf("\ngot:\n\t%t\nwant:\n\t%t", got, tt.want)
			}
		})
	}
}

// strSliceEqual compares two string slices.
func strSliceEqual(a, b []string) bool {
	sort.Slice(a, func(i, j int) bool {
		return a[i] < a[j]
	})

	sort.Slice(b, func(i, j int) bool {
		return b[i] < b[j]
	})

	return reflect.DeepEqual(a, b)
}
