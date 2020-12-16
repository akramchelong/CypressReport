package oauth2

import "testing"

func TestDetermineCodeChallenge(t *testing.T) {
	// Values taken from example in PKCE RFC (https://tools.ietf.org/html/rfc7636#appendix-B)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	got := determineCodeChallenge(codeVerifier)
	if got != want {
		t.Errorf("\nExpected \n\t%q\ngot \n\t%q", want, got)
	}
}
