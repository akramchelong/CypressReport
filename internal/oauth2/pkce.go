package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
)

// determineCodeChallenge returns a code challenge based on a code verifier.
// The code verifier is derived according to rfc7636#section-4.6, which is
// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
func determineCodeChallenge(codeVerifier string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
