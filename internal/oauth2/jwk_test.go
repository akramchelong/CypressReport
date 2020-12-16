package oauth2_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/oauth2"
)

func TestGetJwks(t *testing.T) {
	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := private.PublicKey

	jwks := oauth2.GetJwks([]*rsa.PrivateKey{private})
	jwk := jwks.Keys[0]

	if jwk.Kty != "RSA" {
		t.Errorf("Invalid key type %s, expected %s", jwk.Kty, "RSA")
	}

	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Errorf("Invalid N value, unable to decode due to %s", err.Error())
	}
	gotN := new(big.Int).SetBytes(nb)

	if gotN.Cmp(pub.N) != 0 {
		t.Errorf("Modulus (N) does not match, got %d, expected %d", gotN, pub.N)
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Errorf("Invalid E value, unable to decode due to %s", err.Error())
	}

	// JWK values are without padding, must add padding if missing
	padding := make([]byte, 8)
	copy(padding[len(padding)-len(eb):], eb)
	gotE := binary.BigEndian.Uint64(padding)

	if int(gotE) != pub.E {
		t.Errorf("Exponent (E) does not match, got %d, expected %d", gotE, pub.E)
	}
}
