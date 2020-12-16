package oauth2

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

type jwk struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	// use string
	// x5c []string
	// x5t string
}

// Jwks contains the available jwk, formatted according to OpenID specification
type Jwks struct {
	Keys []jwk `json:"keys"`
}

// GetJwks extract a JWK from a public key
func GetJwks(signingKeys []*rsa.PrivateKey) Jwks {
	var keySpecs []jwk
	for _, key := range signingKeys {
		pub := &key.PublicKey
		modulus := base64.URLEncoding.EncodeToString(pub.N.Bytes())
		exponent := base64.URLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		kid, err := util.GetKid(key)
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		keySpec := jwk{
			Alg: "RS256",
			Kty: "RSA",
			Kid: kid,
			N:   strings.TrimRight(modulus, "="),
			E:   strings.TrimRight(exponent, "="),
		}
		keySpecs = append(keySpecs, keySpec)
	}
	keys := Jwks{
		Keys: keySpecs,
	}

	return keys
}
