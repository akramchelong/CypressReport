package oauth2

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"

	"github.com/form3tech-oss/jwt-go"
	"github.com/google/uuid"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
)

// JwtFactory helps to create JWT
type JwtFactory struct {
	signingKey *rsa.PrivateKey
}

// NewJwtFactory creates a new JwtFactory
func NewJwtFactory(signingKey *rsa.PrivateKey) JwtFactory {
	return JwtFactory{
		signingKey,
	}
}

// NewAccessToken creates a new access token
func (f JwtFactory) NewAccessToken(userSID, username, host, clientID, nonce string, groups []auth.Group) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	groupSids := []string{}
	groupNiceNames := []string{}
	for _, group := range groups {
		groupSids = append(groupSids, group.SID)
		groupNiceNames = append(groupNiceNames, group.NiceName)
	}

	t.Claims = &struct {
		UserSid        string `json:"userSID"`
		Username       string `json:"username"`
		Groups         string `json:"groups"`
		GroupsNiceName string `json:"groupsNiceName"`

		// Purpose defines what this JWT is for, either access_token or
		// id_token.
		Purpose string `json:"purpose"`

		jwt.StandardClaims
	}{
		userSID,
		username,
		strings.Join(groupSids, ","),
		strings.Join(groupNiceNames, ","),
		"access_token",
		getStandardClaims(host, username, clientID),
	}

	return f.sign(t)
}

// NewIDToken creates a new ID Token
func (f JwtFactory) NewIDToken(username, host, clientID, nonce string) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	t.Claims = &struct {
		Username string `json:"username"`
		Nonce    string `json:"nonce,omitempty"`

		// azp is the authorized party - the party to which the ID Token was
		// issued. Same as Audience.
		Azp string `json:"azp"`

		// Purpose defines what this JWT is for, either access_token or
		// id_token.
		Purpose string `json:"purpose"`

		jwt.StandardClaims
	}{
		username,
		nonce,
		clientID,
		"id_token",
		getStandardClaims(host, username, clientID),
	}

	return f.sign(t)
}

// Sign signs the provided JWT using the configured private key.
func (f JwtFactory) sign(token *jwt.Token) (string, error) {
	kid, err := util.GetKid(f.signingKey)
	if err != nil {
		logger.Debug("Could not fetch key ID")
		return "", err
	}

	token.Header["kid"] = kid
	tokenString, err := token.SignedString(f.signingKey)
	if err != nil {
		logger.Debug("Could not sign JWT token")
	}
	return tokenString, err
}

// Verify checks the signature on the signedToken and verifies it against the
// public key
func Verify(signedToken string, pub *rsa.PublicKey) (*jwt.Token, error) {
	valid, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
		return pub, nil
	})
	return valid, err
}

func getStandardClaims(host, username, clientID string) jwt.StandardClaims {
	return jwt.StandardClaims{
		// Issuer (iss) is the "Issuer Identifier for the Issuer of the
		// response. The iss value is a case sensitive URL using the https
		// scheme that contains scheme, host, and optionally, port number
		// and path components and no query or fragment components."
		Issuer: fmt.Sprintf("https://%s", host),

		// IssuedAt (iat) is the time at which the JWT was issued as
		// seconds since the Unix epoch.
		IssuedAt: time.Now().Unix(),

		// Subject (sub) is "A locally unique and never reassigned
		// identifier within the Issuer for the End-User, which is intended
		// to be consumed by the Client".
		Subject: username,

		// Audience (aud) "Audience(s) that this ID Token is intended for.
		// It MUST contain the OAuth 2.0 client_id of the Relying Party as
		// an audience value. It MAY also contain identifiers for other
		// audiences. In the general case, the aud value is an array of
		// case sensitive strings. In the common special case when there is
		// one audience, the aud value MAY be a single case sensitive
		// string."
		Audience: []string{clientID},

		// ExpiresAt (exp) is the "Expiration time on or after which the ID
		// Token MUST NOT be accepted for processing. The processing of
		// this parameter requires that the current date/time MUST be
		// before the expiration date/time listed in the value.
		// Implementers MAY provide for some small leeway, usually no more
		// than a few minutes, to account for clock skew. Its value is a
		// JSON number representing the number of seconds from
		// 1970-01-01T0:0:0Z as measured in UTC until the date/time."
		ExpiresAt: time.Now().Add(config.AccessTokenExpiry).Unix(),

		// NotBefore (nbf) is the time before the JWT MUST NOT be accepted
		// for processing. This claim is optional.
		NotBefore: time.Now().Unix(),

		// Id (jti) is a JWT ID, an unique identifier for the JWT. This
		// claim is optional.
		Id: uuid.New().String(),
	}
}
