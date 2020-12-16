package models

import (
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/random"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

// CodeExchangeSession is a short lived session that is created after a
// successful login attempt. Holds data needed for a successful token exchange.
type CodeExchangeSession struct {
	// ID is the authorization code used for token exchange
	ID string

	ClientID string

	// CreatedAt is used for cleaning up old exchange sessions
	CreatedAt time.Time

	// UserInfo contains username, groups and sids
	UserInfo *UserInfo

	// CodeChallenge is part of PKCE
	CodeChallenge string

	// Nonce is the original nonce received from the client
	Nonce string

	// RedirectURI is included in order to validate that the redirectURI used
	// for token exchange is same as used in the initial authentication request
	RedirectURI string
}

// NewCodeExchangeSession creates a new code exchange session.
// Returns authorization code unhashed as first parameter and code exchange
// session as the second.
func NewCodeExchangeSession(clientID, codeChallenge, nonce, redirectURI string, userInfo *UserInfo) (string, *CodeExchangeSession) {
	id := random.String(40)
	hash := util.HashSHA3(id)
	return id, &CodeExchangeSession{
		ID:            hash,
		ClientID:      clientID,
		CreatedAt:     time.Now(),
		UserInfo:      userInfo,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		RedirectURI:   redirectURI,
	}
}

// HasExpired returns true if the code exchange has expired.
func (c *CodeExchangeSession) HasExpired(expiryTime time.Duration) bool {
	return time.Since(c.CreatedAt) > expiryTime
}
