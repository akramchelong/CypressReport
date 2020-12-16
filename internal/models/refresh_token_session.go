package models

import (
	"sync"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/config"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/queue"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/random"
)

const CACHE_SIZE_EXPIRED_TOKENS = 10

// RefreshTokenSession is created once a client requests a token with valid
// codeChallenge and authorization code. RefreshTokenSession holds data related
// to id-, access- and refresh-token.
type RefreshTokenSession struct {
	ID            string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ClientID      string
	Nonce         string
	UserInfo      *UserInfo
	ExpiredTokens *queue.Bounded
	mutex         sync.Mutex
}

// NewRefreshTokenSession will return a new session with the client id provided. ID and
// created at will be set automatically.
// Returns refresh token unhashed as first parameter and refresh token session
// as the second.
func NewRefreshTokenSession(clientID, nonce string, userInfo *UserInfo) (string, *RefreshTokenSession) {
	id := random.String(40)
	hash := util.HashSHA3(id)
	return id, &RefreshTokenSession{
		ID:            hash,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(config.RefreshTokenMaxLifetime),
		ClientID:      clientID,
		Nonce:         nonce,
		UserInfo:      userInfo,
		ExpiredTokens: queue.NewBounded(CACHE_SIZE_EXPIRED_TOKENS),
	}
}

// Rotate mutates the current RefreshTokenSession by creating a new ID and
// storing the old one in a list of rotated IDs. The new unhashed refresh token
// is returned as the first parameter.
func (r *RefreshTokenSession) Rotate() (string, *RefreshTokenSession) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.ExpiredTokens.Add(r.ID)
	r.CreatedAt = time.Now()
	id := random.String(40)
	hash := util.HashSHA3(id)
	r.ID = hash

	return id, r
}

// HasExpired returns true if the refresh token has expired
func (r *RefreshTokenSession) HasExpired(expiryTime time.Duration) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return time.Since(r.CreatedAt) > expiryTime || time.Now().After(r.ExpiresAt)
}

// HasRotatedToken checks if this session contains a rotated token with the provided hash.
func (r *RefreshTokenSession) HasRotatedToken(hashedToken string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.ExpiredTokens.Contains(hashedToken)
}
