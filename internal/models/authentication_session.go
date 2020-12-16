package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthenticationSession encapsulates a login attempt. Each
// AuthenticationSession belongs to a client and have a code challenge sent
// from the client.
type AuthenticationSession struct {
	CodeChallenge string
	ClientID      string
	ID            string
	Nonce         string
	State         string
	RedirectURI   string
	CreatedAt     time.Time
}

// NewAuthenticationSession will return a new session with the code challenge and client
// id provided. ID and created at will be set automatically.
func NewAuthenticationSession(codeChallenge, clientID, nonce, state, redirectURI string) *AuthenticationSession {
	return &AuthenticationSession{
		CodeChallenge: codeChallenge,
		ClientID:      clientID,
		Nonce:         nonce,
		State:         state,
		RedirectURI:   redirectURI,
		ID:            uuid.New().String(),
		CreatedAt:     time.Now(),
	}
}

// HasExpired returns true if the authentication session has expired.
func (a *AuthenticationSession) HasExpired(expiryTime time.Duration) bool {
	return time.Since(a.CreatedAt) > expiryTime
}
