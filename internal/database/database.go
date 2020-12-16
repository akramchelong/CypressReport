package database

import (
	"sync"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/models"
)

// Database is a in-memory (using a map) store
type Database struct {
	clients    map[string]*models.Client
	clientsMux sync.RWMutex

	refreshTokens    map[string]*models.RefreshTokenSession
	refreshTokensMux sync.Mutex

	authSessions    map[string]*models.AuthenticationSession
	authSessionsMux sync.Mutex

	codeExchangeSessions    map[string]*models.CodeExchangeSession
	codeExchangeSessionsMux sync.Mutex
}

// NewDatabase is a constructor function to create a new database
func NewDatabase() *Database {
	clients := make(map[string]*models.Client)
	refreshTokens := make(map[string]*models.RefreshTokenSession)
	authSessions := make(map[string]*models.AuthenticationSession)
	codeExchangeSessions := make(map[string]*models.CodeExchangeSession)

	return &Database{
		clients:              clients,
		refreshTokens:        refreshTokens,
		authSessions:         authSessions,
		codeExchangeSessions: codeExchangeSessions,
	}
}

// AddClient adds a new client to the database
func (db *Database) AddClient(client *models.Client) {
	db.clientsMux.Lock()
	defer db.clientsMux.Unlock()

	db.clients[client.ID.String()] = client
}

// AddRefreshTokenSession adds a new session to the database
func (db *Database) AddRefreshTokenSession(session *models.RefreshTokenSession) {
	db.refreshTokensMux.Lock()
	defer db.refreshTokensMux.Unlock()

	db.refreshTokens[session.ID] = session
}

// FindClient retrieves a client from the database given a client id. If the
// client doesn't exist, nil is returned.
func (db *Database) FindClient(id string) *models.Client {
	db.clientsMux.RLock()
	defer db.clientsMux.RUnlock()

	return db.clients[id]
}

// ClientExists returns true if the client id exists in the database.
func (db *Database) ClientExists(id string) bool {
	client := db.FindClient(id)

	return client != nil
}

// DeleteClient will remove the client from the database. If the client does
// not exist, then this is a no-op.
func (db *Database) DeleteClient(id string) {
	db.clientsMux.Lock()
	defer db.clientsMux.Unlock()

	delete(db.clients, id)
}

// TakeOutRefreshTokenSession retrieves and deletes a refresh token session if it
// exists. If the session does not exist, then nil is returned.
func (db *Database) TakeOutRefreshTokenSession(sessionID string) *models.RefreshTokenSession {
	db.refreshTokensMux.Lock()
	defer db.refreshTokensMux.Unlock()

	defer delete(db.refreshTokens, sessionID)
	return db.refreshTokens[sessionID]
}

// FindRotatedRefreshTokenSession return the session that previously had the
// provided sessionID if it exists
func (db *Database) FindRotatedRefreshTokenSession(sessionID string) *models.RefreshTokenSession {
	db.refreshTokensMux.Lock()
	defer db.refreshTokensMux.Unlock()

	for _, session := range db.refreshTokens {
		if session.HasRotatedToken(sessionID) {
			return session
		}
	}

	return nil
}

// DeleteRefreshTokenSession removes the session from the database. If the session does not
// exist, then this is a no-op.
func (db *Database) DeleteRefreshTokenSession(sessionID string) {
	db.refreshTokensMux.Lock()
	defer db.refreshTokensMux.Unlock()

	delete(db.refreshTokens, sessionID)
}

// AddAuthenticationSession adds a login attempt to the database
func (db *Database) AddAuthenticationSession(authSession *models.AuthenticationSession) {
	db.authSessionsMux.Lock()
	defer db.authSessionsMux.Unlock()

	db.authSessions[authSession.ID] = authSession
}

// FindAuthenticationSession returns a login attempt based on id. If no such login
// attempt exists, nil is returned.
func (db *Database) FindAuthenticationSession(id string) *models.AuthenticationSession {
	db.authSessionsMux.Lock()
	defer db.authSessionsMux.Unlock()

	return db.authSessions[id]
}

// DeleteAuthenticationSession removes login attempt from the database. If the login
// attempt does not exist, then this is a no-op.
func (db *Database) DeleteAuthenticationSession(id string) {
	db.authSessionsMux.Lock()
	defer db.authSessionsMux.Unlock()

	delete(db.authSessions, id)
}

// AuthenticationSessionExist return true if the authentication session exist
func (db *Database) AuthenticationSessionExist(id string) bool {
	return db.FindAuthenticationSession(id) != nil
}

// GetOldAuthenticationSessions returns auth sessions that are older than the
// provider duration.
func (db *Database) GetOldAuthenticationSessions(authSessionLifetime time.Duration) []*models.AuthenticationSession {
	oldAuthenticationSessions := []*models.AuthenticationSession{}

	db.authSessionsMux.Lock()
	defer db.authSessionsMux.Unlock()

	for _, authSession := range db.authSessions {
		if authSession.HasExpired(authSessionLifetime) {
			oldAuthenticationSessions = append(oldAuthenticationSessions, authSession)
		}
	}

	return oldAuthenticationSessions
}

// AddCodeExchangeSession stores a code exchange session in the database
func (db *Database) AddCodeExchangeSession(codeExchangeSession *models.CodeExchangeSession) {
	db.codeExchangeSessionsMux.Lock()
	defer db.codeExchangeSessionsMux.Unlock()

	db.codeExchangeSessions[codeExchangeSession.ID] = codeExchangeSession
}

// DeleteCodeExchangeSession removes a code exchange session from the database.
// If the session does not exist, then this is a no-op.
func (db *Database) DeleteCodeExchangeSession(id string) {
	db.codeExchangeSessionsMux.Lock()
	defer db.codeExchangeSessionsMux.Unlock()

	delete(db.codeExchangeSessions, id)
}

// TakeOutCodeExchangeSession retrieves and remove the code exchange session if it
// exist. If the session does not exist, then nil is returned.
func (db *Database) TakeOutCodeExchangeSession(id string) *models.CodeExchangeSession {
	db.codeExchangeSessionsMux.Lock()
	defer db.codeExchangeSessionsMux.Unlock()

	defer delete(db.codeExchangeSessions, id)
	return db.codeExchangeSessions[id]
}

// GetOldCodeExchangeSession returns token exchange sessions that are older
// than the provided duration
func (db *Database) GetOldCodeExchangeSession(codeExchangeLifetime time.Duration) []*models.CodeExchangeSession {
	oldCodeExchangeSessions := []*models.CodeExchangeSession{}

	db.codeExchangeSessionsMux.Lock()
	defer db.codeExchangeSessionsMux.Unlock()

	for _, codeExchangeSession := range db.codeExchangeSessions {
		if codeExchangeSession.HasExpired(codeExchangeLifetime) {
			oldCodeExchangeSessions = append(oldCodeExchangeSessions, codeExchangeSession)
		}
	}

	return oldCodeExchangeSessions
}

// DeleteRefreshTokensForClient will remove all refresh tokens for the
// specified client id. Note that this is a O(n) operation.
func (db *Database) DeleteRefreshTokensForClient(clientID string) {
	db.refreshTokensMux.Lock()
	defer db.refreshTokensMux.Unlock()

	for refreshTokenId, token := range db.refreshTokens {
		if token.ClientID == clientID {
			delete(db.refreshTokens, refreshTokenId)
		}
	}
}
