package database

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/models"
)

func TestAddClient(t *testing.T) {
	db := NewDatabase()
	client := models.Client{
		ID:           uuid.New(),
		RedirectURIs: []string{"http://example.com"},
	}
	db.AddClient(&client)
	foundClient := db.FindClient(client.ID.String())
	if client.ID != foundClient.ID {
		t.Error("Got wrong client")
	}
}

func TestAddRefreshTokenSession(t *testing.T) {
	db := NewDatabase()

	_, session := models.NewRefreshTokenSession("aoeu", "nonce", &models.UserInfo{})

	db.AddRefreshTokenSession(session)
	got := db.TakeOutRefreshTokenSession(session.ID)
	if got == nil {
		t.Errorf("Expected refresh token, got none")
	}
}

func TestDeleteRefreshTokenSession(t *testing.T) {
	db := NewDatabase()

	_, session := models.NewRefreshTokenSession("aoeu", "nonce", &models.UserInfo{})
	db.AddRefreshTokenSession(session)
	db.DeleteRefreshTokenSession(session.ID)

	got := db.TakeOutRefreshTokenSession(session.ID)
	if got != nil {
		t.Errorf("Expected no refresh token, got %q", got.ID)
	}
}

func TestDeleteRefreshTokensForClient(t *testing.T) {
	db := NewDatabase()
	clientA := models.Client{ID: uuid.New()}
	clientB := models.Client{ID: uuid.New()}

	// add 5 refresh tokens for each client
	for i := 0; i < 5; i++ {
		_, s1 := models.NewRefreshTokenSession(clientA.ID.String(), "nonce", &models.UserInfo{})
		db.AddRefreshTokenSession(s1)
		_, s2 := models.NewRefreshTokenSession(clientB.ID.String(), "nonce", &models.UserInfo{})
		db.AddRefreshTokenSession(s2)
	}

	if len(db.refreshTokens) != 10 {
		t.Error("Expected database to contain 10 refresh tokens")
	}

	db.DeleteRefreshTokensForClient(clientA.ID.String())

	if len(db.refreshTokens) != 5 {
		t.Error("Expected 5 refresh tokens to remain in database")
	}

	db.DeleteRefreshTokensForClient(clientB.ID.String())

	if len(db.refreshTokens) != 0 {
		t.Error("Expected 0 refresh tokens to remain in database")
	}
}

func TestClientExist(t *testing.T) {
	db := NewDatabase()
	client := models.Client{
		ID:           uuid.New(),
		RedirectURIs: []string{"http://example.com"},
	}
	db.AddClient(&client)
	got := db.ClientExists(client.ID.String())
	want := true
	if got != want {
		t.Errorf("got: %t, want: %t", got, want)
	}
}

func TestDeleteClient(t *testing.T) {
	db := NewDatabase()
	client := models.Client{ID: uuid.New()}

	db.AddClient(&client)
	if len(db.clients) != 1 {
		t.Error("Expected client to be added.")
	}

	db.DeleteClient(client.ID.String())

	if len(db.clients) != 0 {
		t.Errorf("Expected client to be deleted")
	}
}

// Test database for race conditions
func TestMultipleClientReadWrites(t *testing.T) {
	db := NewDatabase()
	wg := &sync.WaitGroup{}

	for i := 0; i < 15; i++ {
		wg.Add(4)

		go func(wg *sync.WaitGroup, db *Database) {
			client := models.Client{
				ID:           uuid.New(),
				RedirectURIs: []string{"http://example.com"},
			}
			db.AddClient(&client)
			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.ClientExists(uuid.New().String())
			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.FindClient(uuid.New().String())
			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.DeleteClient(uuid.New().String())
			wg.Done()
		}(wg, db)
	}
	wg.Wait()
}

// Test database for race conditions
func TestMultipleRefreshTokenSessionReadWrites(t *testing.T) {
	db := NewDatabase()
	wg := &sync.WaitGroup{}

	for i := 0; i < 15; i++ {
		wg.Add(3)

		go func(wg *sync.WaitGroup, db *Database) {
			_, session := models.NewRefreshTokenSession("aoeu", "nonce", &models.UserInfo{})
			db.AddRefreshTokenSession(session)

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			sessionID := uuid.New().String()
			db.DeleteRefreshTokenSession(sessionID)

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			clientID := uuid.New().String()
			db.DeleteRefreshTokensForClient(clientID)

			wg.Done()
		}(wg, db)
	}
	wg.Wait()
}

func TestAuthenticationSession(t *testing.T) {
	db := NewDatabase()
	clientID := uuid.New().String()

	authSession := models.NewAuthenticationSession("does-not-matter", clientID, "abcdefghijk", "home", "http://auth.axis.com/callback")

	db.AddAuthenticationSession(authSession)

	got := db.FindAuthenticationSession(authSession.ID)
	if got.ClientID != clientID {
		t.Errorf("Got %q, expected %q", got.ClientID, clientID)
	}

	if !db.AuthenticationSessionExist(authSession.ID) {
		t.Errorf("Expected auth sesson %q to exist", authSession.ID)
	}

	db.DeleteAuthenticationSession(authSession.ID)
	got = db.FindAuthenticationSession(authSession.ID)

	if got != nil {
		t.Error("Expected auth session to be removed")
	}
}

func TestGetOldAuthenticationSession(t *testing.T) {
	db := NewDatabase()

	nbrOfAuthSessions := 10

	for i := 0; i < nbrOfAuthSessions; i++ {
		db.AddAuthenticationSession(models.NewAuthenticationSession("does-not-matter", "does-not-matter", "abcdef", "home", "http://auth.axis.com/callback"))
	}

	oldAuthSessions := db.GetOldAuthenticationSessions(-1 * time.Minute)

	if len(oldAuthSessions) != nbrOfAuthSessions {
		t.Errorf("Expected %d nbr of old auth sessions. Got %d", nbrOfAuthSessions, len(oldAuthSessions))
	}
}

// Test database for race conditions
func TestMultipleAuthSessionReadWrites(t *testing.T) {
	db := NewDatabase()
	wg := &sync.WaitGroup{}

	for i := 0; i < 15; i++ {
		wg.Add(5)

		go func(wg *sync.WaitGroup, db *Database) {
			authSession := models.NewAuthenticationSession("does-not-matter", "does-not-matter", "abcdef", "home", "http://auth.axis.com/callback")
			db.AddAuthenticationSession(authSession)

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.FindAuthenticationSession(uuid.New().String())

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.AuthenticationSessionExist(uuid.New().String())

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.DeleteAuthenticationSession(uuid.New().String())

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.GetOldAuthenticationSessions(-1 * time.Minute)

			wg.Done()
		}(wg, db)
	}

	wg.Wait()
}

func TestCodeExchange(t *testing.T) {
	db := NewDatabase()

	_, codeExchangeSession := models.NewCodeExchangeSession("", "", "", "http://auth.axis.com/callback", &models.UserInfo{})

	db.AddCodeExchangeSession(codeExchangeSession)

	if len(db.codeExchangeSessions) != 1 {
		t.Error("Expected one code exchange to be added to the database.")
	}

	got := db.TakeOutCodeExchangeSession(codeExchangeSession.ID)
	if got == nil {
		t.Error("Expected to get a code exchange session")
	}

	db.DeleteCodeExchangeSession(codeExchangeSession.ID)
	if len(db.codeExchangeSessions) != 0 {
		t.Error("Expected code exchange to be deleted from the database.")
	}
}

func TestGetOldCodeExchangeSession(t *testing.T) {
	db := NewDatabase()

	nbrOfCodeExchangeSessions := 10

	for i := 0; i < nbrOfCodeExchangeSessions; i++ {
		_, ce := models.NewCodeExchangeSession("", "", "", "http://auth.axis.com/callback", &models.UserInfo{})
		db.AddCodeExchangeSession(ce)
	}

	oldCodeExchangeSessions := db.GetOldCodeExchangeSession(-1 * time.Minute)

	if len(oldCodeExchangeSessions) != nbrOfCodeExchangeSessions {
		t.Errorf("Expected %d nbr of old auth sessions. Got %d", nbrOfCodeExchangeSessions, len(oldCodeExchangeSessions))
	}
}

// Test database for race conditions
func TestMultipleCodeExchangeSessionReadWrite(t *testing.T) {
	db := NewDatabase()
	wg := &sync.WaitGroup{}

	for i := 0; i < 15; i++ {
		wg.Add(4)

		go func(wg *sync.WaitGroup, db *Database) {
			_, codeExchangeSession := models.NewCodeExchangeSession("", "", "", "http://auth.axis.com/callback", &models.UserInfo{})
			db.AddCodeExchangeSession(codeExchangeSession)

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.TakeOutCodeExchangeSession(uuid.New().String())

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.DeleteCodeExchangeSession(uuid.New().String())

			wg.Done()
		}(wg, db)

		go func(wg *sync.WaitGroup, db *Database) {
			db.GetOldCodeExchangeSession(-1 * time.Minute)

			wg.Done()
		}(wg, db)
	}

	wg.Wait()
}
