package models_test

import (
	"sync"
	"testing"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/models"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

const (
	clientid = "clientid"
	nonce    = "nonce"
)

func getUserInfo() *models.UserInfo {
	groups := []auth.Group{
		{
			NiceName: "users",
			SID:      "aabbccddeeff",
		},
		{
			NiceName: "administrators",
			SID:      "1122334455",
		},
	}
	return &models.UserInfo{
		groups,
		"S-1-5-21",
		"sts",
	}
}

func TestNewRefreshTokenSession(t *testing.T) {
	ui := getUserInfo()
	_, rt := models.NewRefreshTokenSession(clientid, nonce, ui)
	if rt.ClientID != clientid {
		t.Errorf("Expected ClientID to be: %q, got: %q", clientid, rt.ClientID)
	}
}

func TestRotate(t *testing.T) {
	ui := getUserInfo()
	id, rt := models.NewRefreshTokenSession(clientid, nonce, ui)
	oldID := util.HashSHA3(id)
	newId, rt := rt.Rotate()

	if !rt.ExpiredTokens.Contains(oldID) {
		t.Errorf("Expected %q to be expired", oldID)
	}

	if newId == oldID {
		t.Error("Expected to get a new token when rotating")
	}
}

func TestHasExpired(t *testing.T) {
	ui := getUserInfo()
	_, rt := models.NewRefreshTokenSession(clientid, nonce, ui)
	if rt.HasExpired(12 * time.Hour) {
		t.Errorf("Expected HasExpired to return false")
	}
	rt.CreatedAt = time.Now().Add(-13 * time.Hour)
	if !rt.HasExpired(12 * time.Hour) {
		t.Errorf("Expected HasExpired to return true")
	}
	rt.Rotate()
	if rt.HasExpired(12 * time.Hour) {
		t.Errorf("Expected HasExpired to return false")
	}
	rt.ExpiresAt = time.Now().Add(-1 * time.Second)
	if !rt.HasExpired(12 * time.Hour) {
		t.Errorf("Expected HasExpired to return true")
	}
}

func TestHasRotatedToken(t *testing.T) {
	ui := getUserInfo()
	id, rt := models.NewRefreshTokenSession(clientid, nonce, ui)
	hash := util.HashSHA3(id)
	if rt.HasRotatedToken(hash) {
		t.Errorf("Expected HasRotatedToken to return false")
	}
	rt.Rotate()
	if !rt.HasRotatedToken(hash) {
		t.Errorf("Expected HasRotatedToken to return true")
	}
}

func TestRotationRace(t *testing.T) {
	ui := getUserInfo()
	_, rt := models.NewRefreshTokenSession(clientid, nonce, ui)
	wg := &sync.WaitGroup{}
	wg.Add(100)
	for i := 0; i < 10; i++ {
		go func(wg *sync.WaitGroup, rt *models.RefreshTokenSession) {
			for i := 0; i < 10; i++ {
				rt.Rotate()
				rt.HasExpired(12 * time.Hour)
				rt.HasRotatedToken("FakeID")
				wg.Done()
			}
		}(wg, rt)
	}

	wg.Wait()
}
