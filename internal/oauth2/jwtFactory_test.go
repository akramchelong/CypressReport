package oauth2_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/oauth2"
)

func TestNewAccessToken(t *testing.T) {
	pvt, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenFactory := oauth2.NewJwtFactory(pvt)
	got, err := tokenFactory.NewAccessToken("S-1-5-21 KLMNOPQR", "sts", "localhost", "aabbccddee", "n-0S6_WzA2Mj", []auth.Group{{NiceName: "Users", SID: "S-5-3-1"}})
	if err != nil {
		t.Error("Expected no error, got:", err)
	}
	if len(got) == 0 {
		t.Error("Expected a non empty string, got:", got)
	}
}

func TestNewIDToken(t *testing.T) {
	pvt, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenFactory := oauth2.NewJwtFactory(pvt)
	got, err := tokenFactory.NewIDToken("sts", "localhost", "aabbccddee", "n-0S6_WzA2Mj")
	if err != nil {
		t.Error("Expected no error, got:", err)
	}
	if len(got) == 0 {
		t.Error("Expected a non empty string, got:", got)
	}
}

func TestSignAndVerify(t *testing.T) {
	pvt, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenFactory := oauth2.NewJwtFactory(pvt)
	signed, _ := tokenFactory.NewIDToken("sts", "localhost", "aabbccddee", "n-0S6_WzA2Mj")
	_, err := oauth2.Verify(signed, &pvt.PublicKey)
	if err != nil {
		t.Error("Expected no error, got:", err.Error())
	}
}
