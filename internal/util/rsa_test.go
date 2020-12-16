package util_test

import (
	"io/ioutil"
	"os"
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

func TestGetPrivateKeysNotExist(t *testing.T) {
	dir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(dir)

	priv, err := util.GetPrivateKeys(dir)
	if err != nil {
		t.Errorf("Expected GetPrivateKeys to return no error, got: %s", err)
	}
	if priv == nil {
		t.Errorf("Expected private key to not be nil")
	}
	if err := priv[0].Validate(); err != nil {
		t.Errorf("Expected private key to be valid, got: %s", err)
	}
}

func TestGetPrivateKeysExist(t *testing.T) {
	dir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(dir)

	priv1, _ := util.GetPrivateKeys(dir)   // Generates new keypar
	priv2, err := util.GetPrivateKeys(dir) // Reads same keypair from file
	if err != nil {
		t.Errorf("Expected GetPrivateKeys to return no error, got: %s", err)
	}
	if priv1[0].D.Cmp(priv2[0].D) != 0 {
		t.Errorf("Expected private keys to match")
	}
}
