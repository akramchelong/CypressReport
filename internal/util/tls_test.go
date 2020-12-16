package util_test

import (
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

func TestGenerateSelfSignedCertificate(t *testing.T) {
	ipAddress := "127.0.0.1"
	// Assume certificate generation worked if no error was returned
	_, err := util.GenerateSelfSignedCertificate(ipAddress)
	if err != nil {
		t.Errorf("Expected certificate to yield no errors, got %s", err.Error())
	}
}
