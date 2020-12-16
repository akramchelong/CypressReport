package util_test

import (
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/util"
)

func TestHashSHA3(t *testing.T) {
	input := "hejsan"
	expected := "870c834ac32d003b9507ecce008ff07b6b6c65af68648c34d1e5d19655bf0b1c"

	actual := util.HashSHA3(input)
	if actual != expected {
		t.Errorf("Expected hash to be %q, actual %q", expected, actual)
	}
}
