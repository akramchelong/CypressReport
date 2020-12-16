// +build !windows

package auth_test

import (
	"testing"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"
)

func TestLogonUserCorrect(t *testing.T) {
	dummyHandler := auth.LoginHandler{}
	user := "sts"
	domain := "."
	pass := "Hejsan123"
	expected := "token123"
	token, err := dummyHandler.Verify(user, domain, pass)
	if err != nil {
		t.Errorf("LogonUser(%s,%s) = %s, wanted %s", user, pass, token, expected)
	}
}

func TestLogonUserIncorrect(t *testing.T) {
	dummyHandler := auth.LoginHandler{}
	user := "sts"
	domain := "."
	pass := "wrong"
	expected := ""
	token, err := dummyHandler.Verify(user, domain, pass)
	if err == nil {
		t.Errorf("LogonUser(%s,%s) = %s, wanted %s", user, pass, token, expected)
	}
}
