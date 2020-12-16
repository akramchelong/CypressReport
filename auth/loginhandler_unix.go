// +build !windows

package auth

import (
	"errors"
)

// Group contains nice name and sid for user group
type Group struct {
	NiceName string
	SID      string
}

// LoginHandler provide functionality for logging in
// As this application is intended for windows usage, this is a dummy implementation
type LoginHandler struct{}

// Verify check credentials provided against dummy values
func (LoginHandler) Verify(user, domain, password string) (string, error) {
	if user == "sts" && password == "Hejsan123" {
		return "S-1-5-21 KLMNOPQR", nil
	}
	return "", errors.New("Invalid username or password")
}

func (LoginHandler) GetUserGroups(username string) ([]Group, error) {
	return []Group{
		{
			NiceName: "Users",
			SID:      "aabbccddeeff",
		},
	}, nil
}
