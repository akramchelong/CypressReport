package models

import "gitlab.se.axis.com/e2e/iam/onprem/oidc-win/auth"

// UserInfo contains user information fetched from the windows machine.
type UserInfo struct {
	Groups   []auth.Group
	UserSID  string
	Username string
}
