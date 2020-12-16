package models

import (
	"github.com/google/uuid"
)

// Client holds information about a registered client
type Client struct {
	ID                    uuid.UUID `json:"client_id"`
	RedirectURIs          []string  `json:"redirect_uris"`
	ResponseTypes         []string  `json:"response_types"`
	GrantTypes            []string  `json:"grant_types"`
	ApplicationType       string    `json:"application_type"`
	ClientName            string    `json:"client_name"`
	ClientDescription     string    `json:"client_description"`
	ClientSecret          string    `json:"client_secret"`
	ClientSecretExpiresAt int       `json:"client_secret_expires_at"`

	// Don't return the hashed client secret to the client
	HashedClientSecret []byte `json:"-"`
}
