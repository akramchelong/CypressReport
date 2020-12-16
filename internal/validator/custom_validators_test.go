package validator

import "testing"

func TestRedirectURIValid(t *testing.T) {
	validateTests := []struct {
		name string
		in   string
		want bool
	}{
		{"Remote web site protected by TLS", "https://example.com/oauth_redirect", true},
		{"Remote web site not protected by TLS", "http://example.com/oauth_redirect", false},
		{"Website hosted on local machine", "http://localhost:9090/oauth_redirect", true},
		{"Website hosted on local machine", "http://127.0.0.1:9090/oauth_redirect", true},
		{"Remote website with sub-domain matching local machine not protected by TLS", "http://localhost.evil.website.com/callback", false},
		{"Non-HTTP application-specific URL available only to the client application", "exampleapp://oauth_redirect", false},
		{"Invalid URI", "example.com/oauth_redirect", false},
	}

	for _, tt := range validateTests {
		t.Run(tt.name, func(t *testing.T) {
			got := redirectURIValid(tt.in)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
