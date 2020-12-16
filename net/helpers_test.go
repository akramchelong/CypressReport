package net

import "testing"

func TestClientsAcceptJson(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want bool
	}{
		{"Test empty header", []string{}, false},
		{"Test single application/json header", []string{"application/json"}, true},
		{"Test single plain/text header", []string{"text/plain"}, false},
		{"Test multiple type in single header", []string{"text/html, application/json, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8"}, true},
		{"Test multiple type without spaces", []string{"text/html,application/json,application/xhtml+xml"}, true},
		{"Test multiple headers", []string{"text/html", "application/json"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientsAcceptsJson(tt.in)
			if got != tt.want {
				t.Errorf("\ngot:\n\t%t\nwant:\n\t%t", got, tt.want)
			}
		})
	}
}
