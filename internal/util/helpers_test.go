package util

import (
	"strings"
	"testing"
)

func TestContains(t *testing.T) {
	type testInput struct {
		haystack []string
		needle   string
	}
	tests := []struct {
		name string
		in   testInput
		want bool
	}{
		{"Test empty haystack", testInput{[]string{}, "bob"}, false},
		{"Test needle exists in haystack", testInput{[]string{"bob", "bill", "mario", "riker"}, "bill"}, true},
		{"Test needle does not exists in haystack", testInput{[]string{"bob", "bill", "mario", "riker"}, "garfield"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Contains(tt.in.haystack, tt.in.needle)
			if got != tt.want {
				t.Errorf("\ngot:\n\t%t\nwant:\n\t%t", got, tt.want)
			}
		})
	}
}

func TestMapStringArray(t *testing.T) {
	shouty := []string{"HELLO 👋", "NICE TO MEET YOU", "SORRY - CAN'T DO THAT"}

	notShouty := MapStringArray(shouty, func(element string) string {
		return strings.ToLower(element)
	})

	for i, got := range notShouty {
		expected := strings.ToLower(shouty[i])
		if got != expected {
			t.Errorf("\ngot:\n\t%q\nwant:\n\t%q", got, expected)
		}
	}
}
