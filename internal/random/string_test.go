package random

import (
	"math"
	"testing"
)

// TestStringLength tests that if we ask for a specific length we should get
// that length.
func TestStringLength(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"Test 0 length", 0, 0},
		{"Test 10 length", 10, 10},
		{"Test 100 length", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.in)
			if len(got) != tt.want {
				t.Errorf("\ngot:\n\t%q\nwant:\n\t%q", got, tt.want)
			}
		})
	}
}

// TestRandomStringForLetters tests that each letter is included in the resulting string
func TestRandomStringForLetters(t *testing.T) {
	letterMap := make(map[string]bool)
	for _, letter := range letters {
		letterMap[string(letter)] = true
	}

	if len(letterMap) != len(letters) {
		t.Fatalf("Something is very wrong here")
	}

	maxTries := 1000

	for maxTries > 0 && len(letterMap) > 0 {
		maxTries--
		delete(letterMap, String(1))
	}

	if len(letterMap) != 0 {
		t.Errorf("Expected each character to be included, %d characters were never returned. \n\t%+v contains characters that never was returned", len(letterMap), letterMap)
	}
}

// TestRandomString tests that no strings is returned twice, which should be
// unlikely if the string length is sufficently long.
func TestRandomString(t *testing.T) {
	testRuns := 100000
	stringLength := 20

	randomStrings := make(map[string]bool)

	for i := 0; i < testRuns; i++ {
		randomString := String(stringLength)
		if _, exists := randomStrings[randomString]; exists {
			t.Fatalf("String %s occured twice. Should not occur more than once. ", randomString)
		}
		randomStrings[randomString] = true
	}
}

// TestStringDistribution is a frequency test that verifies that
// each character occures about the same amount of time. This is to test that
// the choice of characters are evenly distributed.
func TestStringDistribution(t *testing.T) {
	testRuns := 1000000
	stringLength := 50

	occurrences := make(map[rune]int)

	for i := 0; i < testRuns; i++ {
		secret := String(stringLength)
		for _, letter := range secret {
			occurrences[letter]++
		}
	}

	// expectedOccurance is how many times each character is expected to occur
	expectedOccurance := ((1.0 / float64(len(letters))) * float64(stringLength)) * float64(testRuns)

	// occuranceThreshold is the maximum deviation from expectedOccurance that is acceptable in percent written as decimal
	occuranceThreshold := 0.01

	for rune, n := range occurrences {
		if math.Abs(float64(n)-expectedOccurance) > (expectedOccurance * occuranceThreshold) {
			t.Errorf("Letter %s is an outlier (diff is %.2f, max is %.2f)", string(rune), math.Abs(float64(n)-expectedOccurance), expectedOccurance*occuranceThreshold)
		}
	}
}
