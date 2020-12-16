package util

// Contains check if string needle exist in array haystack.
func Contains(haystack []string, needle string) bool {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
}

// MapStringArray runs a function on each element in an array and returns the
// new array.
func MapStringArray(old []string, f func(string) string) []string {
	new := make([]string, len(old))
	for i, element := range old {
		new[i] = f(element)
	}

	return new
}
