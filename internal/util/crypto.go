package util

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

// HashSHA3 creates a SHA3-256 hash of str.
func HashSHA3(str string) string {
	hash := sha3.New256()
	_, _ = hash.Write([]byte(str))
	return fmt.Sprintf("%x", hash.Sum(nil))
}
