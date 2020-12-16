package random

import (
	"crypto/rand"
	"math/big"
	"strings"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
)

const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// String returns a cryptographically secure random string with a specified
// length.
func String(length int) string {
	var randomStr strings.Builder
	for i := 0; i < length; i++ {
		rnd, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			logger.Fatal("Could not retrieve random int")
		}
		randomStr.WriteString(string(letters[int(rnd.Int64())]))
	}

	return randomStr.String()
}
