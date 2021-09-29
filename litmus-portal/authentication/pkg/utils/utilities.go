package utils

import (
	"crypto/rand"
	"fmt"
)

// GenerateRandomString helps generate random string of n length
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := fmt.Sprintf("%X", b)
	return s, nil
}
