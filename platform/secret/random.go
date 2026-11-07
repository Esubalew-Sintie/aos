// Package secret holds the engine's cryptography: random tokens, hashes,
// password hashing, encryption at rest and token signing. Nothing outside
// this package should call a crypto primitive directly.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// Token returns n random bytes as URL-safe text. Use 32 for anything a
// person or a program presents later: a session id, a reset link, a key.
func Token(n int) string {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error on supported platforms and
	// aborts the program if the system source fails, so there is nothing
	// to handle here.
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HexID returns n random bytes as hex. For public identifiers such as the
// visible part of a key.
func HexID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Hash is what the database stores in place of a random token. The tokens
// are long and random, so a plain SHA-256 is enough. It is not suitable
// for passwords: see HashPassword.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Equal compares two hashes without leaking, through timing, where they differ.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
