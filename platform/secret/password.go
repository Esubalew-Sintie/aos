package secret

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordParams are the Argon2id cost settings.
type PasswordParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultPasswordParams follows the OWASP minimum for Argon2id:
// 19 MiB of memory, 2 passes, 1 thread.
var DefaultPasswordParams = PasswordParams{MemoryKiB: 19456, Time: 2, Threads: 1}

const (
	passwordSaltLen = 16
	passwordKeyLen  = 32
	// Upper bounds on the cost read back from a stored hash, so a bad
	// row cannot make one sign-in consume the whole machine.
	maxPasswordMemoryKiB = 1 << 20 // 1 GiB
	maxPasswordTime      = 16
)

var b64 = base64.RawStdEncoding

// HashPassword returns a self-describing string that holds the algorithm,
// its cost, the salt and the hash:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func HashPassword(password string, p PasswordParams) (string, error) {
	salt := make([]byte, passwordSaltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, passwordKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a stored hash. It also returns
// the cost the hash was made with, so the caller can replace a hash made
// with weaker settings after a successful sign-in.
func VerifyPassword(password, encoded string) (bool, PasswordParams, error) {
	var p PasswordParams
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		// An imported hash. The zero params make the caller replace it
		// with Argon2id after a successful sign-in.
		ok, err := verifyImported(password, encoded)
		return ok, p, err
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, p, errors.New("secret: unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, p, errors.New("secret: bad argon2 parameters")
	}
	if p.MemoryKiB == 0 || p.MemoryKiB > maxPasswordMemoryKiB || p.Time == 0 || p.Time > maxPasswordTime || p.Threads == 0 {
		return false, p, errors.New("secret: argon2 parameters out of range")
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, p, errors.New("secret: bad argon2 salt")
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, p, errors.New("secret: bad argon2 hash")
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return Equal(got, want), p, nil
}

// Weaker reports whether a hash made with p should be replaced by one
// made with target.
func (p PasswordParams) Weaker(target PasswordParams) bool {
	return p.MemoryKiB < target.MemoryKiB || p.Time < target.Time
}
