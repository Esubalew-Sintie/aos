package secret

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Imported password hashes (user-flow SET-4 step 6, HOST-6). Accounts
// moved from another system keep their passwords: the old hash is checked
// at sign-in and replaced by Argon2id on success. Accepted forms:
//
//	bcrypt          $2a$10$...  $2b$...  $2y$...
//	scrypt (PHC)    $scrypt$ln=15,r=8,p=1$<salt>$<hash>
//	PBKDF2 (passlib) $pbkdf2-sha256$<iterations>$<salt>$<hash>   (also sha1, sha512)
//	PBKDF2 (Django)  pbkdf2_sha256$<iterations>$<salt>$<hash>

// IsImportedHash reports whether a stored hash is one of the imported
// forms, well formed enough to be checked.
func IsImportedHash(encoded string) bool {
	_, err := verifyImported("probe", encoded)
	return err == nil
}

// IsSupportedHash reports whether a hash can be stored as a password.
func IsSupportedHash(encoded string) bool {
	if strings.HasPrefix(encoded, "$argon2id$") {
		_, _, err := VerifyPassword("probe", encoded)
		return err == nil
	}
	return IsImportedHash(encoded)
}

// maxImportedCost bounds the work one stored hash may ask for.
const (
	maxBcryptCost       = 15
	maxScryptLogN       = 20
	maxPBKDF2Iterations = 2_000_000
)

func verifyImported(password, encoded string) (bool, error) {
	switch {
	case strings.HasPrefix(encoded, "$2a$"), strings.HasPrefix(encoded, "$2b$"), strings.HasPrefix(encoded, "$2y$"):
		normalized := encoded
		if strings.HasPrefix(encoded, "$2y$") {
			normalized = "$2a$" + encoded[4:]
		}
		cost, err := bcrypt.Cost([]byte(normalized))
		if err != nil {
			return false, errors.New("secret: bad bcrypt hash")
		}
		if cost > maxBcryptCost {
			return false, errors.New("secret: bcrypt cost out of range")
		}
		err = bcrypt.CompareHashAndPassword([]byte(normalized), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return err == nil, err
	case strings.HasPrefix(encoded, "$scrypt$"):
		parts := strings.Split(encoded, "$")
		if len(parts) != 5 {
			return false, errors.New("secret: bad scrypt hash")
		}
		var ln, r, p int
		if _, err := fmt.Sscanf(parts[2], "ln=%d,r=%d,p=%d", &ln, &r, &p); err != nil || ln < 1 || ln > maxScryptLogN || r < 1 || r > 32 || p < 1 || p > 16 {
			return false, errors.New("secret: bad scrypt parameters")
		}
		salt, err1 := decodeAny(parts[3])
		want, err2 := decodeAny(parts[4])
		if err1 != nil || err2 != nil || len(want) == 0 {
			return false, errors.New("secret: bad scrypt encoding")
		}
		got, err := scrypt.Key([]byte(password), salt, 1<<ln, r, p, len(want))
		if err != nil {
			return false, err
		}
		return Equal(got, want), nil
	case strings.HasPrefix(encoded, "$pbkdf2"):
		parts := strings.Split(encoded, "$")
		if len(parts) != 5 {
			return false, errors.New("secret: bad pbkdf2 hash")
		}
		h, ok := pbkdf2Hash(strings.TrimPrefix(parts[1], "pbkdf2-"), parts[1] == "pbkdf2")
		if !ok {
			return false, errors.New("secret: unsupported pbkdf2 digest")
		}
		iterations, err := strconv.Atoi(parts[2])
		if err != nil || iterations < 1 || iterations > maxPBKDF2Iterations {
			return false, errors.New("secret: bad pbkdf2 iterations")
		}
		salt, err1 := decodeAB64(parts[3])
		want, err2 := decodeAB64(parts[4])
		if err1 != nil || err2 != nil || len(want) == 0 {
			return false, errors.New("secret: bad pbkdf2 encoding")
		}
		return Equal(pbkdf2.Key([]byte(password), salt, iterations, len(want), h), want), nil
	case strings.HasPrefix(encoded, "pbkdf2_"):
		parts := strings.Split(encoded, "$")
		if len(parts) != 4 {
			return false, errors.New("secret: bad django pbkdf2 hash")
		}
		h, ok := pbkdf2Hash(strings.TrimPrefix(parts[0], "pbkdf2_"), false)
		if !ok {
			return false, errors.New("secret: unsupported pbkdf2 digest")
		}
		iterations, err := strconv.Atoi(parts[1])
		if err != nil || iterations < 1 || iterations > maxPBKDF2Iterations {
			return false, errors.New("secret: bad pbkdf2 iterations")
		}
		want, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil || len(want) == 0 {
			return false, errors.New("secret: bad pbkdf2 encoding")
		}
		return Equal(pbkdf2.Key([]byte(password), []byte(parts[2]), iterations, len(want), h), want), nil
	}
	return false, errors.New("secret: unknown password hash format")
}

func pbkdf2Hash(name string, sha1Default bool) (func() hash.Hash, bool) {
	switch name {
	case "sha256":
		return sha256.New, true
	case "sha512":
		return sha512.New, true
	}
	return nil, false
}

// decodeAB64 reads passlib's "adapted base64": standard base64 with "."
// for "+" and no padding.
func decodeAB64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.ReplaceAll(s, ".", "+"))
}

func decodeAny(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
