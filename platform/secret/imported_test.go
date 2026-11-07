package secret

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func TestImportedHashes(t *testing.T) {
	bc, _ := bcrypt.GenerateFromPassword([]byte("hunter22"), 4)
	salt := []byte("saltsaltsaltsalt")
	sc, _ := scrypt.Key([]byte("hunter22"), salt, 1<<10, 8, 1, 32)
	scryptHash := fmt.Sprintf("$scrypt$ln=10,r=8,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sc))
	pb := pbkdf2.Key([]byte("hunter22"), salt, 1000, 32, sha256.New)
	passlib := fmt.Sprintf("$pbkdf2-sha256$1000$%s$%s", strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(salt), "+", "."), strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(pb), "+", "."))
	django := fmt.Sprintf("pbkdf2_sha256$1000$%s$%s", "plainsalt", base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte("hunter22"), []byte("plainsalt"), 1000, 32, sha256.New)))
	for name, h := range map[string]string{"bcrypt": string(bc), "bcrypt-2y": "$2y$" + string(bc)[4:], "scrypt": scryptHash, "passlib": passlib, "django": django} {
		if !IsSupportedHash(h) {
			t.Errorf("%s: not recognised", name)
		}
		ok, p, err := VerifyPassword("hunter22", h)
		if err != nil || !ok {
			t.Errorf("%s: right password refused: %v", name, err)
		}
		if !p.Weaker(DefaultPasswordParams) {
			t.Errorf("%s: an imported hash must be replaced after sign-in", name)
		}
		if ok, _, _ := VerifyPassword("wrong", h); ok {
			t.Errorf("%s: wrong password accepted", name)
		}
	}
	for _, bad := range []string{"", "plain", "$md5$x", "$2a$31$" + strings.Repeat("a", 53), "$scrypt$ln=40,r=8,p=1$c2FsdA$aGFzaA"} {
		if IsSupportedHash(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	argon, _ := HashPassword("x", PasswordParams{MemoryKiB: 64, Time: 1, Threads: 1})
	if !IsSupportedHash(argon) {
		t.Error("argon2id not recognised")
	}
}
