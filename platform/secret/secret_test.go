package secret

import (
	"bytes"
	"strings"
	"testing"
)

var fast = PasswordParams{MemoryKiB: 64, Time: 1, Threads: 1}

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=64,t=1,p=1$") || strings.Contains(hash, "correct horse") {
		t.Fatalf("unexpected hash: %s", hash)
	}

	ok, params, err := VerifyPassword("correct horse", hash)
	if err != nil || !ok || params != fast {
		t.Fatalf("the right password: ok=%v params=%+v err=%v", ok, params, err)
	}
	if ok, _, _ := VerifyPassword("wrong horse", hash); ok {
		t.Fatal("a wrong password verified")
	}
	if ok, _, _ := VerifyPassword("", hash); ok {
		t.Fatal("an empty password verified")
	}

	// The same password hashes differently every time, because of the salt.
	again, _ := HashPassword("correct horse", fast)
	if again == hash {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}
}

func TestPasswordHashRefusesBadInput(t *testing.T) {
	for name, encoded := range map[string]string{
		"not a hash":        "plain-text",
		"another algorithm": "$2a$10$abcdefghijklmnopqrstuv",
		"zero memory":       "$argon2id$v=19$m=0,t=1,p=1$c2FsdA$aGFzaA",
		"absurd memory":     "$argon2id$v=19$m=999999999,t=1,p=1$c2FsdA$aGFzaA",
		"absurd time":       "$argon2id$v=19$m=64,t=9999,p=1$c2FsdA$aGFzaA",
		"empty hash":        "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$",
	} {
		if ok, _, err := VerifyPassword("x", encoded); ok || err == nil {
			t.Errorf("%s: ok=%v err=%v, want a refusal", name, ok, err)
		}
	}
}

func TestWeakerParams(t *testing.T) {
	if !fast.Weaker(DefaultPasswordParams) {
		t.Fatal("the test settings should count as weaker than the default")
	}
	if DefaultPasswordParams.Weaker(DefaultPasswordParams) || DefaultPasswordParams.Weaker(fast) {
		t.Fatal("equal or stronger settings were reported as weaker")
	}
}

func TestSealAndOpen(t *testing.T) {
	key := NewDataKey()
	sealed, err := Seal(key, []byte("the reset link"), []byte("tenant-a"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("reset")) {
		t.Fatal("the sealed value shows its plaintext")
	}
	plain, err := Open(key, sealed, []byte("tenant-a"))
	if err != nil || string(plain) != "the reset link" {
		t.Fatalf("open: %q %v", plain, err)
	}

	// Sealing twice gives different bytes: the nonce is random.
	again, _ := Seal(key, []byte("the reset link"), []byte("tenant-a"))
	if bytes.Equal(sealed, again) {
		t.Fatal("two seals of one value are identical")
	}

	// Anything changed, and Open refuses.
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	for name, try := range map[string]func() ([]byte, error){
		"changed data":    func() ([]byte, error) { return Open(key, tampered, []byte("tenant-a")) },
		"another key":     func() ([]byte, error) { return Open(NewDataKey(), sealed, []byte("tenant-a")) },
		"another context": func() ([]byte, error) { return Open(key, sealed, []byte("tenant-b")) },
		"too short":       func() ([]byte, error) { return Open(key, []byte("x"), []byte("tenant-a")) },
		"a short key":     func() ([]byte, error) { return Open([]byte("short"), sealed, []byte("tenant-a")) },
	} {
		if _, err := try(); err == nil {
			t.Errorf("%s: Open succeeded", name)
		}
	}
}

func TestMasterKeyWrapsDataKeys(t *testing.T) {
	master, err := ParseMasterKey(NewMasterKeyString())
	if err != nil {
		t.Fatal(err)
	}
	dataKey := NewDataKey()
	wrapped, err := master.Wrap(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dataKey) {
		t.Fatal("the wrapped key shows the data key")
	}
	got, err := master.Unwrap(wrapped)
	if err != nil || !bytes.Equal(got, dataKey) {
		t.Fatalf("unwrap: %v", err)
	}

	other, _ := ParseMasterKey(NewMasterKeyString())
	if _, err := other.Unwrap(wrapped); err == nil {
		t.Fatal("another master key unwrapped the data key")
	}
	if master.Ref() == other.Ref() || strings.Contains(master.Ref(), NewMasterKeyString()) {
		t.Fatal("the key reference does not tell two keys apart")
	}

	for name, bad := range map[string]string{"not base64": "!!!", "too short": "c2hvcnQ=", "empty": ""} {
		if _, err := ParseMasterKey(bad); err == nil {
			t.Errorf("%s: a bad master key was accepted", name)
		}
	}
}

func TestTokensAreRandomAndHashStable(t *testing.T) {
	a, b := Token(32), Token(32)
	if a == b || len(a) < 40 {
		t.Fatalf("tokens are not random or too short: %q %q", a, b)
	}
	if !Equal(Hash(a), Hash(a)) || Equal(Hash(a), Hash(b)) {
		t.Fatal("hash comparison is wrong")
	}
	if len(HexID(12)) != 24 {
		t.Fatal("hex id has the wrong length")
	}
}
