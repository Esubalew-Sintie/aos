package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Envelope encryption: every tenant has its own data key, which encrypts
// that tenant's secrets. The data key is stored in the database only in
// wrapped form, encrypted by the master key. The master key lives outside
// the database. A copy of the database alone therefore decrypts nothing.

const dataKeyLen = 32

// MasterKey wraps and unwraps data keys.
type MasterKey struct {
	key []byte
	ref string
}

// ParseMasterKey reads a master key from base64 of 32 random bytes.
func ParseMasterKey(encoded string) (*MasterKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("secret: master key is not valid base64: %w", err)
	}
	if len(key) != dataKeyLen {
		return nil, fmt.Errorf("secret: master key must be %d bytes, got %d", dataKeyLen, len(key))
	}
	sum := sha256.Sum256(key)
	return &MasterKey{key: key, ref: "env:" + hex.EncodeToString(sum[:4])}, nil
}

// NewMasterKeyString makes a fresh master key in the form ParseMasterKey reads.
func NewMasterKeyString() string {
	key := make([]byte, dataKeyLen)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// Ref names this master key without revealing it. It is stored beside
// each wrapped data key, so a later key rotation knows which key wrapped what.
func (m *MasterKey) Ref() string { return m.ref }

func (m *MasterKey) Wrap(dataKey []byte) ([]byte, error) {
	return Seal(m.key, dataKey, []byte("aos:data-key"))
}

func (m *MasterKey) Unwrap(wrapped []byte) ([]byte, error) {
	return Open(m.key, wrapped, []byte("aos:data-key"))
}

// NewDataKey makes a fresh per-tenant data key.
func NewDataKey() []byte {
	key := make([]byte, dataKeyLen)
	rand.Read(key)
	return key
}

// Seal encrypts plaintext with AES-256-GCM. The result is the random
// nonce followed by the ciphertext. context is bound to the result: Open
// fails unless it is given the same context, so a value encrypted for one
// tenant or purpose cannot be swapped in for another.
func Seal(key, plaintext, context []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	return aead.Seal(nonce, nonce, plaintext, context), nil
}

// Open reverses Seal.
func Open(key, sealed, context []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("secret: sealed value is too short")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, context)
	if err != nil {
		return nil, errors.New("secret: could not decrypt (wrong key, wrong context, or changed data)")
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != dataKeyLen {
		return nil, fmt.Errorf("secret: key must be %d bytes, got %d", dataKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
