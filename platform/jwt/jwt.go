package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Signed tokens. The engine signs with Ed25519 and nothing else, so there
// is no algorithm to negotiate and none for an attacker to downgrade.

var b64url = base64.RawURLEncoding

const alg = "EdDSA"

// GenerateKey makes a new Ed25519 key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign returns a compact signed token. kid names the key, so a
// verifier can pick the matching public key.
func Sign(kid string, key ed25519.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64url.EncodeToString(header) + "." + b64url.EncodeToString(body)
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + b64url.EncodeToString(sig), nil
}

// Verify checks the signature and the expiry and returns the claims.
// lookup returns the public key for a key id, or nil if it is unknown.
// This is what an application's backend does with the 60-second token.
func Verify(token string, now time.Time, lookup func(kid string) ed25519.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: token is not in three parts")
	}
	headerJSON, err := b64url.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt: bad token header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("jwt: bad token header")
	}
	// The algorithm is fixed. A token that names any other is refused
	// before its signature is looked at.
	if header.Alg != alg {
		return nil, errors.New("jwt: token algorithm is not EdDSA")
	}
	key := lookup(header.Kid)
	if key == nil {
		return nil, errors.New("jwt: token was signed with an unknown key")
	}
	sig, err := b64url.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("jwt: bad token signature")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("jwt: token signature does not match")
	}
	bodyJSON, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: bad token body")
	}
	var claims map[string]any
	if err := json.Unmarshal(bodyJSON, &claims); err != nil {
		return nil, errors.New("jwt: bad token body")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("jwt: token has no expiry")
	}
	if !now.Before(time.Unix(int64(exp), 0)) {
		return nil, errors.New("jwt: token has expired")
	}
	return claims, nil
}

// JWK is a public key in the JSON form that verifiers download.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func PublicJWK(kid string, key ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64url.EncodeToString(key), Kid: kid, Use: "sig", Alg: alg}
}

// PublicKey reads the key back out of a JWK.
func (j JWK) PublicKey() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, errors.New("jwt: not an Ed25519 key")
	}
	raw, err := b64url.DecodeString(j.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("jwt: bad Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}
