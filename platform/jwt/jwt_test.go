package jwt

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	lookup := func(kid string) ed25519.PublicKey {
		if kid == "k1" {
			return pub
		}
		return nil
	}

	token, err := Sign("k1", priv, map[string]any{"sub": "user-1", "exp": now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(token, now, lookup)
	if err != nil || claims["sub"] != "user-1" {
		t.Fatalf("verify: %v %v", claims, err)
	}

	// At and after its expiry, it is refused.
	if _, err := Verify(token, now.Add(time.Minute), lookup); err == nil {
		t.Fatal("a token verified at the moment it expired")
	}
	if _, err := Verify(token, now.Add(time.Hour), lookup); err == nil {
		t.Fatal("an expired token verified")
	}
}

func TestVerifyRefusesForgedTokens(t *testing.T) {
	pub, priv, _ := GenerateKey()
	_, otherPriv, _ := GenerateKey()
	now := time.Unix(1_800_000_000, 0)
	lookup := func(kid string) ed25519.PublicKey {
		if kid == "k1" {
			return pub
		}
		return nil
	}
	claims := map[string]any{"sub": "user-1", "exp": now.Add(time.Minute).Unix()}
	good, _ := Sign("k1", priv, claims)
	parts := strings.Split(good, ".")

	// A body that names another user, under the original signature.
	forgedBody, _ := json.Marshal(map[string]any{"sub": "admin", "exp": now.Add(time.Minute).Unix()})
	// A header that claims no signature is needed.
	noneHeader := b64url.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`))
	// A header that claims a shared-secret algorithm.
	hmacHeader := b64url.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"k1"}`))

	signedByAnother, _ := Sign("k1", otherPriv, claims)
	unknownKey, _ := Sign("k2", priv, claims)
	noExpiry, _ := Sign("k1", priv, map[string]any{"sub": "user-1"})

	for name, token := range map[string]string{
		"changed body":            parts[0] + "." + b64url.EncodeToString(forgedBody) + "." + parts[2],
		"algorithm none":          noneHeader + "." + parts[1] + ".",
		"algorithm none with sig": noneHeader + "." + parts[1] + "." + parts[2],
		"algorithm HS256":         hmacHeader + "." + parts[1] + "." + parts[2],
		"signed by another key":   signedByAnother,
		"unknown key id":          unknownKey,
		"no expiry":               noExpiry,
		"signature removed":       parts[0] + "." + parts[1] + ".",
		"not a token":             "abc",
		"empty":                   "",
	} {
		if _, err := Verify(token, now, lookup); err == nil {
			t.Errorf("%s: the token verified", name)
		}
	}
}

func TestJWKRoundTrip(t *testing.T) {
	pub, _, _ := GenerateKey()
	jwk := PublicJWK("k1", pub)
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" || jwk.Kid != "k1" {
		t.Fatalf("unexpected JWK: %+v", jwk)
	}
	back, err := jwk.PublicKey()
	if err != nil || !pub.Equal(back) {
		t.Fatalf("the key did not survive the round trip: %v", err)
	}
	if _, err := (JWK{Kty: "RSA"}).PublicKey(); err == nil {
		t.Fatal("a key of another type was accepted")
	}
}
