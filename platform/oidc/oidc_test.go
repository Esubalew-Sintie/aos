package oidc

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFlowAgainstTheFakeProvider(t *testing.T) {
	fp, err := NewFakeProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()
	c := New(true)
	p, err := c.Discover(context.Background(), fp.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewVerifier()
	u := AuthorizationURL(p, fp.ClientID, "https://app.test/cb", "state1", "nonce1", verifier, []string{"openid", "email"})
	if !strings.Contains(u, "code_challenge_method=S256") || !strings.Contains(u, "state=state1") {
		t.Fatalf("url: %s", u)
	}
	code, state, err := fp.Authorize(u, map[string]any{"sub": "u1", "email": "A@Example.com", "email_verified": true, "name": "Ann"})
	if err != nil || state != "state1" {
		t.Fatal(err, state)
	}
	id, err := c.Exchange(context.Background(), p, fp.ClientID, fp.Secret, "https://app.test/cb", code, verifier, "nonce1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "u1" || id.Email != "a@example.com" || !id.EmailVerified || id.Name != "Ann" {
		t.Fatalf("identity: %+v", id)
	}
	// A wrong verifier, a used code, a wrong nonce, and a wrong audience are refused.
	if _, err := c.Exchange(context.Background(), p, fp.ClientID, fp.Secret, "https://app.test/cb", code, verifier, "nonce1", time.Now()); err == nil {
		t.Fatal("a code worked twice")
	}
	code, _, _ = fp.Authorize(u, map[string]any{"sub": "u1"})
	if _, err := c.Exchange(context.Background(), p, fp.ClientID, fp.Secret, "https://app.test/cb", code, "wrong", "nonce1", time.Now()); err == nil {
		t.Fatal("a wrong verifier was accepted")
	}
	code, _, _ = fp.Authorize(u, map[string]any{"sub": "u1"})
	if _, err := c.Exchange(context.Background(), p, fp.ClientID, fp.Secret, "https://app.test/cb", code, verifier, "other-nonce", time.Now()); err == nil {
		t.Fatal("a wrong nonce was accepted")
	}
	code, _, _ = fp.Authorize(u, map[string]any{"sub": "u1", "aud": "someone-else"})
	if _, err := c.Exchange(context.Background(), p, fp.ClientID, fp.Secret, "https://app.test/cb", code, verifier, "nonce1", time.Now()); err == nil {
		t.Fatal("a token for another client was accepted")
	}
	// Private addresses are refused unless allowed.
	if _, err := New(false).Discover(context.Background(), fp.Server.URL); err == nil {
		t.Fatal("a private provider was accepted in production")
	}
}
