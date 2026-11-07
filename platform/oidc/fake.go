package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// FakeProvider is an OpenID Connect provider for tests. It issues one
// code per sign-in and signs identity tokens with RS256.
type FakeProvider struct {
	Server   *httptest.Server
	ClientID string
	Secret   string
	key      *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]fakeCode
	// Calls counts token exchanges.
	Calls int
}

type fakeCode struct {
	claims   map[string]any
	verifier string
}

func NewFakeProvider() (*FakeProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	p := &FakeProvider{ClientID: "client-123", Secret: "secret-456", key: key, codes: map[string]fakeCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Provider{
			Issuer: p.Server.URL, AuthorizationEndpoint: p.Server.URL + "/authorize",
			TokenEndpoint: p.Server.URL + "/token", JWKSURI: p.Server.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": b64.EncodeToString(key.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		defer p.mu.Unlock()
		p.Calls++
		c, ok := p.codes[r.Form.Get("code")]
		if !ok || r.Form.Get("client_id") != p.ClientID || r.Form.Get("client_secret") != p.Secret ||
			r.Form.Get("code_verifier") == "" || Challenge(r.Form.Get("code_verifier")) != c.verifier {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		delete(p.codes, r.Form.Get("code"))
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": p.sign(c.claims), "access_token": "at", "token_type": "Bearer"})
	})
	p.Server = httptest.NewServer(mux)
	return p, nil
}

// Authorize plays the person approving at the provider: it takes the
// authorization URL the engine made and returns the code the browser
// would carry back, with the claims the provider will put in the token.
func (p *FakeProvider) Authorize(authorizationURL string, claims map[string]any) (code, state string, err error) {
	u, err := parseURL(authorizationURL)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	code = "code-" + randomString()
	full := map[string]any{"iss": p.Server.URL, "aud": q.Get("client_id"), "nonce": q.Get("nonce"),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		full[k] = v
	}
	p.mu.Lock()
	p.codes[code] = fakeCode{claims: full, verifier: q.Get("code_challenge")}
	p.mu.Unlock()
	return code, q.Get("state"), nil
}

func (p *FakeProvider) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signed := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	return signed + "." + b64.EncodeToString(sig)
}

func (p *FakeProvider) Close() { p.Server.Close() }
