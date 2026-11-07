// Package oidc is a small OpenID Connect client: discovery, the
// authorization request with PKCE, the code exchange, and the checks on
// the identity token. It holds no state between calls.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider is what the client needs to know about an issuer.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// Identity is what the provider said about the person.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Issuer        string
	Claims        map[string]any
}

// Client talks to providers. AllowPrivate lets it reach addresses on a
// private network, for development only.
type Client struct {
	HTTP         *http.Client
	AllowPrivate bool
}

func New(allowPrivate bool) *Client {
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Second}, AllowPrivate: allowPrivate}
}

var b64 = base64.RawURLEncoding

// Discover reads the provider's configuration document.
func (c *Client) Discover(ctx context.Context, issuer string) (*Provider, error) {
	if err := c.checkURL(issuer); err != nil {
		return nil, err
	}
	var p Provider
	if err := c.getJSON(ctx, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", &p); err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return nil, errors.New("oidc: the provider's configuration is incomplete")
	}
	for _, u := range []string{p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI} {
		if err := c.checkURL(u); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

// NewVerifier makes a PKCE verifier.
func NewVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// Challenge is the S256 challenge of a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// AuthorizationURL is where the browser goes.
func AuthorizationURL(p *Provider, clientID, redirectURI, state, nonce, verifier string, scopes []string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(p.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.AuthorizationEndpoint + sep + q.Encode()
}

// Exchange trades the code for tokens and checks the identity token.
func (c *Client) Exchange(ctx context.Context, p *Provider, clientID, clientSecret, redirectURI, code, verifier, nonce string, now time.Time) (*Identity, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc: the provider refused the code (%d)", resp.StatusCode)
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil || tokens.IDToken == "" {
		return nil, errors.New("oidc: the provider returned no identity token")
	}
	claims, err := c.VerifyIDToken(ctx, p, tokens.IDToken, clientID, nonce, now)
	if err != nil {
		return nil, err
	}
	id := &Identity{Claims: claims, Issuer: p.Issuer}
	id.Subject, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	id.Name, _ = claims["name"].(string)
	switch v := claims["email_verified"].(type) {
	case bool:
		id.EmailVerified = v
	case string:
		id.EmailVerified = v == "true"
	}
	if id.Subject == "" {
		return nil, errors.New("oidc: the identity token names no subject")
	}
	id.Email = strings.ToLower(strings.TrimSpace(id.Email))
	return id, nil
}

// VerifyIDToken checks the signature against the provider's keys, and
// the issuer, audience, nonce and expiry.
func (c *Client) VerifyIDToken(ctx context.Context, p *Provider, token, clientID, nonce string, now time.Time) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: identity token is not in three parts")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("oidc: bad identity token header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("oidc: bad identity token header")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("oidc: bad identity token payload")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("oidc: bad identity token signature")
	}
	keys, err := c.fetchKeys(ctx, p.JWKSURI)
	if err != nil {
		return nil, err
	}
	key, ok := keys[header.Kid]
	if !ok {
		if len(keys) == 1 && header.Kid == "" {
			for _, k := range keys {
				key = k
			}
		} else {
			return nil, errors.New("oidc: identity token was signed with an unknown key")
		}
	}
	signed := []byte(parts[0] + "." + parts[1])
	switch header.Alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("oidc: key type does not match the algorithm")
		}
		sum := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, errors.New("oidc: identity token signature does not match")
		}
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return nil, errors.New("oidc: key type does not match the algorithm")
		}
		sum := sha256.Sum256(signed)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return nil, errors.New("oidc: identity token signature does not match")
		}
	default:
		return nil, fmt.Errorf("oidc: identity token algorithm %q is not supported", header.Alg)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("oidc: bad identity token payload")
	}
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(p.Issuer, "/") {
		return nil, errors.New("oidc: identity token came from another issuer")
	}
	if !audienceHas(claims["aud"], clientID) {
		return nil, errors.New("oidc: identity token is for another client")
	}
	if n, _ := claims["nonce"].(string); nonce != "" && n != nonce {
		return nil, errors.New("oidc: identity token nonce does not match")
	}
	exp, _ := claims["exp"].(float64)
	if exp == 0 || !now.Before(time.Unix(int64(exp), 0).Add(time.Minute)) {
		return nil, errors.New("oidc: identity token has expired")
	}
	return claims, nil
}

func audienceHas(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (c *Client) fetchKeys(ctx context.Context, uri string) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(ctx, uri, &set); err != nil {
		return nil, fmt.Errorf("oidc: keys: %w", err)
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := b64.DecodeString(k.N)
			e, err2 := b64.DecodeString(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := b64.DecodeString(k.X)
			y, err2 := b64.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			out[k.Kid] = &ecdsa.PublicKey{Curve: ellipticP256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("oidc: the provider published no usable key")
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, uri string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %d", uri, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst)
}

// checkURL refuses anything but https to a public host, unless private
// addresses are allowed for development.
func (c *Client) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("oidc: not a valid address")
	}
	if u.Scheme != "https" && !(c.AllowPrivate && u.Scheme == "http") {
		return errors.New("oidc: the provider must use https")
	}
	if c.AllowPrivate {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && isPrivate(ip) {
		return errors.New("oidc: the provider must be on the public internet")
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return errors.New("oidc: the provider must be on the public internet")
	}
	return nil
}

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
}
