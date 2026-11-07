package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
)

func parseURL(raw string) (*url.URL, error) { return url.Parse(raw) }

func randomString() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
