// Package config reads the engine's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type Config struct {
	// DatabaseURL is the Postgres connection string.
	DatabaseURL string
	// MasterKey wraps every tenant's data key. Base64 of 32 random bytes.
	// It never goes into the database.
	MasterKey string
	// ListenAddr is where the HTTP API listens.
	ListenAddr string
	// PublicURL is the address the world reaches the engine at. It is the
	// issuer of the tokens the engine signs as an OAuth provider.
	PublicURL string
	// Env is "development" or "production".
	Env string
	// TrustedProxies lists the proxies whose X-Forwarded-For header is
	// believed. Empty means the header is never trusted.
	TrustedProxies []netip.Prefix

	// SMTP settings for sending email. With no SMTPAddr, a development
	// engine writes emails to its log, and a production engine refuses
	// to start.
	SMTPAddr     string
	SMTPUsername string
	SMTPPassword string
	MailFrom     string

	// BreachCheck is "local" (the built-in list, the default) or "hibp"
	// (the built-in list plus the Have I Been Pwned service).
	BreachCheck string
}

func (c Config) Development() bool { return c.Env == "development" }

// FromEnv reads the configuration. needMasterKey is false for commands
// that only touch the schema, such as "migrate".
func FromEnv(needMasterKey bool) (Config, error) {
	c := Config{
		DatabaseURL: os.Getenv("AOS_DATABASE_URL"),
		MasterKey:   os.Getenv("AOS_MASTER_KEY"),
		ListenAddr:  getenv("AOS_LISTEN_ADDR", ":8080"),
		PublicURL:   strings.TrimRight(getenv("AOS_PUBLIC_URL", "http://localhost:8080"), "/"),
		Env:         getenv("AOS_ENV", "production"),

		SMTPAddr:     os.Getenv("AOS_SMTP_ADDR"),
		SMTPUsername: os.Getenv("AOS_SMTP_USERNAME"),
		SMTPPassword: os.Getenv("AOS_SMTP_PASSWORD"),
		MailFrom:     os.Getenv("AOS_MAIL_FROM"),

		BreachCheck: getenv("AOS_BREACH_CHECK", "local"),
	}
	if c.DatabaseURL == "" {
		return c, errors.New("AOS_DATABASE_URL is not set")
	}
	if needMasterKey && c.MasterKey == "" {
		return c, errors.New("AOS_MASTER_KEY is not set (create one with: aos keygen)")
	}
	if c.Env != "development" && c.Env != "production" {
		return c, fmt.Errorf("AOS_ENV must be development or production, not %q", c.Env)
	}
	if c.BreachCheck != "local" && c.BreachCheck != "hibp" {
		return c, fmt.Errorf("AOS_BREACH_CHECK must be local or hibp, not %q", c.BreachCheck)
	}
	for _, raw := range strings.Split(os.Getenv("AOS_TRUSTED_PROXIES"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return c, fmt.Errorf("AOS_TRUSTED_PROXIES: %q is not a network such as 10.0.0.0/8: %w", raw, err)
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	return c, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
