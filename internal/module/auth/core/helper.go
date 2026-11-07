// Package core holds the small pure rules of sign-in.
package core

import (
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/platform/secret"
)

// LimitKey turns an email address or a client address into the key of a
// rate-limit counter. Only a hash is stored, so the counters table holds
// no addresses.
func LimitKey(value string) []byte {
	return secret.Hash("aos:limit|" + value)
}

// LockoutDelay is how long sign-in pauses after a failed attempt.
// The first failures cost nothing. Then each one doubles the wait: 1, 2,
// 4, 8 seconds. At the lock limit the account is locked for the full
// lockout time.
func LockoutDelay(failures int) time.Duration {
	switch {
	case failures >= constant.LockoutLockAfter:
		return constant.LockoutDuration
	case failures > constant.LockoutDelayAfter:
		return time.Second << (failures - constant.LockoutDelayAfter - 1)
	}
	return 0
}

// EmailInDomains reports whether an address belongs to one of the listed
// domains.
func EmailInDomains(email string, domains []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	for _, d := range domains {
		if strings.EqualFold(domain, strings.TrimSpace(d)) {
			return true
		}
	}
	return false
}

// Link builds the address a person opens from an email. The token is in
// the query string of a page in the application. That page shows the AOS
// screen, which sends the token to the API with a POST. It returns "" when
// the tenant has no application address, and the email then shows the
// token itself.
func Link(appURL, path, token string) string {
	if appURL == "" {
		return ""
	}
	return strings.TrimRight(appURL, "/") + path + "?token=" + url.QueryEscape(token)
}

// Paths in the application that the email links point at.
const (
	VerifyEmailPath   = "/auth/verify-email"
	ResetPasswordPath = "/auth/reset-password"
	ConfirmEmailPath  = "/auth/confirm-email"
	SetupAccountPath  = "/auth/setup"
	InvitationPath    = "/auth/invitation"
	MagicLinkPath     = "/auth/magic-link"
	ApprovalsPath     = "/auth/approvals"
	ForgotPath        = "/auth/forgot-password"
)

// DeviceLabel turns a user agent into a short, readable description.
func DeviceLabel(userAgent string) string {
	ua := strings.ToLower(userAgent)
	browser := "a browser"
	switch {
	case strings.Contains(ua, "edg/"):
		browser = "Edge"
	case strings.Contains(ua, "chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "safari/"):
		browser = "Safari"
	case ua == "":
		return "an unknown device"
	}
	os := ""
	switch {
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"):
		os = "iOS"
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac os"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	}
	if os == "" {
		return browser
	}
	return browser + " on " + os
}

// EmailDomain is the part after the @, lower-cased.
func EmailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// AddressAllowed reports whether an address is in an allow-list of
// addresses and networks. An unknown address is not allowed.
func AddressAllowed(ip string, allow []string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, entry := range allow {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(addr) {
				return true
			}
			continue
		}
		if one := net.ParseIP(entry); one != nil && one.Equal(addr) {
			return true
		}
	}
	return false
}
