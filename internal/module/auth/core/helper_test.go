package core

import (
	"bytes"
	"testing"
	"time"

	"github.com/flash-softeware/aos/internal/constant"
)

func TestLockoutDelay(t *testing.T) {
	want := map[int]time.Duration{
		1: 0, 5: 0, // the first five failures cost nothing
		6: 1 * time.Second, 7: 2 * time.Second, 8: 4 * time.Second, 9: 8 * time.Second, // then it doubles
		10: constant.LockoutDuration, 11: constant.LockoutDuration, 50: constant.LockoutDuration, // then the lock
	}
	for failures, delay := range want {
		if got := LockoutDelay(failures); got != delay {
			t.Errorf("after %d failures: got %v, want %v", failures, got, delay)
		}
	}
}

func TestEmailInDomains(t *testing.T) {
	domains := []string{"example.com", " Bank.Example "}
	for email, want := range map[string]bool{
		"a@example.com":          true,
		"a@EXAMPLE.com":          true,
		"a@bank.example":         true,
		"a@evil-example.com":     false,
		"a@example.com.evil.org": false,
		"example.com":            false,
		"a@":                     false,
	} {
		if got := EmailInDomains(email, domains); got != want {
			t.Errorf("%s: got %v, want %v", email, got, want)
		}
	}
}

func TestLink(t *testing.T) {
	if got := Link("", VerifyEmailPath, "tok"); got != "" {
		t.Errorf("with no application address there is no link, got %q", got)
	}
	if got, want := Link("https://app.test/", VerifyEmailPath, "a b+c"), "https://app.test/auth/verify-email?token=a+b%2Bc"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLimitKey(t *testing.T) {
	if !bytes.Equal(LimitKey("a@example.com"), LimitKey("a@example.com")) {
		t.Error("the same value gave two keys")
	}
	if bytes.Equal(LimitKey("a@example.com"), LimitKey("b@example.com")) {
		t.Error("two values gave the same key")
	}
	if bytes.Contains(LimitKey("a@example.com"), []byte("example")) {
		t.Error("the key shows the address")
	}
}
