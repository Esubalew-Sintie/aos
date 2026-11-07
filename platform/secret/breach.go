package secret

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// A BreachChecker reports whether a password is known to be leaked.
type BreachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}

// LocalBreachList refuses the most common leaked passwords from a list
// built into the binary. It needs no network and never fails.
type LocalBreachList struct {
	set map[string]struct{}
}

func NewLocalBreachList() *LocalBreachList {
	set := make(map[string]struct{}, len(commonPasswords))
	for _, p := range commonPasswords {
		set[p] = struct{}{}
	}
	return &LocalBreachList{set: set}
}

func (l *LocalBreachList) Breached(_ context.Context, password string) (bool, error) {
	_, found := l.set[strings.ToLower(strings.TrimSpace(password))]
	return found, nil
}

// HIBPChecker asks the Have I Been Pwned range API. Only the first five
// characters of the password's SHA-1 leave this machine; the service
// answers with every suffix that shares them, and the match is made here.
type HIBPChecker struct {
	client  *http.Client
	baseURL string
}

func NewHIBPChecker() *HIBPChecker {
	return &HIBPChecker{client: &http.Client{Timeout: 3 * time.Second}, baseURL: "https://api.pwnedpasswords.com/range/"}
}

// NewHIBPCheckerAt points the checker at another address. For tests.
func NewHIBPCheckerAt(baseURL string) *HIBPChecker {
	return &HIBPChecker{client: &http.Client{Timeout: 3 * time.Second}, baseURL: baseURL}
}

func (h *HIBPChecker) Breached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "aos-identity-engine")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("breach check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("breach check: the service answered %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, suffix) && !strings.HasSuffix(line, ":0") {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// BreachChain asks each checker in turn. A checker that fails is skipped:
// a password check must not stop sign-ups when a network service is down.
type BreachChain struct {
	checkers []BreachChecker
	onError  func(error)
}

func NewBreachChain(onError func(error), checkers ...BreachChecker) *BreachChain {
	return &BreachChain{checkers: checkers, onError: onError}
}

func (c *BreachChain) Breached(ctx context.Context, password string) (bool, error) {
	for _, checker := range c.checkers {
		found, err := checker.Breached(ctx, password)
		if err != nil {
			if c.onError != nil {
				c.onError(err)
			}
			continue
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// commonPasswords are the most used passwords in public leak lists. A
// password on this list is refused whatever else it contains.
var commonPasswords = []string{
	"123456", "123456789", "12345678", "password", "qwerty123", "qwerty1", "111111", "12345", "secret", "123123",
	"1234567890", "1234567", "000000", "qwerty", "abc123", "password1", "iloveyou", "11111111", "dragon", "monkey",
	"123321", "654321", "666666", "1q2w3e4r", "7777777", "123qwe", "zxcvbnm", "121212", "asdasd", "a123456",
	"sunshine", "princess", "football", "charlie", "welcome", "login", "admin", "admin123", "letmein", "master",
	"passw0rd", "password123", "baseball", "shadow", "michael", "jennifer", "superman", "hello123", "whatever",
	"trustno1", "computer", "freedom", "starwars", "summer", "flower", "hottie", "loveme", "zaq12wsx", "passwort",
	"qwertyuiop", "asdfghjkl", "1qaz2wsx", "q1w2e3r4", "88888888", "987654321", "11223344", "1234qwer", "qazwsx",
	"123abc", "abcd1234", "pokemon", "batman", "soccer", "cheese", "killer", "jordan", "hunter", "harley",
	"ranger", "buster", "thomas", "robert", "george", "daniel", "andrew", "joshua", "matthew", "mustang",
	"access", "ashley", "nicole", "bailey", "tigger", "cookie", "maggie", "ginger", "yankees", "pepper",
	"test1234", "changeme", "default", "temp123", "welcome1", "welcome123", "p@ssw0rd", "pa55word", "root", "toor",
	"12341234", "123456a", "1234567a", "qwerty12", "1q2w3e", "asdf1234", "zxcvbn", "aaaaaa", "abc12345", "mypassword",
}
