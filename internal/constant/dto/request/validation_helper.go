// Package request holds what the API accepts, and the checks on it.
package request

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/flash-softeware/aos/internal/constant"
)

// These two patterns are the same as the check constraints on
// aos.permissions and aos.role_permissions.
var (
	permissionName    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?$`)
	slugPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// NormalizeEmail trims and lower-cases an address. Sign-up, sign-in and
// reset all use it, so the same person always maps to the same account.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	// ParseAddress also accepts "Name <a@b>". Only a bare address is allowed.
	return err == nil && addr.Address == email && strings.Contains(email[strings.LastIndex(email, "@")+1:], ".")
}

// passwordProblem returns why a password is not acceptable, or "".
// The rule is length only: no forced symbols.
func passwordProblem(password string) string {
	n := utf8.RuneCountInString(password)
	switch {
	case n < constant.PasswordMinLength:
		return "must be at least 8 characters"
	case n > constant.PasswordMaxLength:
		return "must be at most 256 characters"
	}
	return ""
}

func validPermissionName(name string) bool {
	return len(name) <= 200 && permissionName.MatchString(name)
}

func validPermissionPattern(pattern string) bool {
	return pattern == "*" || (len(pattern) <= 200 && permissionPattern.MatchString(pattern))
}

func validUUID(s string) bool { return uuidPattern.MatchString(s) }

// fields collects one message per failed field.
type fields map[string]string

func (f fields) require(name, value string) {
	if strings.TrimSpace(value) == "" {
		f[name] = "is required"
	}
}
