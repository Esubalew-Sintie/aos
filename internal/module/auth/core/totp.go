package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/flash-softeware/aos/internal/constant"
)

// TOTP is the time-based one-time password of RFC 6238, as authenticator
// apps implement it: HMAC-SHA1, 6 digits, 30-second steps.

// NewTOTPSecret returns 20 random bytes, the size the apps expect.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("totp secret: %w", err)
	}
	return b, nil
}

// TOTPURI is what the app scans: an otpauth link.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(constant.TOTPDigits))
	q.Set("period", fmt.Sprint(int(constant.TOTPPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// EncodeTOTPSecret is the base32 form shown for manual entry.
func EncodeTOTPSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// TOTPStep is the time step a moment falls in.
func TOTPStep(at time.Time) int64 {
	return at.Unix() / int64(constant.TOTPPeriod.Seconds())
}

// TOTPCode computes the code for one time step.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < constant.TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", constant.TOTPDigits, code%mod)
}

// VerifyTOTP checks a code against the steps around now. A step at or
// before lastUsed is refused, so a code cannot be replayed. It returns
// the step that matched.
func VerifyTOTP(secret []byte, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != constant.TOTPDigits {
		return 0, false
	}
	current := TOTPStep(now)
	matched := int64(0)
	ok := false
	// Every candidate is checked, so the time taken does not say which one matched.
	for d := -int64(constant.TOTPSkew); d <= int64(constant.TOTPSkew); d++ {
		step := current + d
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code)) == 1 && step > lastUsed {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// recoveryAlphabet leaves out letters that are easy to misread.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes makes n codes of the form xxxxx-xxxxx.
func NewRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("recovery codes: %w", err)
		}
		var sb strings.Builder
		for j, x := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
		}
		out = append(out, sb.String())
	}
	return out, nil
}

// NormalizeRecoveryCode makes typed codes comparable: lower case, no
// spaces or dashes.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	return strings.ReplaceAll(code, " ", "")
}

// NewNumericCode makes a sign-in code of the given number of digits.
func NewNumericCode(digits int) (string, error) {
	b := make([]byte, digits)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("numeric code: %w", err)
	}
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte('0' + x%10)
	}
	return sb.String(), nil
}
