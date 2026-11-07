package response

import (
	"encoding/json"
	"time"
)

type User struct {
	ID             string    `json:"id"`
	Email          string    `json:"email,omitempty"`
	Name           string    `json:"name,omitempty"`
	Status         string    `json:"status"`
	EmailVerified  bool      `json:"email_verified"`
	AssuranceLevel int       `json:"assurance_level"`
	CreatedAt      time.Time `json:"created_at"`
	// Guest is true for a visitor with no account yet.
	Guest bool `json:"guest,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
	// SecondFactorAt is when a second factor was last given, if ever.
	SecondFactorAt *time.Time `json:"second_factor_at,omitempty"`
	// The organization the person is working in, when one is chosen.
	ActiveOrganizationID string `json:"active_organization_id,omitempty"`
	ActiveOrganization   string `json:"active_organization,omitempty"`
}

// AuthResponse is the answer to a successful sign-in or verification.
type AuthResponse struct {
	User    User    `json:"user"`
	Session Session `json:"session"`
	// SessionToken is the raw session id. The handler puts it in a
	// host-locked cookie. It appears in the body only for development
	// tenants, where a first-party cookie is not possible.
	SessionToken string `json:"session_token,omitempty"`
	// DeviceToken is a long-lived id for this browser. The handler puts
	// it in a cookie, and never shows it in the body.
	DeviceToken string `json:"-"`

	// SecondFactorRequired means no session exists yet: the person must
	// give a second factor with the pending token (SIGN-2).
	SecondFactorRequired bool     `json:"second_factor_required,omitempty"`
	PendingToken         string   `json:"pending_token,omitempty"`
	Methods              []string `json:"methods,omitempty"`
	// SecondFactorSetupRequired means the application requires a second
	// factor and this person has none yet. The session works only for
	// setting one up.
	SecondFactorSetupRequired bool `json:"second_factor_setup_required,omitempty"`

	// TestResult is what a test sign-in through a company identity
	// provider returned, with no session made.
	TestResult map[string]any `json:"test_result,omitempty"`

	// For a token session (SIGN-8): a signed access token and a refresh
	// token, instead of a cookie.
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// TOTPEnrollment is what the person scans or types into their app.
type TOTPEnrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// RecoveryCodes are shown once.
type RecoveryCodes struct {
	Codes []string `json:"codes"`
}

type Factors struct {
	TOTP              bool       `json:"totp"`
	Passkeys          int        `json:"passkeys"`
	RecoveryCodesLeft int        `json:"recovery_codes_left"`
	SecondFactorAt    *time.Time `json:"second_factor_at,omitempty"`
	Required          bool       `json:"required"`
}

type StepUpResponse struct {
	SecondFactorAt time.Time `json:"second_factor_at"`
}

// SessionResponse is the answer to "who am I".
type SessionResponse struct {
	User    User    `json:"user"`
	Session Session `json:"session"`
}

// TokenResponse carries the short-lived signed token that the
// application's own backend verifies.
type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// JWK is a public signing key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// SessionInfo is one entry of a person's device list.
type SessionInfo struct {
	ID          string    `json:"id"`
	Current     bool      `json:"current"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	IP          string    `json:"ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	AuthMethods []string  `json:"auth_methods"`
}

// ExportResponse is everything AOS holds about one person.
type ExportResponse struct {
	User     User          `json:"user"`
	Sessions []SessionInfo `json:"sessions"`
	Grants   []Grant       `json:"grants"`
	Audit    []AuditEntry  `json:"audit"`
}

type AuditEntry struct {
	Seq        int64     `json:"seq"`
	OccurredAt time.Time `json:"occurred_at"`
	Action     string    `json:"action"`
	Result     string    `json:"result"`
	ReasonCode string    `json:"reason_code,omitempty"`
	TargetType string    `json:"target_type,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
}

// UserPage is one page of users.
type UserPage struct {
	Users      []User `json:"users"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// Webhook is a registered endpoint. The signing secret appears only in
// the answer to the call that created it.
type Webhook struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	URL           string     `json:"url"`
	Label         string     `json:"label,omitempty"`
	EventTypes    []string   `json:"event_types"`
	TimeoutMs     int        `json:"timeout_ms"`
	Secret        string     `json:"secret,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

// PasskeyChallenge is what the browser hands to navigator.credentials.
type PasskeyChallenge struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

type Passkey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name,omitempty"`
	Transports []string   `json:"transports"`
	BackedUp   bool       `json:"backed_up"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// OAuthProvider never carries the secret.
type OAuthProvider struct {
	Provider  string    `json:"provider"`
	ClientID  string    `json:"client_id"`
	Issuer    string    `json:"issuer"`
	Scopes    []string  `json:"scopes"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// SocialStart is where the browser goes next.
type SocialStart struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

type Identity struct {
	Provider     string     `json:"provider"`
	Subject      string     `json:"subject"`
	Email        string     `json:"email,omitempty"`
	LinkedAt     time.Time  `json:"linked_at"`
	LastSignInAt *time.Time `json:"last_sign_in_at,omitempty"`
}
