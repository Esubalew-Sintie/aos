package response

import "time"

type SSOConnection struct {
	ID                   string         `json:"id"`
	OrganizationID       string         `json:"organization_id"`
	Name                 string         `json:"name,omitempty"`
	Protocol             string         `json:"protocol"`
	Status               string         `json:"status"`
	Issuer               string         `json:"issuer,omitempty"`
	ClientID             string         `json:"client_id,omitempty"`
	SAMLEntityID         string         `json:"saml_entity_id,omitempty"`
	SAMLSSOURL           string         `json:"saml_sso_url,omitempty"`
	TrustIdPSecondFactor bool           `json:"trust_idp_second_factor"`
	DefaultRole          string         `json:"default_role,omitempty"`
	Mappings             []GroupMapping `json:"mappings"`
	Domains              []Domain       `json:"domains"`
	LastTest             map[string]any `json:"last_test,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	ActivatedAt          *time.Time     `json:"activated_at,omitempty"`
	// What the IT admin pastes into the identity provider.
	RedirectURI string `json:"redirect_uri"`
	SCIMURL     string `json:"scim_url"`
}

type GroupMapping struct {
	Group    string   `json:"group"`
	Role     string   `json:"role"`
	Resource Resource `json:"resource"`
}

type Domain struct {
	ID         string     `json:"id"`
	Domain     string     `json:"domain"`
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	// Record is the DNS TXT record to add: name and value.
	RecordName  string `json:"record_name"`
	RecordValue string `json:"record_value"`
}

// SetupLink is handed to the IT admin. It is shown once.
type SetupLink struct {
	ConnectionID string    `json:"connection_id"`
	Token        string    `json:"token"`
	Link         string    `json:"link,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type SSOStart struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
	ConnectionID     string `json:"connection_id"`
}

type OrgPolicies struct {
	MFARequired           bool     `json:"mfa_required"`
	SessionMaxSeconds     int      `json:"session_max_seconds,omitempty"`
	AllowedAuthMethods    []string `json:"allowed_auth_methods"`
	IPAllowlist           []string `json:"ip_allowlist"`
	EnforceSSO            bool     `json:"enforce_sso"`
	BreakGlassPrincipalID string   `json:"break_glass_principal_id,omitempty"`
}

type Directory struct {
	ID            string     `json:"id"`
	DefaultRole   string     `json:"default_role,omitempty"`
	SCIMURL       string     `json:"scim_url"`
	CreatedAt     time.Time  `json:"created_at"`
	LastRequestAt *time.Time `json:"last_request_at,omitempty"`
	DisabledAt    *time.Time `json:"disabled_at,omitempty"`
	// Token is shown once.
	Token string `json:"token,omitempty"`
}
