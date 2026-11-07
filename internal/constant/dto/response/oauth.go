package response

import "time"

type OAuthClient struct {
	ID                 string     `json:"id"`
	ClientID           string     `json:"client_id"`
	Name               string     `json:"name"`
	Description        string     `json:"description,omitempty"`
	Kind               string     `json:"kind"`
	RedirectURIs       []string   `json:"redirect_uris"`
	AllowedScopes      []string   `json:"allowed_scopes"`
	GrantTypes         []string   `json:"grant_types"`
	ServicePrincipalID string     `json:"service_principal_id,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	DisabledAt         *time.Time `json:"disabled_at,omitempty"`
	// ClientSecret is shown once, when it is made or rotated.
	ClientSecret string `json:"client_secret,omitempty"`
}

// AuthorizationRequestView is what the consent screen shows.
type AuthorizationRequestView struct {
	RequestID    string    `json:"request_id"`
	ClientName   string    `json:"client_name"`
	ClientID     string    `json:"client_id"`
	Scopes       []string  `json:"scopes"`
	Resource     string    `json:"resource,omitempty"`
	ConsentGiven bool      `json:"consent_given"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ConsentResult is where the browser goes next.
type ConsentResult struct {
	RedirectTo string `json:"redirect_to"`
}

type Consent struct {
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	ClientKey  string    `json:"client_key"`
	Scopes     []string  `json:"scopes"`
	GrantedAt  time.Time `json:"granted_at"`
}

type DeviceApproval struct {
	ClientName string   `json:"client_name"`
	Scopes     []string `json:"scopes"`
	Status     string   `json:"status"`
}
