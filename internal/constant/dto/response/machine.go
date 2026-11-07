package response

import "time"

type Machine struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
	Purpose   string     `json:"purpose,omitempty"`
	OwnerID   string     `json:"owner_principal_id,omitempty"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	Suspended *time.Time `json:"suspended_at,omitempty"`
}

type APIKey struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principal_id"`
	Name        string     `json:"name"`
	PublicID    string     `json:"public_id"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreatedAPIKey carries the key itself, once.
type CreatedAPIKey struct {
	APIKey
	Key string `json:"key"`
}

// APIKeyCheck is who a key is, and the answer to its question.
type APIKeyCheck struct {
	KeyID       string   `json:"key_id"`
	PrincipalID string   `json:"principal_id"`
	Kind        string   `json:"kind"`
	Scopes      []string `json:"scopes"`
	// The answer, when a permission was asked about.
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
}

type Delegation struct {
	ID        string     `json:"id"`
	AgentID   string     `json:"agent_id"`
	UserID    string     `json:"user_id"`
	Scopes    []string   `json:"scopes"`
	Resource  Resource   `json:"resource"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type Approval struct {
	ID         string         `json:"id"`
	AgentID    string         `json:"agent_id"`
	AgentName  string         `json:"agent_name,omitempty"`
	UserID     string         `json:"user_id"`
	Permission string         `json:"permission"`
	Resource   Resource       `json:"resource"`
	Details    map[string]any `json:"details"`
	Status     string         `json:"status"`
	ExpiresAt  time.Time      `json:"expires_at"`
	DecidedAt  *time.Time     `json:"decided_at,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// AgentRevocation says what the kill switch removed.
type AgentRevocation struct {
	Keys        int64 `json:"api_keys_revoked"`
	Delegations int64 `json:"delegations_revoked"`
	Grants      int64 `json:"grants_removed"`
}
