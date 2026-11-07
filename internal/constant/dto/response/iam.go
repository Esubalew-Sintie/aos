package response

import "time"

// CanResponse answers "may this principal do this action here?".
type CanResponse struct {
	Allowed bool `json:"allowed"`
	// Reason is a stable code, such as "allowed", "no_matching_grant" or
	// "denied_by_grant".
	Reason string `json:"reason"`
	// Grant and Role name what decided it, when a grant did.
	GrantID string `json:"grant_id,omitempty"`
	Role    string `json:"role,omitempty"`
	// DelegationID is the delegation an agent acted through.
	DelegationID string `json:"delegation_id,omitempty"`
	// ApprovalID is set with the reason approval_required: the agent
	// repeats the action with it once a human has approved.
	ApprovalID string `json:"approval_id,omitempty"`
}

type Permission struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Source        string `json:"source"`
	StepUpSeconds int    `json:"step_up_seconds,omitempty"`
	NeedsApproval bool   `json:"needs_approval,omitempty"`
}

type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Source      string   `json:"source"`
	Permissions []string `json:"permissions"`
}

type Resource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// ExternalID is the application's own id for this object.
	ExternalID string `json:"external_id"`
}

type Grant struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principal_id,omitempty"`
	GroupID     string     `json:"group_id,omitempty"`
	Role        string     `json:"role"`
	Resource    Resource   `json:"resource"`
	Effect      string     `json:"effect"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Condition   string     `json:"condition,omitempty"`
}

type CanBatchResponse struct {
	Results []CanResponse `json:"results"`
}

// ExplainResponse says why a decision came out as it did.
type ExplainResponse struct {
	Allowed   bool           `json:"allowed"`
	Reason    string         `json:"reason"`
	DecidedBy *ExplainGrant  `json:"decided_by,omitempty"`
	LookedAt  []Resource     `json:"looked_at"`
	Matched   []ExplainGrant `json:"matched"`
}

type ExplainGrant struct {
	GrantID     string `json:"grant_id"`
	Role        string `json:"role"`
	Effect      string `json:"effect"`
	Conditional bool   `json:"conditional"`
	// Depth is how far above the resource the grant was made. 0 is the resource itself.
	Depth int `json:"depth"`
}

// FilterResponse lists the application's own ids of the resources where
// the permission holds. Conditional holds those allowed only under a
// condition the engine does not evaluate yet.
type FilterResponse struct {
	ResourceType string   `json:"resource_type"`
	Allowed      []string `json:"allowed"`
	Conditional  []string `json:"conditional"`
	// Truncated is true when more exist than were returned.
	Truncated bool `json:"truncated"`
}

type PrincipalEntry struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status"`
	// Through names the grant that gives the right.
	Through ExplainGrant `json:"through"`
}

type PrincipalsResponse struct {
	Principals []PrincipalEntry `json:"principals"`
}

// SimulateResponse says who would lose what if a grant were removed.
type SimulateResponse struct {
	Grant    Grant            `json:"grant"`
	Affected []SimulateEffect `json:"affected"`
}

type SimulateEffect struct {
	PrincipalID string `json:"principal_id"`
	Permission  string `json:"permission"`
	// StillAllowed is true when another grant keeps the permission.
	StillAllowed bool `json:"still_allowed"`
}

type Group struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	OrganizationID string    `json:"organization_id,omitempty"`
	MemberCount    int       `json:"member_count"`
	CreatedAt      time.Time `json:"created_at"`
}
