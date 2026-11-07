package response

import "time"

type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Member struct {
	PrincipalID string   `json:"principal_id"`
	Email       string   `json:"email,omitempty"`
	Name        string   `json:"name,omitempty"`
	Status      string   `json:"status"`
	Roles       []string `json:"roles"`
}

type Invitation struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	Role             string    `json:"role"`
	Resource         Resource  `json:"resource"`
	OrganizationID   string    `json:"organization_id,omitempty"`
	OrganizationName string    `json:"organization_name,omitempty"`
	InvitedBy        string    `json:"invited_by,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
}

// InvitationPreview is what the invited person sees before deciding.
type InvitationPreview struct {
	Email            string    `json:"email"`
	Role             string    `json:"role"`
	OrganizationName string    `json:"organization_name"`
	InvitedBy        string    `json:"invited_by,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	// AccountExists tells the screen whether to show sign-in or sign-up.
	AccountExists bool `json:"account_exists"`
}
