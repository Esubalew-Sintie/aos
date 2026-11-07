package response

import "time"

type ImportResult struct {
	Created int               `json:"created"`
	Skipped []ImportSkip      `json:"skipped"`
	IDs     map[string]string `json:"ids"`
}

type ImportSkip struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// Archive is the encrypted tenant, as text.
type Archive struct {
	Format    string         `json:"format"`
	Archive   string         `json:"archive"`
	CreatedAt time.Time      `json:"created_at"`
	Counts    map[string]int `json:"counts"`
}

type ArchiveImport struct {
	Counts map[string]int `json:"counts"`
}

type AccessReview struct {
	ID             string             `json:"id"`
	OrganizationID string             `json:"organization_id"`
	Status         string             `json:"status"`
	ReviewerID     string             `json:"reviewer_principal_id,omitempty"`
	DueAt          *time.Time         `json:"due_at,omitempty"`
	CompletedAt    *time.Time         `json:"completed_at,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	Items          []AccessReviewItem `json:"items,omitempty"`
	Undecided      int                `json:"undecided"`
}

type AccessReviewItem struct {
	ID          string     `json:"id"`
	GrantID     string     `json:"grant_id"`
	PrincipalID string     `json:"principal_id,omitempty"`
	GroupID     string     `json:"group_id,omitempty"`
	Who         string     `json:"who"`
	Role        string     `json:"role"`
	Resource    Resource   `json:"resource"`
	Effect      string     `json:"effect"`
	Decision    string     `json:"decision,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	Gone        bool       `json:"gone,omitempty"`
}
