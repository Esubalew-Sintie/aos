package response

import "time"

// AuditRecord is one entry of the tenant's audit log. ActorType is the
// kind of principal who acted ("user", "service", "agent", ...), or
// "system" when no principal did. ActorEmail is set for a user.
type AuditRecord struct {
	Seq            int64     `json:"seq"`
	OccurredAt     time.Time `json:"occurred_at"`
	Action         string    `json:"action"`
	Result         string    `json:"result"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	ActorType      string    `json:"actor_type"`
	ActorID        string    `json:"actor_id,omitempty"`
	ActorEmail     string    `json:"actor_email,omitempty"`
	TargetType     string    `json:"target_type,omitempty"`
	TargetID       string    `json:"target_id,omitempty"`
	OrganizationID string    `json:"organization_id,omitempty"`
	IP             string    `json:"ip,omitempty"`
}

// AuditPage is one page of the audit log, newest first. NextBefore is the
// "before" for the next page, and absent on the last one.
type AuditPage struct {
	Entries    []AuditRecord `json:"entries"`
	NextBefore int64         `json:"next_before,omitempty"`
}
