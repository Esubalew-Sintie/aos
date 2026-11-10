package request

import "github.com/flash-software-technology/aos/internal/constant/errors"

// ListAuditRequest reads the tenant's audit log, newest first. Every
// filter is optional.
type ListAuditRequest struct {
	Limit int
	// Before returns entries older than this sequence number: the
	// next_before of the previous page. 0 starts at the newest.
	Before int64
	// Action matches actions that start with it, such as "user." or "signin".
	Action   string
	ActorID  string
	TargetID string
}

func (r *ListAuditRequest) Validate() error {
	f := fields{}
	if r.Before < 0 {
		f["before"] = "must be a sequence number"
	}
	if len(r.Action) > 200 {
		f["action"] = "is too long"
	}
	if r.ActorID != "" && !validUUID(r.ActorID) {
		f["actor_id"] = "must be a principal id"
	}
	if len(r.TargetID) > 200 {
		f["target_id"] = "is too long"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}
