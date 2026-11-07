package request

import (
	"net/url"

	"github.com/flash-softeware/aos/internal/constant/errors"
)

// CreateWebhookRequest registers an address the engine calls.
//
//   - kind "events": the engine POSTs each matching event after it happened.
//   - kind "before_hook": the engine POSTs before an action and waits for
//     {"allow": true}. No answer within the time limit means the action is
//     refused.
type CreateWebhookRequest struct {
	Kind  string `json:"kind"`
	URL   string `json:"url"`
	Label string `json:"label"`
	// EventTypes lists the events or hooks this endpoint wants. Empty
	// means all of them.
	EventTypes []string `json:"event_types"`
	TimeoutMs  int      `json:"timeout_ms"`
	// OrganizationID is required for an audit_export endpoint: only that
	// organization's entries are sent (ENT-8).
	OrganizationID string `json:"organization_id"`
}

func (r *CreateWebhookRequest) Validate() error {
	if r.Kind == "" {
		r.Kind = "events"
	}
	if r.TimeoutMs == 0 {
		r.TimeoutMs = 2000
	}
	if len(r.EventTypes) == 0 {
		r.EventTypes = []string{"*"}
	}
	f := fields{}
	if r.Kind != "events" && r.Kind != "before_hook" && r.Kind != "audit_export" {
		f["kind"] = "must be events, before_hook or audit_export"
	}
	if r.Kind == "audit_export" && !validUUID(r.OrganizationID) {
		f["organization_id"] = "an audit export belongs to one organization"
	}
	if r.OrganizationID != "" && !validUUID(r.OrganizationID) {
		f["organization_id"] = "must be an id"
	}
	u, err := url.Parse(r.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		f["url"] = "must be an https address"
	}
	if r.TimeoutMs < 200 || r.TimeoutMs > 10000 {
		f["timeout_ms"] = "must be between 200 and 10000"
	}
	if len(r.Label) > 100 {
		f["label"] = "must be at most 100 characters"
	}
	for _, t := range r.EventTypes {
		if t == "" || len(t) > 100 {
			f["event_types"] = "each must be an event name or *"
			break
		}
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}
