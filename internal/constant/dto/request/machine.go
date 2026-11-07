package request

import (
	"strings"
	"time"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/errors"
)

// CreateMachineRequest makes a service account or an agent (MACH-1, MACH-8).
type CreateMachineRequest struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	// OwnerPrincipalID is who answers for it. Required for an agent.
	OwnerPrincipalID string `json:"owner_principal_id"`
}

func (r *CreateMachineRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	r.Purpose = strings.TrimSpace(r.Purpose)
	f := fields{}
	f.require("name", r.Name)
	if len(r.Name) > 200 || len(r.Purpose) > 2000 {
		f["name"] = "is too long"
	}
	if r.OwnerPrincipalID != "" && !validUUID(r.OwnerPrincipalID) {
		f["owner_principal_id"] = "must be an id"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// CreateAPIKeyRequest issues a key for a principal (MACH-2). Scopes can
// only narrow what the principal holds.
type CreateAPIKeyRequest struct {
	PrincipalID string     `json:"principal_id"`
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

func (r *CreateAPIKeyRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	f := fields{}
	if r.PrincipalID != "" && !validUUID(r.PrincipalID) {
		f["principal_id"] = "must be an id"
	}
	f.require("name", r.Name)
	if len(r.Name) > 200 {
		f["name"] = "must be at most 200 characters"
	}
	if len(r.Scopes) == 0 {
		r.Scopes = []string{"*"}
	}
	if len(r.Scopes) > 200 {
		f["scopes"] = "holds too many entries"
	}
	for _, p := range r.Scopes {
		if !validPermissionPattern(p) {
			f["scopes"] = "each must be a permission name, a prefix such as payment.*, or *"
			break
		}
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(time.Now()) {
		f["expires_at"] = "must be in the future"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// CheckAPIKeyRequest identifies a key and asks a permission question in
// one call (MACH-3).
type CheckAPIKeyRequest struct {
	Key        string         `json:"key"`
	Permission string         `json:"permission"`
	Resource   *ResourceRef   `json:"resource"`
	Details    map[string]any `json:"details"`
	ApprovalID string         `json:"approval_id"`
}

func (r *CheckAPIKeyRequest) Validate() error {
	f := fields{}
	f.require("key", r.Key)
	if r.Permission != "" && !validPermissionName(r.Permission) {
		f["permission"] = "must be a dotted name such as payment.refund"
	}
	if r.Permission != "" && r.Resource == nil {
		f["resource"] = "is required with a permission"
	}
	if r.Resource != nil {
		r.Resource.check("resource", f)
	}
	if r.ApprovalID != "" && !validUUID(r.ApprovalID) {
		f["approval_id"] = "must be an id"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// CreateDelegationRequest lets an agent act for the signed-in person
// (MACH-8): these permissions, on this resource, for this long.
type CreateDelegationRequest struct {
	AgentID  string      `json:"agent_id"`
	Scopes   []string    `json:"scopes"`
	Resource ResourceRef `json:"resource"`
	Hours    int         `json:"hours"`
}

func (r *CreateDelegationRequest) Validate() error {
	f := fields{}
	if !validUUID(r.AgentID) {
		f["agent_id"] = "must be an id"
	}
	if len(r.Scopes) == 0 || len(r.Scopes) > 200 {
		f["scopes"] = "must hold 1 to 200 entries"
	}
	for _, p := range r.Scopes {
		if !validPermissionPattern(p) {
			f["scopes"] = "each must be a permission name, a prefix such as payment.*, or *"
			break
		}
	}
	r.Resource.check("resource", f)
	if r.Hours <= 0 || r.Hours > constant.DelegationMaxHours {
		f["hours"] = "must be between 1 and 168"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// ReasonRequest carries the written reason a status change needs.
type ReasonRequest struct {
	Reason string `json:"reason"`
}

func (r *ReasonRequest) Validate() error {
	r.Reason = strings.TrimSpace(r.Reason)
	f := fields{}
	f.require("reason", r.Reason)
	if len(r.Reason) > 5000 {
		f["reason"] = "must be at most 5000 characters"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}
