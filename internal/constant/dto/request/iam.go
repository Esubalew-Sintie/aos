package request

import (
	"strings"
	"time"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/errors"
)

// ResourceRef names a resource by its type and the application's own id.
// {"type": "tenant", "id": "root"} is the top of the tenant.
type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (r ResourceRef) check(name string, f fields) {
	if r.Type == "" || r.ID == "" {
		f[name] = "needs a type and an id"
	} else if len(r.Type) > 100 || len(r.ID) > 200 {
		f[name] = "is too long"
	}
}

// CanRequest asks "may this principal do this action on this resource?".
type CanRequest struct {
	PrincipalID string      `json:"principal_id"`
	Permission  string      `json:"permission"`
	Resource    ResourceRef `json:"resource"`
	// SessionID lets a permission that needs a fresh second factor
	// (SIGN-9) see when the session last gave one. It is the "sid" claim
	// of the signed token.
	SessionID string `json:"session_id"`
	// Scopes narrow the answer, as an API key's scopes do (MACH-3).
	Scopes []string `json:"scopes"`
	// AgentID names an agent acting for the principal through a
	// delegation (MACH-8).
	AgentID string `json:"agent_id"`
	// ApprovalID repeats an action a human has approved (MACH-9).
	// Details are the exact values of the action; the approval is bound
	// to them.
	ApprovalID string         `json:"approval_id"`
	Details    map[string]any `json:"details"`
	// Context is what grant conditions read (PERM-9), such as
	// {"request": {"amount": 500}}.
	Context map[string]any `json:"context"`
}

func (r *CanRequest) Validate() error {
	f := fields{}
	if !validUUID(r.PrincipalID) {
		f["principal_id"] = "must be an id"
	}
	if r.SessionID != "" && !validUUID(r.SessionID) {
		f["session_id"] = "must be an id"
	}
	if r.AgentID != "" && !validUUID(r.AgentID) {
		f["agent_id"] = "must be an id"
	}
	if r.ApprovalID != "" && !validUUID(r.ApprovalID) {
		f["approval_id"] = "must be an id"
	}
	for _, p := range r.Scopes {
		if !validPermissionPattern(p) {
			f["scopes"] = "each must be a permission name, a prefix such as payment.*, or *"
			break
		}
	}
	if !validPermissionName(r.Permission) {
		f["permission"] = "must be a dotted name such as payment.refund"
	}
	r.Resource.check("resource", f)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type PutPermissionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// StepUpSeconds, when set, means a check passes only for a session
	// whose second factor is no older than this (SIGN-9).
	StepUpSeconds int `json:"step_up_seconds"`
	// NeedsApproval means an agent must wait for a human (MACH-9).
	NeedsApproval bool `json:"needs_approval"`
}

func (r *PutPermissionRequest) Validate() error {
	f := fields{}
	if !validPermissionName(r.Name) {
		f["name"] = "must be a dotted name such as payment.refund"
	}
	if r.StepUpSeconds < 0 || r.StepUpSeconds > 24*3600 {
		f["step_up_seconds"] = "must be between 0 and 86400"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type PutRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Permissions are exact names, prefixes such as "payment.*", or "*".
	Permissions []string `json:"permissions"`
}

func (r *PutRoleRequest) Validate() error {
	f := fields{}
	f.require("name", r.Name)
	if len(r.Name) > 100 {
		f["name"] = "must be at most 100 characters"
	}
	if len(r.Permissions) > 500 {
		f["permissions"] = "holds too many entries"
	}
	for _, p := range r.Permissions {
		if !validPermissionPattern(p) {
			f["permissions"] = "each must be a permission name, a prefix such as payment.*, or *"
			break
		}
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type CreateResourceRequest struct {
	Type string `json:"type"`
	// ID is the application's own id for the object.
	ID string `json:"id"`
	// Parent is the node it sits under. Empty means the tenant root.
	Parent      *ResourceRef `json:"parent"`
	DisplayName string       `json:"display_name"`
}

func (r *CreateResourceRequest) Validate() error {
	f := fields{}
	ResourceRef{Type: r.Type, ID: r.ID}.check("type", f)
	if r.Type == constant.ResourceTypeTenant {
		f["type"] = "is reserved for the tenant root"
	}
	if r.Parent != nil {
		r.Parent.check("parent", f)
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type CreateGrantRequest struct {
	// Exactly one of PrincipalID and GroupID.
	PrincipalID string      `json:"principal_id"`
	GroupID     string      `json:"group_id"`
	Role        string      `json:"role"`
	Resource    ResourceRef `json:"resource"`
	// Effect is "allow" or "deny". Empty means "allow".
	Effect    string     `json:"effect"`
	ExpiresAt *time.Time `json:"expires_at"`
	Reason    string     `json:"reason"`
	// Condition is an expression on the request's context (PERM-9).
	Condition string `json:"condition"`
}

func (r *CreateGrantRequest) Validate() error {
	if r.Effect == "" {
		r.Effect = constant.EffectAllow
	}
	f := fields{}
	switch {
	case r.PrincipalID == "" && r.GroupID == "":
		f["principal_id"] = "principal_id or group_id is required"
	case r.PrincipalID != "" && r.GroupID != "":
		f["principal_id"] = "give principal_id or group_id, not both"
	case r.PrincipalID != "" && !validUUID(r.PrincipalID):
		f["principal_id"] = "must be an id"
	case r.GroupID != "" && !validUUID(r.GroupID):
		f["group_id"] = "must be an id"
	}
	f.require("role", r.Role)
	r.Resource.check("resource", f)
	if r.Effect != constant.EffectAllow && r.Effect != constant.EffectDeny {
		f["effect"] = "must be allow or deny"
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(time.Now()) {
		f["expires_at"] = "must be in the future"
	}
	r.Condition = strings.TrimSpace(r.Condition)
	if len(r.Condition) > 2000 {
		f["condition"] = "is too long"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type CanBatchRequest struct {
	Checks []CanRequest `json:"checks"`
}

func (r *CanBatchRequest) Validate() error {
	if len(r.Checks) == 0 || len(r.Checks) > 100 {
		return errors.Validation(map[string]string{"checks": "must hold 1 to 100 checks"})
	}
	for i := range r.Checks {
		if err := r.Checks[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// FilterRequest asks on which resources of a type a principal holds a
// permission. The answer goes into the application's own list query.
type FilterRequest struct {
	PrincipalID  string `json:"principal_id"`
	Permission   string `json:"permission"`
	ResourceType string `json:"resource_type"`
}

func (r *FilterRequest) Validate() error {
	f := fields{}
	if !validUUID(r.PrincipalID) {
		f["principal_id"] = "must be an id"
	}
	if !validPermissionName(r.Permission) {
		f["permission"] = "must be a dotted name such as payment.refund"
	}
	if r.ResourceType == "" || len(r.ResourceType) > 100 {
		f["resource_type"] = "is required"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// ListPrincipalsRequest asks who may do an action on a resource.
type ListPrincipalsRequest struct {
	Permission string      `json:"permission"`
	Resource   ResourceRef `json:"resource"`
}

func (r *ListPrincipalsRequest) Validate() error {
	f := fields{}
	if !validPermissionName(r.Permission) {
		f["permission"] = "must be a dotted name such as payment.refund"
	}
	r.Resource.check("resource", f)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// SimulateRequest asks what would change if a grant were removed.
type SimulateRequest struct {
	GrantID string `json:"grant_id"`
}

func (r *SimulateRequest) Validate() error {
	if !validUUID(r.GrantID) {
		return errors.Validation(map[string]string{"grant_id": "must be an id"})
	}
	return nil
}

type PutGroupRequest struct {
	Name string `json:"name"`
	// OrganizationID, when set, makes the group belong to that organization.
	OrganizationID string `json:"organization_id"`
}

func (r *PutGroupRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	f := fields{}
	f.require("name", r.Name)
	if len(r.Name) > 100 {
		f["name"] = "must be at most 100 characters"
	}
	if r.OrganizationID != "" && !validUUID(r.OrganizationID) {
		f["organization_id"] = "must be an id"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type GroupMemberRequest struct {
	PrincipalID string `json:"principal_id"`
}

func (r *GroupMemberRequest) Validate() error {
	if !validUUID(r.PrincipalID) {
		return errors.Validation(map[string]string{"principal_id": "must be an id"})
	}
	return nil
}

// ListGrantsRequest lists the grants of a principal, or on a resource.
// At least one of the two is needed.
type ListGrantsRequest struct {
	PrincipalID  string
	ResourceType string
	ResourceID   string
	Limit        int
}

func (r *ListGrantsRequest) Validate() error {
	f := fields{}
	hasResource := r.ResourceType != "" || r.ResourceID != ""
	switch {
	case r.PrincipalID == "" && !hasResource:
		f["principal_id"] = "or resource_type and resource_id are required"
	case r.PrincipalID != "" && !validUUID(r.PrincipalID):
		f["principal_id"] = "must be a principal id"
	}
	if hasResource {
		ResourceRef{Type: r.ResourceType, ID: r.ResourceID}.check("resource_id", f)
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}
