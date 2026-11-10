package iam

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module/iam/core"
	"github.com/flash-software-technology/aos/platform/postgres"
)

// filterLimit caps how many resource ids one Filter answer carries.
const filterLimit = 1000

// ---------------------------------------------------------------------
// module.Authorizer: checks inside another module's transaction
// ---------------------------------------------------------------------

func (m *iamModule) Check(ctx context.Context, tx pgx.Tx, tenantID, principalID, permission, resourceID string) (bool, string, error) {
	status, err := m.repo.GetPrincipalStatus(ctx, tx, tenantID, principalID)
	if err != nil {
		return false, "", err
	}
	if status == "" {
		return false, core.ReasonUnknownPrincipal, nil
	}
	if status != constant.PrincipalActive {
		return false, core.ReasonPrincipalInactive, nil
	}
	grants, err := m.repo.MatchingGrants(ctx, tx, tenantID, principalID, resourceID, permission, "", m.now())
	if err != nil {
		return false, "", err
	}
	outcome := core.Decide(grants)
	if !outcome.Allowed {
		d := model.Decision{PrincipalID: principalID, Permission: permission, ResourceID: resourceID, ReasonCode: outcome.Reason}
		if outcome.Grant != nil {
			d.GrantID = outcome.Grant.ID
		}
		if err := m.repo.LogDecision(ctx, tx, tenantID, d); err != nil {
			return false, "", err
		}
	}
	return outcome.Allowed, outcome.Reason, nil
}

func (m *iamModule) MayGrant(ctx context.Context, tx pgx.Tx, tenantID, actorID, roleID, resourceID string) (bool, error) {
	held, err := m.repo.ActorPatterns(ctx, tx, tenantID, actorID, resourceID, m.now())
	if err != nil {
		return false, err
	}
	wanted, err := m.repo.RolePatterns(ctx, tx, tenantID, roleID)
	if err != nil {
		return false, err
	}
	return core.Covers(held, wanted), nil
}

// ---------------------------------------------------------------------
// The other questions
// ---------------------------------------------------------------------

func (m *iamModule) CanBatch(ctx context.Context, t *model.Tenant, req request.CanBatchRequest, meta model.RequestMeta) (*response.CanBatchResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	out := &response.CanBatchResponse{Results: make([]response.CanResponse, 0, len(req.Checks))}
	for _, check := range req.Checks {
		res, err := m.Can(ctx, t, check, meta)
		if err != nil {
			return nil, err
		}
		out.Results = append(out.Results, *res)
	}
	return out, nil
}

func (m *iamModule) Explain(ctx context.Context, t *model.Tenant, req request.CanRequest) (*response.ExplainResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	out := &response.ExplainResponse{LookedAt: []response.Resource{}, Matched: []response.ExplainGrant{}}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		status, err := m.repo.GetPrincipalStatus(ctx, tx, t.ID, req.PrincipalID)
		if err != nil {
			return err
		}
		resourceID, _, err := m.repo.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: req.Resource.Type, ID: req.Resource.ID})
		if err != nil {
			return err
		}
		switch {
		case status == "":
			out.Reason = core.ReasonUnknownPrincipal
			return nil
		case status != constant.PrincipalActive:
			out.Reason = core.ReasonPrincipalInactive
			return nil
		case resourceID == "":
			out.Reason = core.ReasonUnknownResource
			return nil
		}
		nodes, err := m.repo.Ancestors(ctx, tx, t.ID, resourceID)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			out.LookedAt = append(out.LookedAt, response.Resource{ID: n.ID, Type: n.Type, ExternalID: n.ExternalID})
		}
		grants, err := m.repo.MatchingGrants(ctx, tx, t.ID, req.PrincipalID, resourceID, req.Permission, "", now)
		if err != nil {
			return err
		}
		for _, g := range grants {
			out.Matched = append(out.Matched, toExplainGrant(g))
		}
		outcome := core.Decide(grants)
		out.Allowed, out.Reason = outcome.Allowed, outcome.Reason
		if outcome.Grant != nil {
			eg := toExplainGrant(*outcome.Grant)
			out.DecidedBy = &eg
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("explain: %w", err)
	}
	return out, nil
}

func (m *iamModule) Filter(ctx context.Context, t *model.Tenant, req request.FilterRequest) (*response.FilterResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	out := &response.FilterResponse{ResourceType: req.ResourceType, Allowed: []string{}, Conditional: []string{}}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		status, err := m.repo.GetPrincipalStatus(ctx, tx, t.ID, req.PrincipalID)
		if err != nil {
			return err
		}
		if status != constant.PrincipalActive {
			return nil // an unknown or inactive principal may see nothing
		}
		allowed, conditional, err := m.repo.AllowedResources(ctx, tx, t.ID, req.PrincipalID, req.Permission, req.ResourceType, m.now(), filterLimit+1)
		if err != nil {
			return err
		}
		if len(allowed)+len(conditional) > filterLimit {
			out.Truncated = true
			if len(allowed) > filterLimit {
				allowed = allowed[:filterLimit]
			}
		}
		if allowed != nil {
			out.Allowed = allowed
		}
		if conditional != nil {
			out.Conditional = conditional
		}
		return m.repo.TouchPermission(ctx, tx, t.ID, req.Permission, m.now())
	})
	if err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	return out, nil
}

func (m *iamModule) ListPrincipals(ctx context.Context, t *model.Tenant, req request.ListPrincipalsRequest) (*response.PrincipalsResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	out := &response.PrincipalsResponse{Principals: []response.PrincipalEntry{}}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		resourceID, _, err := m.repo.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: req.Resource.Type, ID: req.Resource.ID})
		if err != nil {
			return err
		}
		if resourceID == "" {
			return errors.NotFound("resource")
		}
		// Everyone with an allow is a candidate. Each is then decided in
		// full, so a deny anywhere above still removes them.
		candidates, err := m.repo.CandidatePrincipals(ctx, tx, t.ID, resourceID, req.Permission, now)
		if err != nil {
			return err
		}
		for _, p := range candidates {
			if p.Status != constant.PrincipalActive {
				continue
			}
			grants, err := m.repo.MatchingGrants(ctx, tx, t.ID, p.ID, resourceID, req.Permission, "", now)
			if err != nil {
				return err
			}
			outcome := core.Decide(grants)
			if !outcome.Allowed {
				continue
			}
			out.Principals = append(out.Principals, response.PrincipalEntry{
				ID: p.ID, Kind: p.Kind, Email: p.Email, Name: p.Name, Status: p.Status,
				Through: toExplainGrant(*outcome.Grant),
			})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list principals", err)
	}
	return out, nil
}

func (m *iamModule) Simulate(ctx context.Context, t *model.Tenant, req request.SimulateRequest) (*response.SimulateResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.SimulateResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		grant, principals, err := m.repo.GetGrant(ctx, tx, t.ID, req.GrantID)
		if err != nil {
			return err
		}
		if grant == nil {
			return errors.NotFound("grant")
		}
		resourceID, _, err := m.repo.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: grant.ResourceType, ID: grant.ResourceID})
		if err != nil {
			return err
		}
		roleID, _, err := m.repo.GetRoleByName(ctx, tx, t.ID, grant.Role)
		if err != nil {
			return err
		}
		patterns, err := m.repo.RolePatterns(ctx, tx, t.ID, roleID)
		if err != nil {
			return err
		}
		out = &response.SimulateResponse{
			Grant: response.Grant{
				ID: grant.ID, Role: grant.Role, Effect: grant.Effect, ExpiresAt: grant.ExpiresAt,
				Resource: response.Resource{ID: resourceID, Type: grant.ResourceType, ExternalID: grant.ResourceID},
			},
			Affected: []response.SimulateEffect{},
		}
		if grant.Effect != constant.EffectAllow {
			// Removing a deny takes nothing away from anyone.
			return nil
		}
		// For each person the grant covers and each permission it carries:
		// would another grant still allow it, on the same resource?
		for _, principalID := range principals {
			for _, pattern := range patterns {
				others, err := m.repo.MatchingGrants(ctx, tx, t.ID, principalID, resourceID, pattern, grant.ID, now)
				if err != nil {
					return err
				}
				out.Affected = append(out.Affected, response.SimulateEffect{
					PrincipalID: principalID, Permission: pattern, StillAllowed: core.Decide(others).Allowed,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("simulate", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------

func (m *iamModule) PutGroup(ctx context.Context, t *model.Tenant, req request.PutGroupRequest, meta model.RequestMeta) (*response.Group, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var id string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		if req.OrganizationID != "" {
			ok, err := m.repo.IsUnder(ctx, tx, t.ID, req.OrganizationID, req.OrganizationID)
			if err != nil {
				return err
			}
			if !ok {
				return errors.Validation(map[string]string{"organization_id": "does not exist"})
			}
		}
		if id, err = m.repo.UpsertGroup(ctx, tx, t.ID, req.Name, req.OrganizationID); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "group.saved", Result: model.AuditSuccess, TargetType: "group", TargetID: id,
			OrganizationID: req.OrganizationID, Data: map[string]any{"name": req.Name}, RequestID: meta.RequestID,
		})
	})
	if err != nil {
		return nil, passThrough("put group", err)
	}
	return &response.Group{ID: id, Name: req.Name, OrganizationID: req.OrganizationID, CreatedAt: m.now()}, nil
}

func (m *iamModule) ListGroups(ctx context.Context, t *model.Tenant, organizationID string) ([]response.Group, error) {
	var groups []model.Group
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		groups, err = m.repo.ListGroups(ctx, tx, t.ID, organizationID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	out := make([]response.Group, 0, len(groups))
	for _, g := range groups {
		out = append(out, response.Group{ID: g.ID, Name: g.Name, OrganizationID: g.OrganizationID, MemberCount: g.MemberCount, CreatedAt: g.CreatedAt})
	}
	return out, nil
}

func (m *iamModule) DeleteGroup(ctx context.Context, t *model.Tenant, groupID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(groupID) {
		return errors.NotFound("group")
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		found, err := m.repo.DeleteGroup(ctx, tx, t.ID, groupID)
		if err != nil {
			return err
		}
		if !found {
			return errors.NotFound("group")
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "group.deleted", Result: model.AuditSuccess, TargetType: "group", TargetID: groupID, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "group.deleted", map[string]any{"group_id": groupID})
	})
	return passThrough("delete group", err)
}

func (m *iamModule) AddGroupMember(ctx context.Context, t *model.Tenant, groupID, principalID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(groupID) {
		return errors.NotFound("group")
	}
	if !postgres.IsUUID(principalID) {
		return errors.Validation(map[string]string{"principal_id": "must be an id"})
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		exists, err := m.repo.GroupExists(ctx, tx, t.ID, groupID)
		if err != nil {
			return err
		}
		if !exists {
			return errors.NotFound("group")
		}
		status, err := m.repo.GetPrincipalStatus(ctx, tx, t.ID, principalID)
		if err != nil {
			return err
		}
		if status == "" {
			return errors.Validation(map[string]string{"principal_id": "does not exist"})
		}
		if err := m.repo.AddGroupMember(ctx, tx, t.ID, groupID, principalID); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "group.member_added", Result: model.AuditSuccess, TargetType: "group", TargetID: groupID,
			Data: map[string]any{"principal_id": principalID}, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "group.member_added", map[string]any{"group_id": groupID, "principal_id": principalID})
	})
	return passThrough("add group member", err)
}

func (m *iamModule) RemoveGroupMember(ctx context.Context, t *model.Tenant, groupID, principalID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(groupID) || !postgres.IsUUID(principalID) {
		return errors.NotFound("group member")
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		found, err := m.repo.RemoveGroupMember(ctx, tx, t.ID, groupID, principalID)
		if err != nil {
			return err
		}
		if !found {
			return errors.NotFound("group member")
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "group.member_removed", Result: model.AuditSuccess, TargetType: "group", TargetID: groupID,
			Data: map[string]any{"principal_id": principalID}, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "group.member_removed", map[string]any{"group_id": groupID, "principal_id": principalID})
	})
	return passThrough("remove group member", err)
}

func toExplainGrant(g model.MatchedGrant) response.ExplainGrant {
	return response.ExplainGrant{GrantID: g.ID, Role: g.RoleName, Effect: g.Effect, Conditional: g.Conditional, Depth: g.Depth}
}
