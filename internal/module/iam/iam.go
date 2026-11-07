// Package iam is permissions, roles, resources, grants and the
// permission check.
package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/module"
	authcore "github.com/flash-softeware/aos/internal/module/auth/core"
	"github.com/flash-softeware/aos/internal/module/iam/core"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
)

// allowSampleRate is the share of allow decisions written to the
// decision log. Every deny is written.
const allowSampleRate = 0.01

type iamModule struct {
	meter    module.UsageMeter // nil in the package modes
	machines storage.MachineRepository
	users    storage.AuthRepository
	db       *postgres.DB
	repo     storage.IAMRepository
	audit    storage.AuditRepository
	notify   module.Notification
	now      func() time.Time
	log      logger.Logger
}

func NewIAMModule(db *postgres.DB, repo storage.IAMRepository, machines storage.MachineRepository, users storage.AuthRepository,
	audit storage.AuditRepository, notify module.Notification, meter module.UsageMeter, now func() time.Time, log logger.Logger) module.IAM {
	return &iamModule{db: db, repo: repo, machines: machines, users: users, audit: audit, notify: notify, meter: meter, now: now, log: log}
}

func (m *iamModule) Can(ctx context.Context, t *model.Tenant, req request.CanRequest, meta model.RequestMeta) (*response.CanResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	ref := model.ResourceRef{Type: req.Resource.Type, ID: req.Resource.ID}

	var (
		outcome      core.Outcome
		delegationID string
		approvalID   string
	)
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		status, err := m.repo.GetPrincipalStatus(ctx, tx, t.ID, req.PrincipalID)
		if err != nil {
			return err
		}
		resourceID, _, err := m.repo.FindResource(ctx, tx, t.ID, ref)
		if err != nil {
			return err
		}

		switch {
		case status == "":
			outcome = core.Outcome{Reason: core.ReasonUnknownPrincipal}
		case status != constant.PrincipalActive:
			// A suspended or deleted principal is denied everything.
			outcome = core.Outcome{Reason: core.ReasonPrincipalInactive}
		case resourceID == "":
			outcome = core.Outcome{Reason: core.ReasonUnknownResource}
		default:
			// An agent acting for the principal needs a delegation that
			// covers the resource and the permission (MACH-8).
			delegationID, outcome, err = m.delegated(ctx, tx, t.ID, req, resourceID, now)
			if err != nil {
				return err
			}
			if outcome.Reason == "" {
				grants, err := m.repo.MatchingGrants(ctx, tx, t.ID, req.PrincipalID, resourceID, req.Permission, "", now)
				if err != nil {
					return err
				}
				outcome = core.DecideWith(grants, req.Context)
			}
			// A key's scopes can only narrow (MACH-3).
			if outcome.Allowed && len(req.Scopes) > 0 && !core.Covers(req.Scopes, []string{req.Permission}) {
				outcome = core.Outcome{Allowed: false, Reason: core.ReasonOutsideScope, Grant: outcome.Grant}
			}
			if outcome.Allowed {
				// A permission that needs a fresh second factor passes
				// only for a session that gave one recently enough.
				fresh, err := m.stepUpSatisfied(ctx, tx, t.ID, req.Permission, req.SessionID, now)
				if err != nil {
					return err
				}
				if !fresh {
					outcome = core.Outcome{Allowed: false, Reason: core.ReasonStepUpRequired, Grant: outcome.Grant}
				}
			}
			if outcome.Allowed {
				// A sensitive action by an agent waits for a human (MACH-9).
				approvalID, outcome, err = m.approved(ctx, tx, t, req, resourceID, outcome, now, meta)
				if err != nil {
					return err
				}
			}
		}

		if err := m.repo.TouchPermission(ctx, tx, t.ID, req.Permission, now); err != nil {
			return err
		}
		// Every deny is logged. Allows are sampled.
		if !outcome.Allowed || rand.Float64() < allowSampleRate {
			d := model.Decision{
				Permission: req.Permission, ResourceID: resourceID,
				Allowed: outcome.Allowed, ReasonCode: outcome.Reason, RequestID: meta.RequestID,
			}
			if status != "" {
				d.PrincipalID = req.PrincipalID
			}
			if outcome.Grant != nil {
				d.GrantID = outcome.Grant.ID
			}
			if err := m.repo.LogDecision(ctx, tx, t.ID, d); err != nil {
				return err
			}
		}
		if m.meter != nil {
			return m.meter.Count(ctx, tx, t.ID, constant.MetricChecks)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("can", err)
	}
	m.notify.Wake()

	out := &response.CanResponse{Allowed: outcome.Allowed, Reason: outcome.Reason, DelegationID: delegationID, ApprovalID: approvalID}
	if outcome.Grant != nil {
		out.GrantID = outcome.Grant.ID
		out.Role = outcome.Grant.RoleName
	}
	return out, nil
}

// delegated applies MACH-8 when an agent is named: the agent must be a
// live agent, and a delegation from the principal to it must cover the
// resource and the permission. The answer is then the principal's own.
func (m *iamModule) delegated(ctx context.Context, tx pgx.Tx, tenantID string, req request.CanRequest, resourceID string, now time.Time) (string, core.Outcome, error) {
	if req.AgentID == "" {
		return "", core.Outcome{}, nil
	}
	kind, err := m.repo.GetPrincipalKind(ctx, tx, tenantID, req.AgentID)
	if err != nil {
		return "", core.Outcome{}, err
	}
	status, err := m.repo.GetPrincipalStatus(ctx, tx, tenantID, req.AgentID)
	if err != nil {
		return "", core.Outcome{}, err
	}
	if kind != constant.PrincipalKindAgent || status != constant.PrincipalActive {
		return "", core.Outcome{Reason: core.ReasonPrincipalInactive}, nil
	}
	delegations, err := m.machines.LiveDelegations(ctx, tx, tenantID, req.AgentID, req.PrincipalID, resourceID, now)
	if err != nil {
		return "", core.Outcome{}, err
	}
	if len(delegations) == 0 {
		return "", core.Outcome{Reason: core.ReasonNoDelegation}, nil
	}
	for _, d := range delegations {
		if core.Covers(d.Scopes, []string{req.Permission}) {
			return d.ID, core.Outcome{}, nil
		}
	}
	return "", core.Outcome{Reason: core.ReasonOutsideDelegation}, nil
}

// approved applies MACH-9 when the actor is an agent and the permission
// needs a human: with an approval id, the approval is spent; without one,
// a request is made and the person is told.
func (m *iamModule) approved(ctx context.Context, tx pgx.Tx, t *model.Tenant, req request.CanRequest, resourceID string, outcome core.Outcome, now time.Time, meta model.RequestMeta) (string, core.Outcome, error) {
	needs, err := m.repo.PermissionNeedsApproval(ctx, tx, t.ID, req.Permission)
	if err != nil || !needs {
		return "", outcome, err
	}
	agentID := req.AgentID
	userID := req.PrincipalID
	if agentID == "" {
		kind, err := m.repo.GetPrincipalKind(ctx, tx, t.ID, req.PrincipalID)
		if err != nil {
			return "", outcome, err
		}
		if kind != constant.PrincipalKindAgent {
			return "", outcome, nil // a person needs no approval
		}
		agent, err := m.machines.GetMachine(ctx, tx, t.ID, req.PrincipalID)
		if err != nil {
			return "", outcome, err
		}
		if agent == nil || agent.OwnerID == "" {
			return "", core.Outcome{Allowed: false, Reason: core.ReasonApprovalRequired, Grant: outcome.Grant}, nil
		}
		agentID, userID = agent.ID, agent.OwnerID
	}
	digest := core.ActionDigest(req.Permission, resourceID, req.Details)
	denied := func(reason string) core.Outcome {
		return core.Outcome{Allowed: false, Reason: reason, Grant: outcome.Grant}
	}

	if req.ApprovalID != "" {
		a, err := m.machines.LockApproval(ctx, tx, t.ID, req.ApprovalID)
		if err != nil {
			return "", outcome, err
		}
		if a == nil || a.AgentID != agentID || a.UserID != userID || !bytes.Equal(a.Digest, digest) || !now.Before(a.ExpiresAt) {
			return "", denied(core.ReasonApprovalInvalid), nil
		}
		switch a.Status {
		case constant.ApprovalPending:
			return a.ID, denied(core.ReasonApprovalPending), nil
		case constant.ApprovalDeclined:
			return a.ID, denied(core.ReasonApprovalDeclined), nil
		case constant.ApprovalApproved:
			if err := m.machines.MarkApprovalUsed(ctx, tx, t.ID, a.ID, now); err != nil {
				return "", outcome, err
			}
			if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "approval.used", Result: model.AuditSuccess, ActorID: agentID, TargetType: "approval", TargetID: a.ID,
				Data: map[string]any{"user_id": userID, "permission": req.Permission}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			}); err != nil {
				return "", outcome, err
			}
			return a.ID, core.Outcome{Allowed: true, Reason: core.ReasonApproved, Grant: outcome.Grant}, nil
		default:
			return a.ID, denied(core.ReasonApprovalInvalid), nil
		}
	}

	// No id: an open request for the same action is reused, else one is made.
	existing, err := m.machines.FindPendingApproval(ctx, tx, t.ID, agentID, digest, now)
	if err != nil {
		return "", outcome, err
	}
	if existing != nil {
		return existing.ID, denied(core.ReasonApprovalRequired), nil
	}
	id, err := m.machines.CreateApproval(ctx, tx, t.ID, model.Approval{
		AgentID: agentID, UserID: userID, Permission: req.Permission, ResourceID: resourceID, Digest: digest,
		Details: req.Details, ExpiresAt: now.Add(constant.ApprovalTTL),
	})
	if err != nil {
		return "", outcome, err
	}
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "approval.requested", Result: model.AuditSuccess, ActorID: agentID, TargetType: "approval", TargetID: id,
		Data: map[string]any{"user_id": userID, "permission": req.Permission, "details": req.Details}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return "", outcome, err
	}
	if err := m.notify.Emit(ctx, tx, t.ID, "approval.requested", map[string]any{"approval_id": id, "agent_id": agentID, "user_id": userID, "permission": req.Permission}); err != nil {
		return "", outcome, err
	}
	agentName := agentID
	if agent, err := m.machines.GetMachine(ctx, tx, t.ID, agentID); err == nil && agent != nil {
		agentName = agent.Name
	}
	if user, err := m.users.GetUser(ctx, tx, t.ID, userID); err == nil && user != nil {
		details, _ := json.Marshal(req.Details)
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: user.Email, Template: constant.TemplateApprovalRequested,
			Data: map[string]string{"agent": agentName, "permission": req.Permission, "resource": req.Resource.Type + " " + req.Resource.ID,
				"details": string(details), "link": authcore.Link(t.AppURL, authcore.ApprovalsPath, "")},
		}); err != nil {
			return "", outcome, err
		}
	}
	return id, denied(core.ReasonApprovalRequired), nil
}

func (m *iamModule) PutPermission(ctx context.Context, t *model.Tenant, req request.PutPermissionRequest, source string, meta model.RequestMeta) (*response.Permission, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var stored string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		if stored, err = m.repo.UpsertPermission(ctx, tx, t.ID, req.Name, req.Description, source); err != nil {
			return err
		}
		if err := m.repo.SetPermissionStepUp(ctx, tx, t.ID, req.Name, req.StepUpSeconds); err != nil {
			return err
		}
		if err := m.repo.SetPermissionNeedsApproval(ctx, tx, t.ID, req.Name, req.NeedsApproval); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "permission.saved", Result: model.AuditSuccess,
			TargetType: "permission", TargetID: req.Name,
			Data: map[string]any{"source": source, "step_up_seconds": req.StepUpSeconds}, RequestID: meta.RequestID,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("put permission: %w", err)
	}
	return &response.Permission{Name: req.Name, Description: req.Description, Source: stored, StepUpSeconds: req.StepUpSeconds, NeedsApproval: req.NeedsApproval}, nil
}

// stepUpSatisfied applies SIGN-9: a permission with a step-up window
// needs a session whose second factor is no older than that window. A
// check without a session cannot satisfy it.
func (m *iamModule) stepUpSatisfied(ctx context.Context, tx pgx.Tx, tenantID, permission, sessionID string, now time.Time) (bool, error) {
	seconds, err := m.repo.PermissionStepUp(ctx, tx, tenantID, permission)
	if err != nil {
		return false, err
	}
	if seconds == 0 {
		return true, nil
	}
	if sessionID == "" {
		return false, nil
	}
	at, found, err := m.repo.SessionSecondFactorAt(ctx, tx, tenantID, sessionID)
	if err != nil {
		return false, err
	}
	if !found || at == nil {
		return false, nil
	}
	return now.Sub(*at) <= time.Duration(seconds)*time.Second, nil
}

func (m *iamModule) PutRole(ctx context.Context, t *model.Tenant, req request.PutRoleRequest, source string, meta model.RequestMeta) (*response.Role, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var id, stored string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		_, existingSource, err := m.repo.GetRoleByName(ctx, tx, t.ID, req.Name)
		if err != nil {
			return err
		}
		// Owner is the one role AOS ships. It always holds "*", so that
		// no tenant can be left with nobody able to manage it.
		if existingSource == constant.SourceSystem {
			return errors.Conflict("role_is_built_in", "this role is built in and cannot be changed")
		}
		if id, stored, err = m.repo.UpsertRole(ctx, tx, t.ID, req.Name, req.Description, source); err != nil {
			return err
		}
		if err := m.repo.ReplaceRolePermissions(ctx, tx, t.ID, id, req.Permissions); err != nil {
			return err
		}
		// Changing a role changes what people can do, so it is audited.
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "role.saved", Result: model.AuditSuccess,
			TargetType: "role", TargetID: id,
			Data: map[string]any{"name": req.Name, "permissions": req.Permissions}, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "role.updated", map[string]any{"role_id": id, "name": req.Name})
	})
	if err != nil {
		return nil, passThrough("put role", err)
	}
	permissions := req.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	return &response.Role{ID: id, Name: req.Name, Description: req.Description, Source: stored, Permissions: permissions}, nil
}

func (m *iamModule) CreateResource(ctx context.Context, t *model.Tenant, req request.CreateResourceRequest, meta model.RequestMeta) (*response.Resource, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ref := model.ResourceRef{Type: req.Type, ID: req.ID}
	// With no parent named, the node sits directly under the tenant root.
	parentRef := model.ResourceRef{Type: constant.ResourceTypeTenant, ID: constant.RootExternalID}
	if req.Parent != nil {
		parentRef = model.ResourceRef{Type: req.Parent.Type, ID: req.Parent.ID}
	}

	var id string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		parentID, _, err := m.repo.FindResource(ctx, tx, t.ID, parentRef)
		if err != nil {
			return err
		}
		if parentID == "" {
			return errors.Validation(map[string]string{"parent": "does not exist"})
		}

		// Asking twice for the same node in the same place is not an
		// error. The application may retry after a timeout.
		existingID, existingParent, err := m.repo.FindResource(ctx, tx, t.ID, ref)
		if err != nil {
			return err
		}
		if existingID != "" {
			if existingParent != parentID {
				return errors.Conflict("resource_exists_elsewhere", "this resource already exists under another parent")
			}
			id = existingID
			return nil
		}

		if err := m.repo.EnsureResourceType(ctx, tx, t.ID, req.Type); err != nil {
			return err
		}
		id, err = m.repo.CreateResource(ctx, tx, t.ID, ref, parentID, req.DisplayName)
		return err
	})
	if err != nil {
		return nil, passThrough("create resource", err)
	}
	return &response.Resource{ID: id, Type: req.Type, ExternalID: req.ID}, nil
}

func (m *iamModule) CreateGrant(ctx context.Context, t *model.Tenant, req request.CreateGrantRequest, meta model.RequestMeta) (*response.Grant, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ref := model.ResourceRef{Type: req.Resource.Type, ID: req.Resource.ID}

	var grantID, resourceID string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		problems := map[string]string{}
		if req.PrincipalID != "" {
			status, err := m.repo.GetPrincipalStatus(ctx, tx, t.ID, req.PrincipalID)
			if err != nil {
				return err
			}
			if status == "" {
				problems["principal_id"] = "does not exist"
			}
		} else {
			exists, err := m.repo.GroupExists(ctx, tx, t.ID, req.GroupID)
			if err != nil {
				return err
			}
			if !exists {
				problems["group_id"] = "does not exist"
			}
		}
		roleID, _, err := m.repo.GetRoleByName(ctx, tx, t.ID, req.Role)
		if err != nil {
			return err
		}
		if resourceID, _, err = m.repo.FindResource(ctx, tx, t.ID, ref); err != nil {
			return err
		}
		if roleID == "" {
			problems["role"] = "does not exist"
		}
		if resourceID == "" {
			problems["resource"] = "does not exist"
		}
		if req.Condition != "" {
			if err := core.CheckCondition(req.Condition); err != nil {
				problems["condition"] = "does not parse: " + err.Error()
			}
		}
		if len(problems) > 0 {
			return errors.Validation(problems)
		}

		grantID, err = m.repo.CreateGrant(ctx, tx, t.ID, model.NewGrant{
			PrincipalID: req.PrincipalID, GroupID: req.GroupID, RoleID: roleID, ResourceID: resourceID,
			Effect: req.Effect, ExpiresAt: req.ExpiresAt, Source: "manual", Reason: req.Reason, Condition: req.Condition,
		})
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "grant.created", Result: model.AuditSuccess,
			TargetType: "grant", TargetID: grantID,
			Data: map[string]any{
				"principal_id": req.PrincipalID, "group_id": req.GroupID, "role": req.Role, "effect": req.Effect,
				"resource_type": ref.Type, "resource_id": ref.ID,
			},
			RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "grant.created", map[string]any{
			"grant_id": grantID, "principal_id": req.PrincipalID, "role": req.Role,
		})
	})
	if err != nil {
		return nil, passThrough("create grant", err)
	}
	return &response.Grant{
		ID: grantID, PrincipalID: req.PrincipalID, GroupID: req.GroupID, Role: req.Role, Effect: req.Effect, ExpiresAt: req.ExpiresAt,
		Resource: response.Resource{ID: resourceID, Type: ref.Type, ExternalID: ref.ID},
	}, nil
}

func (m *iamModule) DeleteGrant(ctx context.Context, t *model.Tenant, grantID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(grantID) {
		return errors.NotFound("grant")
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		holder, err := m.repo.DeleteGrant(ctx, tx, t.ID, grantID)
		if err != nil {
			return err
		}
		if holder == "" {
			return errors.NotFound("grant")
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "grant.revoked", Result: model.AuditSuccess,
			TargetType: "grant", TargetID: grantID, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "grant.revoked", map[string]any{"grant_id": grantID})
	})
	if err != nil {
		return passThrough("delete grant", err)
	}
	return nil
}

func passThrough(operation string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsAppError(err); ok {
		return err
	}
	return fmt.Errorf("%s: %w", operation, err)
}
