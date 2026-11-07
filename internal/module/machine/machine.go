// Package machine is the non-human side of the engine (user-flow MACH-1
// to MACH-4 and MACH-8 to MACH-10): service accounts and agents, the API
// keys they hold, the work users delegate to agents, and the approvals a
// human gives for an agent's sensitive actions.
package machine

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/module"
	authcore "github.com/flash-softeware/aos/internal/module/auth/core"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

type machineModule struct {
	db     *postgres.DB
	repo   storage.MachineRepository
	iam    storage.IAMRepository
	users  storage.AuthRepository
	audit  storage.AuditRepository
	notify module.Notification
	can    module.IAM
	auth   module.Auth
	now    func() time.Time
	log    logger.Logger
}

func NewMachineModule(db *postgres.DB, repo storage.MachineRepository, iam storage.IAMRepository, users storage.AuthRepository,
	audit storage.AuditRepository, notify module.Notification, can module.IAM, auth module.Auth, now func() time.Time, log logger.Logger) module.Machine {
	return &machineModule{db: db, repo: repo, iam: iam, users: users, audit: audit, notify: notify, can: can, auth: auth, now: now, log: log}
}

var (
	errOwnerRequired = errors.Validation(map[string]string{"owner_principal_id": "an agent needs an owner"})
	errOwnerUnknown  = errors.Validation(map[string]string{"owner_principal_id": "does not exist"})
	errNotAnAgent    = errors.Validation(map[string]string{"agent_id": "is not an active agent"})
	errKeyInvalid    = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "invalid_api_key", "the key is missing or not valid")
	errKeyLimited    = errors.New(errors.ErrorTypeRateLimit, http.StatusTooManyRequests, "rate_limited", "too many requests for this key. try again later")
	errForbidden     = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "forbidden", "you may not do this")
	errNotYours      = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "not_your_approval", "this request was not addressed to you")
	errDecided       = errors.Conflict("approval_decided", "this request has already been decided or has expired")
	errStepUp        = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "step_up_required", "give your second factor again before approving")
)

// ---------------------------------------------------------------------
// Service accounts and agents
// ---------------------------------------------------------------------

func (m *machineModule) CreateMachine(ctx context.Context, t *model.Tenant, kind string, req request.CreateMachineRequest, meta model.RequestMeta) (*response.Machine, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if kind == constant.PrincipalKindAgent && req.OwnerPrincipalID == "" {
		return nil, errOwnerRequired
	}
	var out *response.Machine
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if req.OwnerPrincipalID != "" {
			status, err := m.iam.GetPrincipalStatus(ctx, tx, t.ID, req.OwnerPrincipalID)
			if err != nil {
				return err
			}
			if status != constant.PrincipalActive {
				return errOwnerUnknown
			}
		}
		id, err := m.repo.CreateMachine(ctx, tx, t.ID, kind, req.Name, req.Purpose, req.OwnerPrincipalID)
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: kind + ".created", Result: model.AuditSuccess, TargetType: kind, TargetID: id,
			Data: map[string]any{"name": req.Name, "owner_id": req.OwnerPrincipalID}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, kind+".created", map[string]any{"principal_id": id, "name": req.Name, "owner_id": req.OwnerPrincipalID}); err != nil {
			return err
		}
		mach, err := m.repo.GetMachine(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		r := toMachine(*mach)
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("create "+kind, err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *machineModule) ListMachines(ctx context.Context, t *model.Tenant, kind string) ([]response.Machine, error) {
	out := []response.Machine{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		list, err := m.repo.ListMachines(ctx, tx, t.ID, kind)
		if err != nil {
			return err
		}
		for _, mach := range list {
			out = append(out, toMachine(mach))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list %ss: %w", kind, err)
	}
	return out, nil
}

func (m *machineModule) GetMachine(ctx context.Context, t *model.Tenant, id string) (*response.Machine, error) {
	var out *response.Machine
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		mach, err := m.repo.GetMachine(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if mach == nil {
			return errors.NotFound("principal")
		}
		r := toMachine(*mach)
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("get machine", err)
	}
	return out, nil
}

func (m *machineModule) DisableMachine(ctx context.Context, t *model.Tenant, id, reason string, meta model.RequestMeta) error {
	return m.setStatus(ctx, t, id, constant.PrincipalSuspended, reason, "disabled", meta)
}

func (m *machineModule) EnableMachine(ctx context.Context, t *model.Tenant, id string, meta model.RequestMeta) error {
	return m.setStatus(ctx, t, id, constant.PrincipalActive, "", "enabled", meta)
}

func (m *machineModule) setStatus(ctx context.Context, t *model.Tenant, id, status, reason, action string, meta model.RequestMeta) error {
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		mach, err := m.repo.GetMachine(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if mach == nil {
			return errors.NotFound("principal")
		}
		if err := m.repo.SetMachineStatus(ctx, tx, t.ID, id, status, reason, m.now()); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: mach.Kind + "." + action, Result: model.AuditSuccess, TargetType: mach.Kind, TargetID: id,
			Data: map[string]any{"reason": reason}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough(action, err)
}

// RevokeAgent takes everything away at once (MACH-10). It works on a
// service account too.
func (m *machineModule) RevokeAgent(ctx context.Context, t *model.Tenant, id, reason string, meta model.RequestMeta) (*response.AgentRevocation, error) {
	now := m.now()
	out := &response.AgentRevocation{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		mach, err := m.repo.GetMachine(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if mach == nil {
			return errors.NotFound("principal")
		}
		if out.Keys, err = m.repo.RevokeAPIKeysOf(ctx, tx, t.ID, id, now); err != nil {
			return err
		}
		if out.Delegations, err = m.repo.RevokeDelegationsOf(ctx, tx, t.ID, id, now); err != nil {
			return err
		}
		if err := m.repo.RevokeTokenFamiliesOfPrincipal(ctx, tx, t.ID, id, "agent revoked", now); err != nil {
			return err
		}
		if _, err := m.users.RevokeAllSessions(ctx, tx, t.ID, id, "agent revoked", now); err != nil {
			return err
		}
		if out.Grants, err = m.repo.DeleteGrantsOf(ctx, tx, t.ID, id); err != nil {
			return err
		}
		if err := m.repo.SetMachineStatus(ctx, tx, t.ID, id, constant.PrincipalSuspended, reason, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: mach.Kind + ".revoked", Result: model.AuditSuccess, TargetType: mach.Kind, TargetID: id,
			Data:      map[string]any{"reason": reason, "api_keys": out.Keys, "delegations": out.Delegations, "grants": out.Grants},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, mach.Kind+".revoked", map[string]any{"principal_id": id, "reason": reason})
	})
	if err != nil {
		return nil, passThrough("revoke agent", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *machineModule) AgentAudit(ctx context.Context, t *model.Tenant, id string, limit int) ([]response.AuditEntry, error) {
	if limit <= 0 || limit > constant.MaxPageSize {
		limit = constant.DefaultPageSize
	}
	out := []response.AuditEntry{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		mach, err := m.repo.GetMachine(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if mach == nil {
			return errors.NotFound("principal")
		}
		entries, err := m.audit.ListForPrincipal(ctx, tx, t.ID, id, limit)
		if err != nil {
			return err
		}
		for _, e := range entries {
			out = append(out, response.AuditEntry{
				Seq: e.Seq, OccurredAt: e.OccurredAt, Action: e.Action, Result: e.Result, ReasonCode: e.ReasonCode,
				TargetType: e.TargetType, TargetID: e.TargetID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("agent audit", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------

func (m *machineModule) CreateAPIKey(ctx context.Context, t *model.Tenant, actor model.Actor, req request.CreateAPIKeyRequest, meta model.RequestMeta) (*response.CreatedAPIKey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	// A person issues keys for themselves only. The backend, for anyone.
	if !actor.Root {
		if req.PrincipalID != "" && req.PrincipalID != actor.PrincipalID {
			return nil, errForbidden
		}
		req.PrincipalID = actor.PrincipalID
	}
	if req.PrincipalID == "" {
		return nil, errors.Validation(map[string]string{"principal_id": "is required"})
	}
	env := "test"
	if t.Environment == constant.EnvProduction {
		env = "live"
	}
	publicID := constant.APIKeyPrefix + env + "_" + secret.HexID(12)
	secretPart := secret.Token(32)
	now := m.now()
	var out *response.CreatedAPIKey
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		status, err := m.iam.GetPrincipalStatus(ctx, tx, t.ID, req.PrincipalID)
		if err != nil {
			return err
		}
		if status != constant.PrincipalActive {
			return errors.Validation(map[string]string{"principal_id": "is not an active principal"})
		}
		id, err := m.repo.CreateAPIKey(ctx, tx, t.ID, model.APIKey{
			PrincipalID: req.PrincipalID, Name: req.Name, PublicID: publicID, SecretHash: secret.Hash(secretPart),
			Scopes: req.Scopes, ExpiresAt: req.ExpiresAt, CreatedBy: actor.PrincipalID,
		})
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "apikey.created", Result: model.AuditSuccess, ActorID: actor.PrincipalID, SessionID: actor.SessionID,
			TargetType: "api_key", TargetID: id, Data: map[string]any{"principal_id": req.PrincipalID, "scopes": req.Scopes, "name": req.Name},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "apikey.created", map[string]any{"api_key_id": id, "principal_id": req.PrincipalID}); err != nil {
			return err
		}
		out = &response.CreatedAPIKey{
			APIKey: response.APIKey{ID: id, PrincipalID: req.PrincipalID, Name: req.Name, PublicID: publicID, Scopes: req.Scopes, ExpiresAt: req.ExpiresAt, CreatedAt: now},
			Key:    publicID + "." + secretPart,
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("create api key", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *machineModule) ListAPIKeys(ctx context.Context, t *model.Tenant, actor model.Actor, principalID string) ([]response.APIKey, error) {
	if !actor.Root {
		principalID = actor.PrincipalID
	}
	if principalID != "" && !postgres.IsUUID(principalID) {
		return nil, errors.Validation(map[string]string{"principal_id": "must be an id"})
	}
	out := []response.APIKey{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		keys, err := m.repo.ListAPIKeys(ctx, tx, t.ID, principalID)
		if err != nil {
			return err
		}
		for _, k := range keys {
			out = append(out, toKey(k))
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list api keys", err)
	}
	return out, nil
}

func (m *machineModule) RevokeAPIKey(ctx context.Context, t *model.Tenant, actor model.Actor, id string, meta model.RequestMeta) error {
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if !actor.Root {
			// A person revokes only their own keys.
			keys, err := m.repo.ListAPIKeys(ctx, tx, t.ID, actor.PrincipalID)
			if err != nil {
				return err
			}
			mine := false
			for _, k := range keys {
				if k.ID == id {
					mine = true
				}
			}
			if !mine {
				return errors.NotFound("api key")
			}
		}
		principalID, err := m.repo.RevokeAPIKey(ctx, tx, t.ID, id, m.now())
		if err != nil {
			return err
		}
		if principalID == "" {
			return errors.NotFound("api key")
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "apikey.revoked", Result: model.AuditSuccess, ActorID: actor.PrincipalID, SessionID: actor.SessionID,
			TargetType: "api_key", TargetID: id, Data: map[string]any{"principal_id": principalID},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "apikey.revoked", map[string]any{"api_key_id": id, "principal_id": principalID})
	})
	if err != nil {
		return passThrough("revoke api key", err)
	}
	m.notify.Wake()
	return nil
}

// CheckAPIKey is MACH-3: find the key, compare in constant time, check
// its state and its principal's, apply its rate limit, then answer the
// question within its scopes.
func (m *machineModule) CheckAPIKey(ctx context.Context, t *model.Tenant, req request.CheckAPIKeyRequest, meta model.RequestMeta) (*response.APIKeyCheck, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	publicID, secretPart, found := strings.Cut(req.Key, ".")
	if !found || !strings.HasPrefix(publicID, constant.APIKeyPrefix) {
		return nil, errKeyInvalid
	}
	now := m.now()
	var key *model.APIKey
	var kind string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		key, err = m.repo.FindAPIKeyByPublicID(ctx, tx, t.ID, publicID)
		if err != nil {
			return err
		}
		// Unknown, revoked, expired and wrong all read the same.
		if key == nil || !secret.Equal(secret.Hash(secretPart), key.SecretHash) ||
			key.RevokedAt != nil || (key.ExpiresAt != nil && !now.Before(*key.ExpiresAt)) {
			return errKeyInvalid
		}
		status, err := m.iam.GetPrincipalStatus(ctx, tx, t.ID, key.PrincipalID)
		if err != nil {
			return err
		}
		if status != constant.PrincipalActive {
			return errKeyInvalid
		}
		if kind, err = m.iam.GetPrincipalKind(ctx, tx, t.ID, key.PrincipalID); err != nil {
			return err
		}
		state, err := m.users.HitRateLimit(ctx, tx, t.ID, constant.BucketAPIKey, authcore.LimitKey(key.ID), now, constant.APIKeyLimitWindow)
		if err != nil {
			return err
		}
		if state.Count > constant.APIKeyLimitPerMinute {
			return errKeyLimited
		}
		if key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= constant.APIKeyTouchInterval {
			return m.repo.TouchAPIKey(ctx, tx, t.ID, key.ID, now)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("check api key", err)
	}
	out := &response.APIKeyCheck{KeyID: key.ID, PrincipalID: key.PrincipalID, Kind: kind, Scopes: key.Scopes}
	if req.Permission == "" {
		return out, nil
	}
	answer, err := m.can.Can(ctx, t, request.CanRequest{
		PrincipalID: key.PrincipalID, Permission: req.Permission, Resource: *req.Resource,
		Scopes: key.Scopes, Details: req.Details, ApprovalID: req.ApprovalID,
	}, meta)
	if err != nil {
		return nil, err
	}
	out.Allowed, out.Reason, out.ApprovalID = answer.Allowed, answer.Reason, answer.ApprovalID
	return out, nil
}

// ---------------------------------------------------------------------
// Delegations (MACH-8)
// ---------------------------------------------------------------------

func (m *machineModule) CreateDelegation(ctx context.Context, t *model.Tenant, sessionToken string, req request.CreateDelegationRequest, meta model.RequestMeta) (*response.Delegation, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.Delegation
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		agent, err := m.repo.GetMachine(ctx, tx, t.ID, req.AgentID)
		if err != nil {
			return err
		}
		if agent == nil || agent.Kind != constant.PrincipalKindAgent || agent.Status != constant.PrincipalActive {
			return errNotAnAgent
		}
		resourceID, _, err := m.iam.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: req.Resource.Type, ID: req.Resource.ID})
		if err != nil {
			return err
		}
		if resourceID == "" {
			return errors.Validation(map[string]string{"resource": "does not exist"})
		}
		expires := now.Add(time.Duration(req.Hours) * time.Hour)
		id, err := m.repo.CreateDelegation(ctx, tx, t.ID, model.Delegation{
			AgentID: agent.ID, UserID: session.PrincipalID, Scopes: req.Scopes, ResourceID: resourceID, ExpiresAt: expires,
		})
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "delegation.created", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "agent", TargetID: agent.ID, Data: map[string]any{"delegation_id": id, "scopes": req.Scopes, "expires_at": expires},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "delegation.created", map[string]any{"delegation_id": id, "agent_id": agent.ID, "user_id": session.PrincipalID}); err != nil {
			return err
		}
		out = &response.Delegation{
			ID: id, AgentID: agent.ID, UserID: session.PrincipalID, Scopes: req.Scopes,
			Resource:  response.Resource{ID: resourceID, Type: req.Resource.Type, ExternalID: req.Resource.ID},
			ExpiresAt: expires, CreatedAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("create delegation", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *machineModule) ListDelegations(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Delegation, error) {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	out := []response.Delegation{}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		list, err := m.repo.ListDelegations(ctx, tx, t.ID, session.PrincipalID, "")
		if err != nil {
			return err
		}
		for _, d := range list {
			r, err := m.toDelegation(ctx, tx, t, d)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list delegations", err)
	}
	return out, nil
}

func (m *machineModule) toDelegation(ctx context.Context, tx pgx.Tx, t *model.Tenant, d model.Delegation) (response.Delegation, error) {
	nodes, err := m.iam.Ancestors(ctx, tx, t.ID, d.ResourceID)
	if err != nil {
		return response.Delegation{}, err
	}
	res := response.Resource{ID: d.ResourceID}
	if len(nodes) > 0 {
		res.Type, res.ExternalID = nodes[0].Type, nodes[0].ExternalID
	}
	return response.Delegation{ID: d.ID, AgentID: d.AgentID, UserID: d.UserID, Scopes: d.Scopes, Resource: res, ExpiresAt: d.ExpiresAt, RevokedAt: d.RevokedAt, CreatedAt: d.CreatedAt}, nil
}

func (m *machineModule) RevokeDelegation(ctx context.Context, t *model.Tenant, sessionToken, id string, meta model.RequestMeta) error {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return err
	}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		ok, err := m.repo.RevokeDelegation(ctx, tx, t.ID, id, session.PrincipalID, m.now())
		if err != nil {
			return err
		}
		if !ok {
			return errors.NotFound("delegation")
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "delegation.revoked", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "delegation", TargetID: id, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough("revoke delegation", err)
}

// ---------------------------------------------------------------------
// Approvals (MACH-9)
// ---------------------------------------------------------------------

func (m *machineModule) ListApprovals(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Approval, error) {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	out := []response.Approval{}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		list, err := m.repo.ListApprovals(ctx, tx, t.ID, session.PrincipalID, m.now())
		if err != nil {
			return err
		}
		for _, a := range list {
			r, err := m.toApproval(ctx, tx, t, a)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list approvals", err)
	}
	return out, nil
}

func (m *machineModule) toApproval(ctx context.Context, tx pgx.Tx, t *model.Tenant, a model.Approval) (response.Approval, error) {
	nodes, err := m.iam.Ancestors(ctx, tx, t.ID, a.ResourceID)
	if err != nil {
		return response.Approval{}, err
	}
	res := response.Resource{ID: a.ResourceID}
	if len(nodes) > 0 {
		res.Type, res.ExternalID = nodes[0].Type, nodes[0].ExternalID
	}
	name := ""
	if agent, err := m.repo.GetMachine(ctx, tx, t.ID, a.AgentID); err == nil && agent != nil {
		name = agent.Name
	}
	return response.Approval{
		ID: a.ID, AgentID: a.AgentID, AgentName: name, UserID: a.UserID, Permission: a.Permission, Resource: res,
		Details: a.Details, Status: a.Status, ExpiresAt: a.ExpiresAt, DecidedAt: a.DecidedAt, CreatedAt: a.CreatedAt,
	}, nil
}

func (m *machineModule) DecideApproval(ctx context.Context, t *model.Tenant, sessionToken, id string, approve bool, meta model.RequestMeta) (*response.Approval, error) {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.Approval
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		a, err := m.repo.LockApproval(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if a == nil {
			return errors.NotFound("approval")
		}
		if a.UserID != session.PrincipalID {
			return errNotYours
		}
		if a.Status != constant.ApprovalPending || !now.Before(a.ExpiresAt) {
			return errDecided
		}
		// Approving is sensitive: a person with a second factor must have
		// given it recently.
		if approve {
			totp, err := m.users.GetTOTP(ctx, tx, t.ID, session.PrincipalID)
			if err != nil {
				return err
			}
			passkeys, err := m.users.CountPasskeys(ctx, tx, t.ID, session.PrincipalID)
			if err != nil {
				return err
			}
			hasFactor := (totp != nil && totp.Confirmed) || passkeys > 0
			if hasFactor && (session.SecondFactorAt == nil || now.Sub(*session.SecondFactorAt) > constant.ApprovalStepUpWindow) {
				return errStepUp
			}
		}
		status := constant.ApprovalDeclined
		if approve {
			status = constant.ApprovalApproved
		}
		if err := m.repo.SetApprovalStatus(ctx, tx, t.ID, a.ID, status, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "approval." + status, Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "approval", TargetID: a.ID, Data: map[string]any{"agent_id": a.AgentID, "permission": a.Permission},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "approval.decided", map[string]any{"approval_id": a.ID, "agent_id": a.AgentID, "status": status}); err != nil {
			return err
		}
		a.Status = status
		a.DecidedAt = &now
		r, err := m.toApproval(ctx, tx, t, *a)
		if err != nil {
			return err
		}
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("decide approval", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *machineModule) GetApproval(ctx context.Context, t *model.Tenant, id string) (*response.Approval, error) {
	var out *response.Approval
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		a, err := m.repo.LockApproval(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if a == nil {
			return errors.NotFound("approval")
		}
		if a.Status == constant.ApprovalPending && !m.now().Before(a.ExpiresAt) {
			a.Status = constant.ApprovalExpired
		}
		r, err := m.toApproval(ctx, tx, t, *a)
		if err != nil {
			return err
		}
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("get approval", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func toMachine(m model.Machine) response.Machine {
	return response.Machine{ID: m.ID, Kind: m.Kind, Name: m.Name, Purpose: m.Purpose, OwnerID: m.OwnerID, Status: m.Status, CreatedAt: m.CreatedAt, Suspended: m.SuspendedAt}
}

func toKey(k model.APIKey) response.APIKey {
	return response.APIKey{ID: k.ID, PrincipalID: k.PrincipalID, Name: k.Name, PublicID: k.PublicID, Scopes: k.Scopes, ExpiresAt: k.ExpiresAt, RevokedAt: k.RevokedAt, LastUsedAt: k.LastUsedAt, CreatedAt: k.CreatedAt}
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
