// Package organization is a customer of the application and its people:
// creating organizations, inviting, switching, changing roles, removing
// members and deleting (user-flow ORG-1 to ORG-11).
//
// Every method takes the actor. Root, from the backend door, holds every
// permission. A signed-in person is bound by their grants, checked with
// AOS's own permissions such as aos.member.invite.
package organization

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module"
	authcore "github.com/flash-software-technology/aos/internal/module/auth/core"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
	"github.com/flash-software-technology/aos/platform/secret"
)

type organizationModule struct {
	db     *postgres.DB
	repo   storage.OrganizationRepository
	iam    storage.IAMRepository
	users  storage.AuthRepository
	audit  storage.AuditRepository
	notify module.Notification
	authz  module.Authorizer
	auth   module.Auth
	breach secret.BreachChecker
	params secret.PasswordParams
	meter  module.UsageMeter // nil in the package modes
	now    func() time.Time
	log    logger.Logger
}

func (m *organizationModule) withinLimit(ctx context.Context, tx pgx.Tx, tenantID, metric string, current func() (int64, error)) error {
	if m.meter == nil {
		return nil
	}
	limit, err := m.meter.Limit(ctx, tx, tenantID, metric)
	if err != nil {
		return err
	}
	if limit < 0 {
		return nil
	}
	n, err := current()
	if err != nil {
		return err
	}
	if n >= limit {
		return errors.LimitReached(metric)
	}
	return nil
}

func NewOrganizationModule(db *postgres.DB, repo storage.OrganizationRepository, iam storage.IAMRepository,
	users storage.AuthRepository, audit storage.AuditRepository, notify module.Notification,
	authz module.Authorizer, auth module.Auth, breach secret.BreachChecker, params secret.PasswordParams,
	meter module.UsageMeter, now func() time.Time, log logger.Logger) module.Organization {
	return &organizationModule{
		db: db, repo: repo, iam: iam, users: users, audit: audit, notify: notify, authz: authz, auth: auth,
		breach: breach, params: params, meter: meter, now: now, log: log,
	}
}

var (
	errForbidden    = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "forbidden", "you may not do this here")
	errNotEnabled   = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "organizations_disabled", "this application has no organizations")
	errCannotGrant  = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "cannot_grant_more_than_held", "you can only give roles whose permissions you hold here yourself")
	errLastOwner    = errors.Conflict("last_owner", "an organization must keep at least one owner. transfer ownership first")
	errAlreadyIn    = errors.Conflict("already_member", "this person already belongs to the organization")
	errAccountExist = errors.Conflict("account_exists", "an account with this address exists. sign in to accept the invitation")
	errWrongAccount = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "invitation_for_another_address", "this invitation is for another email address")
)

// require refuses unless the actor is Root or holds the permission on the resource.
func (m *organizationModule) require(ctx context.Context, tx pgx.Tx, t *model.Tenant, actor model.Actor, permission, resourceID string) error {
	if actor.Root {
		return nil
	}
	allowed, _, err := m.authz.Check(ctx, tx, t.ID, actor.PrincipalID, permission, resourceID)
	if err != nil {
		return err
	}
	if !allowed {
		return errForbidden
	}
	return nil
}

// organization loads an organization or answers "not found".
func (m *organizationModule) organization(ctx context.Context, tx pgx.Tx, t *model.Tenant, orgID string) (*model.Organization, error) {
	if !postgres.IsUUID(orgID) {
		return nil, errors.NotFound("organization")
	}
	org, err := m.repo.GetOrganization(ctx, tx, t.ID, orgID)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, errors.NotFound("organization")
	}
	return org, nil
}

func (m *organizationModule) ownerRole(ctx context.Context, tx pgx.Tx, t *model.Tenant) (string, error) {
	id, _, err := m.iam.GetRoleByName(ctx, tx, t.ID, constant.RoleOwner)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("the tenant has no Owner role")
	}
	return id, nil
}

// ---------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------

func (m *organizationModule) Create(ctx context.Context, t *model.Tenant, actor model.Actor, req request.CreateOrganizationRequest, meta model.RequestMeta) (*response.Organization, error) {
	slugGiven := req.Slug != ""
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if t.Kind != constant.KindMulti {
		return nil, errNotEnabled
	}
	if req.OwnerPrincipalID != "" && !actor.Root {
		return nil, errors.Validation(map[string]string{"owner_principal_id": "only the backend may name another owner"})
	}
	if err := m.notify.Hook(ctx, t, "organization.before_create", map[string]any{"name": req.Name, "slug": req.Slug, "actor_id": actor.PrincipalID}); err != nil {
		return nil, err
	}

	now := m.now()
	var out *response.Organization
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if !actor.Root {
			switch t.OrgCreationPolicy {
			case constant.OrgCreationAdminOnly:
				if err := m.require(ctx, tx, t, actor, constant.PermOrganizationCreate, t.RootResourceID); err != nil {
					return err
				}
			case constant.OrgCreationApplication:
				return errForbidden
			}
		}
		if err := m.withinLimit(ctx, tx, t.ID, constant.MetricOrganizations, func() (int64, error) { return m.repo.CountOrganizations(ctx, tx, t.ID) }); err != nil {
			return err
		}
		taken, err := m.repo.SlugTaken(ctx, tx, t.ID, req.Slug)
		if err != nil {
			return err
		}
		if taken {
			if slugGiven {
				return errors.Conflict("slug_taken", "an organization with this short name already exists")
			}
			req.Slug = req.Slug + "-" + secret.HexID(2)
		}
		if err := m.iam.EnsureResourceType(ctx, tx, t.ID, constant.ResourceTypeOrganization); err != nil {
			return err
		}
		resourceID, err := m.iam.CreateResource(ctx, tx, t.ID,
			model.ResourceRef{Type: constant.ResourceTypeOrganization, ID: req.Slug}, t.RootResourceID, req.Name)
		if err != nil {
			return err
		}
		if err := m.repo.CreateOrganization(ctx, tx, t.ID, resourceID, req.Slug, req.Name, actor.PrincipalID); err != nil {
			return err
		}

		// The creator is the first owner. This is one of the two places
		// where AOS itself gives someone a role.
		owner := actor.PrincipalID
		if actor.Root {
			owner = req.OwnerPrincipalID
		}
		if owner != "" {
			ownerRoleID, err := m.ownerRole(ctx, tx, t)
			if err != nil {
				return err
			}
			if _, err := m.iam.CreateGrant(ctx, tx, t.ID, model.NewGrant{
				PrincipalID: owner, RoleID: ownerRoleID, ResourceID: resourceID, Effect: constant.EffectAllow,
				Source: constant.SourceSystem, Reason: "created the organization", CreatedBy: actor.PrincipalID,
			}); err != nil {
				return err
			}
		}
		if actor.SessionID != "" {
			if err := m.users.SetActiveResource(ctx, tx, t.ID, actor.SessionID, resourceID); err != nil {
				return err
			}
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "organization.created", Result: model.AuditSuccess, OrganizationID: resourceID,
			ActorID: actor.PrincipalID, SessionID: actor.SessionID, TargetType: "organization", TargetID: resourceID,
			Data: map[string]any{"slug": req.Slug, "owner_id": owner}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "organization.created", map[string]any{
			"organization_id": resourceID, "slug": req.Slug, "name": req.Name, "owner_id": owner,
		}); err != nil {
			return err
		}
		out = &response.Organization{ID: resourceID, Slug: req.Slug, Name: req.Name, CreatedAt: now}
		return nil
	})
	if err != nil {
		return nil, passThrough("create organization", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *organizationModule) List(ctx context.Context, t *model.Tenant, actor model.Actor) ([]response.Organization, error) {
	var orgs []model.Organization
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		if actor.Root {
			orgs, err = m.repo.ListOrganizations(ctx, tx, t.ID)
		} else {
			orgs, err = m.repo.ListOrganizationsFor(ctx, tx, t.ID, actor.PrincipalID)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	out := make([]response.Organization, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, toOrg(o))
	}
	return out, nil
}

func (m *organizationModule) Get(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string) (*response.Organization, error) {
	var out *response.Organization
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.requireMember(ctx, tx, t, actor, org.ID); err != nil {
			return err
		}
		o := toOrg(*org)
		out = &o
		return nil
	})
	if err != nil {
		return nil, passThrough("get organization", err)
	}
	return out, nil
}

// requireMember refuses anyone who is not Root and holds no grant in the
// organization. An outsider is told "not found", not "forbidden".
func (m *organizationModule) requireMember(ctx context.Context, tx pgx.Tx, t *model.Tenant, actor model.Actor, orgID string) error {
	if actor.Root {
		return nil
	}
	member, err := m.repo.IsMember(ctx, tx, t.ID, orgID, actor.PrincipalID)
	if err != nil {
		return err
	}
	if !member {
		return errors.NotFound("organization")
	}
	return nil
}

func (m *organizationModule) Switch(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string, meta model.RequestMeta) error {
	if actor.SessionID == "" {
		return errors.ErrUnauthorized
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.requireMember(ctx, tx, t, actor, org.ID); err != nil {
			return err
		}
		// The organization's policies apply from the moment the person
		// works in it (ENT-7).
		policies, err := m.repo.GetPolicies(ctx, tx, t.ID, org.ID)
		if err != nil {
			return err
		}
		if policies != nil {
			session, err := m.users.FindSessionByID(ctx, tx, t.ID, actor.SessionID)
			if err != nil {
				return err
			}
			if session == nil {
				return errors.ErrUnauthorized
			}
			if policies.MFARequired && session.SecondFactorAt == nil {
				return errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "second_factor_required", "this organization requires a second factor. give yours first")
			}
			if len(policies.AllowedAuthMethods) > 0 && !methodAllowed(session.AuthMethods, policies.AllowedAuthMethods) {
				return errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "method_not_allowed", "this organization does not accept the way you signed in. sign in again another way")
			}
			if len(policies.IPAllowlist) > 0 && !authcore.AddressAllowed(meta.IP, policies.IPAllowlist) {
				return errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "address_not_allowed", "this organization does not allow access from this address")
			}
			if policies.SessionMaxSeconds > 0 {
				if err := m.users.CapSession(ctx, tx, t.ID, session.ID, m.now().Add(time.Duration(policies.SessionMaxSeconds)*time.Second)); err != nil {
					return err
				}
			}
		}
		return m.users.SetActiveResource(ctx, tx, t.ID, actor.SessionID, org.ID)
	})
	return passThrough("switch organization", err)
}

func methodAllowed(used []model.AuthMethod, allowed []string) bool {
	for _, u := range used {
		for _, a := range allowed {
			if u.Method == a {
				return true
			}
		}
	}
	return false
}

func (m *organizationModule) Delete(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string, meta model.RequestMeta) error {
	var org *model.Organization
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		if org, err = m.organization(ctx, tx, t, orgID); err != nil {
			return err
		}
		return m.require(ctx, tx, t, actor, constant.PermOrganizationManage, org.ID)
	})
	if err != nil {
		return passThrough("delete organization", err)
	}
	if err := m.notify.Hook(ctx, t, "organization.before_delete", map[string]any{"organization_id": org.ID, "slug": org.Slug}); err != nil {
		return err
	}
	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if err := m.repo.DeleteOrganization(ctx, tx, t.ID, org.ID, now, now.Add(constant.DeletionGrace)); err != nil {
			return err
		}
		if err := m.users.ClearActiveResource(ctx, tx, t.ID, org.ID); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "organization.deleted", Result: model.AuditSuccess, OrganizationID: org.ID,
			ActorID: actor.PrincipalID, SessionID: actor.SessionID, TargetType: "organization", TargetID: org.ID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "organization.deleted", map[string]any{"organization_id": org.ID, "slug": org.Slug})
	})
	if err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	m.notify.Wake()
	return nil
}

// ---------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------

func (m *organizationModule) ListMembers(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string) ([]response.Member, error) {
	var members []model.Member
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.requireMember(ctx, tx, t, actor, org.ID); err != nil {
			return err
		}
		members, err = m.repo.ListMembers(ctx, tx, t.ID, org.ID)
		return err
	})
	if err != nil {
		return nil, passThrough("list members", err)
	}
	out := make([]response.Member, 0, len(members))
	for _, mem := range members {
		out = append(out, response.Member{PrincipalID: mem.PrincipalID, Email: mem.Email, Name: mem.Name, Status: mem.Status, Roles: mem.Roles})
	}
	return out, nil
}

func (m *organizationModule) ChangeMemberRole(ctx context.Context, t *model.Tenant, actor model.Actor, orgID, principalID string, req request.ChangeMemberRoleRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if !postgres.IsUUID(principalID) {
		return errors.NotFound("member")
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.require(ctx, tx, t, actor, constant.PermGrantManage, org.ID); err != nil {
			return err
		}
		member, err := m.repo.IsMember(ctx, tx, t.ID, org.ID, principalID)
		if err != nil {
			return err
		}
		if !member {
			return errors.NotFound("member")
		}
		roleID, _, err := m.iam.GetRoleByName(ctx, tx, t.ID, req.Role)
		if err != nil {
			return err
		}
		if roleID == "" {
			return errors.Validation(map[string]string{"role": "does not exist"})
		}
		if err := m.mayGrant(ctx, tx, t, actor, roleID, org.ID); err != nil {
			return err
		}
		if err := m.keepAnOwner(ctx, tx, t, org.ID, principalID, roleID); err != nil {
			return err
		}
		if err := m.repo.ReplaceRoleOn(ctx, tx, t.ID, org.ID, principalID, roleID, actor.PrincipalID); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "member.role_changed", Result: model.AuditSuccess, OrganizationID: org.ID,
			ActorID: actor.PrincipalID, SessionID: actor.SessionID, TargetType: "user", TargetID: principalID,
			Data: map[string]any{"role": req.Role}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "member.role_changed", map[string]any{
			"organization_id": org.ID, "principal_id": principalID, "role": req.Role,
		})
	})
	return passThrough("change member role", err)
}

// mayGrant applies the rule that nobody hands out more than they hold.
func (m *organizationModule) mayGrant(ctx context.Context, tx pgx.Tx, t *model.Tenant, actor model.Actor, roleID, resourceID string) error {
	if actor.Root {
		return nil
	}
	ok, err := m.authz.MayGrant(ctx, tx, t.ID, actor.PrincipalID, roleID, resourceID)
	if err != nil {
		return err
	}
	if !ok {
		return errCannotGrant
	}
	return nil
}

// keepAnOwner refuses a change that would leave the organization with no
// owner (user-flow ORG-6).
func (m *organizationModule) keepAnOwner(ctx context.Context, tx pgx.Tx, t *model.Tenant, orgID, principalID, newRoleID string) error {
	ownerRoleID, err := m.ownerRole(ctx, tx, t)
	if err != nil {
		return err
	}
	if newRoleID == ownerRoleID {
		return nil
	}
	isOwner, err := m.repo.HoldsRoleOn(ctx, tx, t.ID, orgID, principalID, ownerRoleID)
	if err != nil {
		return err
	}
	if !isOwner {
		return nil
	}
	owners, err := m.repo.CountOwners(ctx, tx, t.ID, orgID, ownerRoleID)
	if err != nil {
		return err
	}
	if owners <= 1 {
		return errLastOwner
	}
	return nil
}

func (m *organizationModule) RemoveMember(ctx context.Context, t *model.Tenant, actor model.Actor, orgID, principalID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(principalID) {
		return errors.NotFound("member")
	}
	leaving := !actor.Root && actor.PrincipalID == principalID
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if !leaving {
			if err := m.require(ctx, tx, t, actor, constant.PermMemberRemove, org.ID); err != nil {
				return err
			}
		}
		member, err := m.repo.IsMember(ctx, tx, t.ID, org.ID, principalID)
		if err != nil {
			return err
		}
		if !member {
			return errors.NotFound("member")
		}
		if err := m.keepAnOwner(ctx, tx, t, org.ID, principalID, ""); err != nil {
			return err
		}
		removed, err := m.repo.RemoveMember(ctx, tx, t.ID, org.ID, principalID)
		if err != nil {
			return err
		}
		if err := m.users.ClearActiveResourceFor(ctx, tx, t.ID, principalID, org.ID); err != nil {
			return err
		}
		action := "member.removed"
		if leaving {
			action = "member.left"
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: action, Result: model.AuditSuccess, OrganizationID: org.ID,
			ActorID: actor.PrincipalID, SessionID: actor.SessionID, TargetType: "user", TargetID: principalID,
			Data: map[string]any{"grants_removed": removed}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "member.removed", map[string]any{
			"organization_id": org.ID, "principal_id": principalID, "left": leaving,
		})
	})
	return passThrough("remove member", err)
}

// ---------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------

func (m *organizationModule) Invite(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string, req request.InviteRequest, meta model.RequestMeta) (*response.Invitation, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	raw := secret.Token(32)
	var out *response.Invitation
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.require(ctx, tx, t, actor, constant.PermMemberInvite, org.ID); err != nil {
			return err
		}
		roleID, _, err := m.iam.GetRoleByName(ctx, tx, t.ID, req.Role)
		if err != nil {
			return err
		}
		if roleID == "" {
			return errors.Validation(map[string]string{"role": "does not exist"})
		}
		// Where the role applies: the organization, or one place inside it.
		targetID, targetRef := org.ID, model.ResourceRef{Type: constant.ResourceTypeOrganization, ID: org.Slug}
		if req.Resource != nil {
			targetRef = model.ResourceRef{Type: req.Resource.Type, ID: req.Resource.ID}
			targetID, _, err = m.iam.FindResource(ctx, tx, t.ID, targetRef)
			if err != nil {
				return err
			}
			under := false
			if targetID != "" {
				if under, err = m.iam.IsUnder(ctx, tx, t.ID, targetID, org.ID); err != nil {
					return err
				}
			}
			if !under {
				return errors.Validation(map[string]string{"resource": "is not inside this organization"})
			}
		}
		if err := m.mayGrant(ctx, tx, t, actor, roleID, targetID); err != nil {
			return err
		}
		// Someone who already belongs needs a role change, not an invitation.
		existing, err := m.users.FindUserByEmail(ctx, tx, t.ID, req.Email)
		if err != nil {
			return err
		}
		if existing != nil {
			member, err := m.repo.IsMember(ctx, tx, t.ID, org.ID, existing.PrincipalID)
			if err != nil {
				return err
			}
			if member {
				return errAlreadyIn
			}
		}
		// A new invitation replaces any pending one for the same address.
		if err := m.repo.RevokeInvitationsFor(ctx, tx, t.ID, org.ID, req.Email, now); err != nil {
			return err
		}
		invitationID, err := m.repo.CreateInvitation(ctx, tx, t.ID, model.NewInvitation{
			Email: req.Email, RoleID: roleID, ResourceID: targetID, InviterID: actor.PrincipalID,
			TokenHash: secret.Hash(raw), ExpiresAt: now.Add(constant.InvitationTTL),
		})
		if err != nil {
			return err
		}
		inviter := "An administrator"
		if actor.PrincipalID != "" {
			if u, err := m.users.GetUser(ctx, tx, t.ID, actor.PrincipalID); err == nil && u != nil {
				if u.Name != "" {
					inviter = u.Name
				} else {
					inviter = u.Email
				}
			}
		}
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: req.Email, Template: constant.TemplateInvitation,
			Data: map[string]string{
				"token": raw, "link": authcore.Link(t.AppURL, authcore.InvitationPath, raw),
				"organization": org.Name, "role": req.Role, "inviter": inviter,
			},
		}); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "invitation.created", Result: model.AuditSuccess, OrganizationID: org.ID,
			ActorID: actor.PrincipalID, SessionID: actor.SessionID, TargetType: "invitation", TargetID: invitationID,
			Data: map[string]any{"role": req.Role}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "invitation.created", map[string]any{
			"organization_id": org.ID, "invitation_id": invitationID, "role": req.Role,
		}); err != nil {
			return err
		}
		out = &response.Invitation{
			ID: invitationID, Email: req.Email, Role: req.Role,
			Resource:       response.Resource{ID: targetID, Type: targetRef.Type, ExternalID: targetRef.ID},
			OrganizationID: org.ID, OrganizationName: org.Name, InvitedBy: inviter,
			ExpiresAt: now.Add(constant.InvitationTTL), CreatedAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("invite", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *organizationModule) ListInvitations(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string) ([]response.Invitation, error) {
	var invitations []model.Invitation
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.require(ctx, tx, t, actor, constant.PermMemberInvite, org.ID); err != nil {
			return err
		}
		invitations, err = m.repo.ListInvitations(ctx, tx, t.ID, org.ID)
		return err
	})
	if err != nil {
		return nil, passThrough("list invitations", err)
	}
	out := make([]response.Invitation, 0, len(invitations))
	for _, i := range invitations {
		out = append(out, toInvitation(i))
	}
	return out, nil
}

func (m *organizationModule) RevokeInvitation(ctx context.Context, t *model.Tenant, actor model.Actor, orgID, invitationID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(invitationID) {
		return errors.NotFound("invitation")
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.organization(ctx, tx, t, orgID)
		if err != nil {
			return err
		}
		if err := m.require(ctx, tx, t, actor, constant.PermMemberInvite, org.ID); err != nil {
			return err
		}
		inv, err := m.repo.GetInvitation(ctx, tx, t.ID, invitationID)
		if err != nil {
			return err
		}
		if inv == nil || inv.OrganizationID != org.ID || !pending(inv, m.now()) {
			return errors.NotFound("invitation")
		}
		if err := m.repo.MarkInvitationRevoked(ctx, tx, t.ID, inv.ID, m.now()); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "invitation.revoked", Result: model.AuditSuccess, OrganizationID: org.ID,
			ActorID: actor.PrincipalID, SessionID: actor.SessionID, TargetType: "invitation", TargetID: inv.ID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "invitation.revoked", map[string]any{"organization_id": org.ID, "invitation_id": inv.ID})
	})
	return passThrough("revoke invitation", err)
}

func pending(inv *model.Invitation, now time.Time) bool {
	return inv.AcceptedAt == nil && inv.DeclinedAt == nil && inv.RevokedAt == nil && now.Before(inv.ExpiresAt)
}

// lockInvitation finds a live invitation by its token. Unknown, used,
// withdrawn and expired all read the same.
func (m *organizationModule) lockInvitation(ctx context.Context, tx pgx.Tx, t *model.Tenant, token string) (*model.Invitation, error) {
	if token == "" {
		return nil, errors.ErrInvalidToken
	}
	inv, err := m.repo.LockInvitationByToken(ctx, tx, t.ID, secret.Hash(token))
	if err != nil {
		return nil, err
	}
	if inv == nil || !pending(inv, m.now()) {
		return nil, errors.ErrInvalidToken
	}
	return inv, nil
}

func (m *organizationModule) Preview(ctx context.Context, t *model.Tenant, token string) (*response.InvitationPreview, error) {
	var out *response.InvitationPreview
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		inv, err := m.lockInvitation(ctx, tx, t, token)
		if err != nil {
			return err
		}
		existing, err := m.users.FindUserByEmail(ctx, tx, t.ID, inv.Email)
		if err != nil {
			return err
		}
		out = &response.InvitationPreview{
			Email: inv.Email, Role: inv.RoleName, OrganizationName: inv.OrganizationName, InvitedBy: inv.InviterName,
			ExpiresAt: inv.ExpiresAt, AccountExists: existing != nil,
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("preview invitation", err)
	}
	return out, nil
}

func (m *organizationModule) Accept(ctx context.Context, t *model.Tenant, actor model.Actor, req request.InvitationTokenRequest, meta model.RequestMeta) (*response.Organization, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if actor.Root || actor.PrincipalID == "" {
		return nil, errors.ErrUnauthorized
	}
	var out *response.Organization
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		inv, err := m.lockInvitation(ctx, tx, t, req.Token)
		if err != nil {
			return err
		}
		user, err := m.users.GetUser(ctx, tx, t.ID, actor.PrincipalID)
		if err != nil {
			return err
		}
		// Bound to one address. Forwarding the link gives the receiver nothing.
		if user == nil || !strings.EqualFold(user.Email, inv.Email) {
			return errWrongAccount
		}
		if err := m.join(ctx, tx, t, inv, actor.PrincipalID, actor.SessionID, meta); err != nil {
			return err
		}
		org, err := m.repo.GetOrganization(ctx, tx, t.ID, inv.OrganizationID)
		if err != nil {
			return err
		}
		if org == nil {
			return errors.ErrInvalidToken
		}
		o := toOrg(*org)
		out = &o
		return nil
	})
	if err != nil {
		return nil, passThrough("accept invitation", err)
	}
	m.notify.Wake()
	return out, nil
}

// join writes what accepting means: a grant, and nothing else. It never
// touches the person's credentials.
func (m *organizationModule) join(ctx context.Context, tx pgx.Tx, t *model.Tenant, inv *model.Invitation, principalID, sessionID string, meta model.RequestMeta) error {
	now := m.now()
	if _, err := m.iam.CreateGrant(ctx, tx, t.ID, model.NewGrant{
		PrincipalID: principalID, RoleID: inv.RoleID, ResourceID: inv.ResourceID, Effect: constant.EffectAllow,
		Source: constant.GrantSourceInvite, Reason: "accepted invitation " + inv.ID, CreatedBy: inv.InviterID,
	}); err != nil {
		return err
	}
	if err := m.repo.MarkInvitationAccepted(ctx, tx, t.ID, inv.ID, principalID, now); err != nil {
		return err
	}
	if sessionID != "" && inv.OrganizationID != "" {
		if err := m.users.SetActiveResource(ctx, tx, t.ID, sessionID, inv.OrganizationID); err != nil {
			return err
		}
	}
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "invitation.accepted", Result: model.AuditSuccess, OrganizationID: inv.OrganizationID,
		ActorID: principalID, SessionID: sessionID, TargetType: "invitation", TargetID: inv.ID,
		Data: map[string]any{"role": inv.RoleName}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return err
	}
	if err := m.notify.Emit(ctx, tx, t.ID, "invitation.accepted", map[string]any{
		"organization_id": inv.OrganizationID, "invitation_id": inv.ID, "principal_id": principalID,
	}); err != nil {
		return err
	}
	return m.notify.Emit(ctx, tx, t.ID, "member.added", map[string]any{
		"organization_id": inv.OrganizationID, "principal_id": principalID, "role": inv.RoleName,
	})
}

func (m *organizationModule) Decline(ctx context.Context, t *model.Tenant, req request.InvitationTokenRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		inv, err := m.lockInvitation(ctx, tx, t, req.Token)
		if err != nil {
			return err
		}
		if err := m.repo.MarkInvitationDeclined(ctx, tx, t.ID, inv.ID, m.now()); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "invitation.declined", Result: model.AuditSuccess, OrganizationID: inv.OrganizationID,
			TargetType: "invitation", TargetID: inv.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough("decline invitation", err)
}

func (m *organizationModule) SignUp(ctx context.Context, t *model.Tenant, req request.InvitationSignUpRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if m.breach != nil {
		if leaked, err := m.breach.Breached(ctx, req.Password); err == nil && leaked {
			return nil, errors.Validation(map[string]string{"password": "appears in a list of leaked passwords. choose another one"})
		}
	}
	hash, err := secret.HashPassword(req.Password, m.params)
	if err != nil {
		return nil, fmt.Errorf("invitation sign-up: %w", err)
	}
	now := m.now()
	var out *response.AuthResponse
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		inv, err := m.lockInvitation(ctx, tx, t, req.Token)
		if err != nil {
			return err
		}
		existing, err := m.users.FindUserByEmail(ctx, tx, t.ID, inv.Email)
		if err != nil {
			return err
		}
		if existing != nil {
			return errAccountExist
		}
		if err := m.withinLimit(ctx, tx, t.ID, constant.MetricUsers, func() (int64, error) { return m.users.CountUsers(ctx, tx, t.ID) }); err != nil {
			return err
		}
		principalID, err := m.users.CreateUser(ctx, tx, t.ID, inv.Email, req.Name)
		if err != nil {
			return err
		}
		if err := m.users.SetPassword(ctx, tx, t.ID, principalID, hash); err != nil {
			return err
		}
		// The link arrived in this mailbox, which is proof enough of it.
		if err := m.users.MarkEmailVerified(ctx, tx, t.ID, principalID, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.created", Result: model.AuditSuccess, ReasonCode: "by_invitation", OrganizationID: inv.OrganizationID,
			ActorID: principalID, TargetType: "user", TargetID: principalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.created", map[string]any{"user_id": principalID, "by": "invitation"}); err != nil {
			return err
		}
		out, err = m.auth.StartSession(ctx, tx, t, principalID, "invitation", meta)
		if err != nil {
			return err
		}
		return m.join(ctx, tx, t, inv, principalID, out.Session.ID, meta)
	})
	if err != nil {
		return nil, passThrough("invitation sign-up", err)
	}
	m.notify.Wake()
	return out, nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func toOrg(o model.Organization) response.Organization {
	return response.Organization{ID: o.ID, Slug: o.Slug, Name: o.Name, CreatedAt: o.CreatedAt}
}

func toInvitation(i model.Invitation) response.Invitation {
	return response.Invitation{
		ID: i.ID, Email: i.Email, Role: i.RoleName,
		Resource:       response.Resource{ID: i.ResourceID, Type: i.ResourceType, ExternalID: i.ResourceExtID},
		OrganizationID: i.OrganizationID, OrganizationName: i.OrganizationName, InvitedBy: i.InviterName,
		ExpiresAt: i.ExpiresAt, CreatedAt: i.CreatedAt,
	}
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
