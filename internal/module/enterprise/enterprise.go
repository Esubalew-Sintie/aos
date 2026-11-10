// Package enterprise is the company side (user-flow ENT-1 to ENT-7): a
// connection to a company's identity provider that its IT admin sets up
// through a link, verified domains, sign-in through the provider,
// directory sync, and organization policies.
package enterprise

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
	"github.com/flash-software-technology/aos/platform/oidc"
	"github.com/flash-software-technology/aos/platform/postgres"
	"github.com/flash-software-technology/aos/platform/secret"
)

// DNSLookup answers a TXT lookup. It is replaced in tests.
type DNSLookup func(ctx context.Context, name string) ([]string, error)

type enterpriseModule struct {
	db        *postgres.DB
	repo      storage.EnterpriseRepository
	orgs      storage.OrganizationRepository
	users     storage.AuthRepository
	iam       storage.IAMRepository
	audit     storage.AuditRepository
	notify    module.Notification
	authz     module.Authorizer
	auth      module.Auth
	keys      module.KeyRing
	oidc      *oidc.Client
	dns       DNSLookup
	publicURL string
	now       func() time.Time
	log       logger.Logger
}

func NewEnterpriseModule(db *postgres.DB, repo storage.EnterpriseRepository, orgs storage.OrganizationRepository, users storage.AuthRepository,
	iam storage.IAMRepository, audit storage.AuditRepository, notify module.Notification, authz module.Authorizer, auth module.Auth,
	keys module.KeyRing, oidcClient *oidc.Client, dns DNSLookup, publicURL string, now func() time.Time, log logger.Logger) module.Enterprise {
	return &enterpriseModule{db: db, repo: repo, orgs: orgs, users: users, iam: iam, audit: audit, notify: notify, authz: authz, auth: auth,
		keys: keys, oidc: oidcClient, dns: dns, publicURL: strings.TrimRight(publicURL, "/"), now: now, log: log}
}

var (
	errForbidden     = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "forbidden", "you may not do this here")
	errSetupInvalid  = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "setup_link_invalid", "this setup link is no longer valid. ask the organization admin for a new one")
	errNotReady      = errors.Conflict("connection_incomplete", "the connection needs its settings, a verified domain and a successful test before it is activated")
	errDomainTaken   = errors.Conflict("domain_taken", "another organization has verified this domain")
	errNoConnection  = errors.New(errors.ErrorTypeNotFound, http.StatusNotFound, "no_enterprise_connection", "this address is not bound to a company identity provider")
	errSSOFailed     = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "sso_failed", "the sign-in with the identity provider did not complete. try again")
	errSAMLNotBuilt  = errors.New(errors.ErrorTypeBadRequest, http.StatusNotImplemented, "saml_not_available", "sign-in with SAML is not available yet. use an OpenID Connect connection")
	errDirectoryGone = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "invalid_token", "the sync token is not valid")
)

func (m *enterpriseModule) require(ctx context.Context, tx pgx.Tx, t *model.Tenant, actor model.Actor, permission, resourceID string) error {
	if actor.Root {
		return nil
	}
	ok, _, err := m.authz.Check(ctx, tx, t.ID, actor.PrincipalID, permission, resourceID)
	if err != nil {
		return err
	}
	if !ok {
		return errForbidden
	}
	return nil
}

// redirectURI is the return address the IT admin pastes into the
// identity provider: a page of the application that posts the answer
// back to the engine.
func (m *enterpriseModule) redirectURI(t *model.Tenant) string {
	return strings.TrimRight(t.AppURL, "/") + "/auth/sso/callback"
}

func (m *enterpriseModule) scimURL(t *model.Tenant) string {
	return m.publicURL + "/scim/v2"
}

func secretContext(tenantID, connectionID string) []byte {
	return []byte("sso:" + tenantID + ":" + connectionID)
}

// ---------------------------------------------------------------------
// Connections, from the organization admin's side (ENT-1 steps 1 and 2)
// ---------------------------------------------------------------------

func (m *enterpriseModule) CreateConnection(ctx context.Context, t *model.Tenant, actor model.Actor, req request.CreateConnectionRequest, meta model.RequestMeta) (*response.SetupLink, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out *response.SetupLink
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		org, err := m.orgs.GetOrganization(ctx, tx, t.ID, req.OrganizationID)
		if err != nil {
			return err
		}
		if org == nil {
			return errors.NotFound("organization")
		}
		if err := m.require(ctx, tx, t, actor, constant.PermSSOManage, org.ID); err != nil {
			return err
		}
		id, err := m.repo.CreateConnection(ctx, tx, t.ID, model.SSOConnection{OrganizationID: org.ID, Name: req.Name, Protocol: req.Protocol})
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "sso.connection_created", Result: model.AuditSuccess, OrganizationID: org.ID, ActorID: actor.PrincipalID, SessionID: actor.SessionID,
			TargetType: "sso_connection", TargetID: id, Data: map[string]any{"protocol": req.Protocol}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		out, err = m.setupLink(ctx, tx, t, id, actor)
		return err
	})
	if err != nil {
		return nil, passThrough("create connection", err)
	}
	return out, nil
}

func (m *enterpriseModule) setupLink(ctx context.Context, tx pgx.Tx, t *model.Tenant, connectionID string, actor model.Actor) (*response.SetupLink, error) {
	raw := secret.Token(32)
	expires := m.now().Add(constant.SSOSetupTTL)
	if _, err := m.users.CreateToken(ctx, tx, t.ID, model.NewToken{
		Purpose: constant.TokenSSOSetup, PrincipalID: actor.PrincipalID, Hash: secret.Hash(raw), ExpiresAt: expires,
		Payload: map[string]string{"connection_id": connectionID},
	}); err != nil {
		return nil, err
	}
	return &response.SetupLink{ConnectionID: connectionID, Token: raw, Link: authcore.Link(t.AppURL, "/auth/sso/setup", raw), ExpiresAt: expires}, nil
}

func (m *enterpriseModule) NewSetupLink(ctx context.Context, t *model.Tenant, actor model.Actor, connectionID string, meta model.RequestMeta) (*response.SetupLink, error) {
	var out *response.SetupLink
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.repo.GetConnection(ctx, tx, t.ID, connectionID)
		if err != nil {
			return err
		}
		if c == nil {
			return errors.NotFound("connection")
		}
		if err := m.require(ctx, tx, t, actor, constant.PermSSOManage, c.OrganizationID); err != nil {
			return err
		}
		out, err = m.setupLink(ctx, tx, t, c.ID, actor)
		return err
	})
	if err != nil {
		return nil, passThrough("new setup link", err)
	}
	return out, nil
}

func (m *enterpriseModule) ListConnections(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string) ([]response.SSOConnection, error) {
	if !postgres.IsUUID(organizationID) {
		return nil, errors.NotFound("organization")
	}
	out := []response.SSOConnection{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if err := m.require(ctx, tx, t, actor, constant.PermSSOManage, organizationID); err != nil {
			return err
		}
		list, err := m.repo.ListConnections(ctx, tx, t.ID, organizationID)
		if err != nil {
			return err
		}
		for _, c := range list {
			v, err := m.view(ctx, tx, t, &c)
			if err != nil {
				return err
			}
			out = append(out, *v)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list connections", err)
	}
	return out, nil
}

func (m *enterpriseModule) DisableConnection(ctx context.Context, t *model.Tenant, actor model.Actor, connectionID string, meta model.RequestMeta) error {
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.repo.GetConnection(ctx, tx, t.ID, connectionID)
		if err != nil {
			return err
		}
		if c == nil {
			return errors.NotFound("connection")
		}
		if err := m.require(ctx, tx, t, actor, constant.PermSSOManage, c.OrganizationID); err != nil {
			return err
		}
		if err := m.repo.SetConnectionStatus(ctx, tx, t.ID, c.ID, constant.SSOStatusDisabled, m.now()); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "sso.connection_disabled", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, ActorID: actor.PrincipalID,
			TargetType: "sso_connection", TargetID: c.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough("disable connection", err)
}

func (m *enterpriseModule) view(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.SSOConnection) (*response.SSOConnection, error) {
	mappings, err := m.repo.ListGroupMappings(ctx, tx, t.ID, c.ID)
	if err != nil {
		return nil, err
	}
	domains, err := m.repo.ListDomains(ctx, tx, t.ID, c.OrganizationID)
	if err != nil {
		return nil, err
	}
	out := &response.SSOConnection{
		ID: c.ID, OrganizationID: c.OrganizationID, Name: c.Name, Protocol: c.Protocol, Status: c.Status, Issuer: c.Issuer, ClientID: c.ClientID,
		SAMLEntityID: c.SAMLEntityID, SAMLSSOURL: c.SAMLSSOURL, TrustIdPSecondFactor: c.TrustIdPSecondFactor, LastTest: c.LastTest,
		CreatedAt: c.CreatedAt, ActivatedAt: c.ActivatedAt, RedirectURI: m.redirectURI(t), SCIMURL: m.scimURL(t),
		Mappings: []response.GroupMapping{}, Domains: []response.Domain{},
	}
	if c.DefaultRoleID != "" {
		_ = tx.QueryRow(ctx, `SELECT name FROM aos.roles WHERE tenant_id = $1 AND id = $2`, t.ID, c.DefaultRoleID).Scan(&out.DefaultRole)
	}
	for _, mp := range mappings {
		nodes, err := m.iam.Ancestors(ctx, tx, t.ID, mp.ResourceID)
		if err != nil {
			return nil, err
		}
		res := response.Resource{ID: mp.ResourceID}
		if len(nodes) > 0 {
			res.Type, res.ExternalID = nodes[0].Type, nodes[0].ExternalID
		}
		out.Mappings = append(out.Mappings, response.GroupMapping{Group: mp.ExternalGroup, Role: mp.RoleName, Resource: res})
	}
	for _, d := range domains {
		out.Domains = append(out.Domains, toDomain(d))
	}
	return out, nil
}

func toDomain(d model.VerifiedDomain) response.Domain {
	return response.Domain{ID: d.ID, Domain: d.Domain, Verified: d.VerifiedAt != nil, VerifiedAt: d.VerifiedAt,
		RecordName: constant.DomainVerificationPrefix + d.Domain, RecordValue: "aos-verify=" + d.TXTValue}
}

// ---------------------------------------------------------------------
// The setup page (ENT-1 steps 3 to 11, ENT-2)
// ---------------------------------------------------------------------

// bySetupToken finds the connection a setup link opens.
func (m *enterpriseModule) bySetupToken(ctx context.Context, tx pgx.Tx, t *model.Tenant, token string) (*model.SSOConnection, error) {
	if token == "" {
		return nil, errSetupInvalid
	}
	tk, err := m.users.LockToken(ctx, tx, t.ID, constant.TokenSSOSetup, secret.Hash(token))
	if err != nil {
		return nil, err
	}
	if tk == nil || tk.UsedAt != nil || !m.now().Before(tk.ExpiresAt) {
		return nil, errSetupInvalid
	}
	c, err := m.repo.GetConnection(ctx, tx, t.ID, tk.Payload["connection_id"])
	if err != nil {
		return nil, err
	}
	if c == nil || c.Status == constant.SSOStatusDisabled {
		return nil, errSetupInvalid
	}
	return c, nil
}

func (m *enterpriseModule) SetupView(ctx context.Context, t *model.Tenant, token string) (*response.SSOConnection, error) {
	var out *response.SSOConnection
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		out, err = m.view(ctx, tx, t, c)
		return err
	})
	if err != nil {
		return nil, passThrough("setup view", err)
	}
	return out, nil
}

func (m *enterpriseModule) SetupSettings(ctx context.Context, t *model.Tenant, token string, req request.ConnectionSettingsRequest, meta model.RequestMeta) (*response.SSOConnection, error) {
	var out *response.SSOConnection
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		if err := req.Validate(c.Protocol); err != nil {
			return err
		}
		if c.Protocol == constant.SSOProtocolOIDC {
			// The issuer must answer, so a typo shows now.
			if _, err := m.oidc.Discover(ctx, req.Issuer); err != nil {
				return errors.Validation(map[string]string{"issuer": "could not be reached: " + err.Error()})
			}
		}
		update := model.SSOConnection{ID: c.ID, Name: req.Name, Issuer: req.Issuer, ClientID: req.ClientID,
			SAMLEntityID: req.SAMLEntityID, SAMLSSOURL: req.SAMLSSOURL, SAMLCertificate: req.SAMLCertificate}
		if req.ClientSecret != "" {
			keyID, key, err := m.keys.DataKey(ctx, tx, t.ID)
			if err != nil {
				return err
			}
			sealed, err := secret.Seal(key, []byte(req.ClientSecret), secretContext(t.ID, c.ID))
			if err != nil {
				return err
			}
			update.ClientSecretEncrypted, update.DataKeyID = sealed, keyID
		}
		if err := m.repo.UpdateConnectionSettings(ctx, tx, t.ID, update); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "sso.settings_changed", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, TargetType: "sso_connection", TargetID: c.ID,
			Data: map[string]any{"by": "setup_link", "issuer": req.Issuer}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		c, err = m.repo.GetConnection(ctx, tx, t.ID, c.ID)
		if err != nil {
			return err
		}
		out, err = m.view(ctx, tx, t, c)
		return err
	})
	if err != nil {
		return nil, passThrough("setup settings", err)
	}
	return out, nil
}

func (m *enterpriseModule) SetupMappings(ctx context.Context, t *model.Tenant, token string, req request.MappingsRequest, meta model.RequestMeta) (*response.SSOConnection, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out *response.SSOConnection
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		mappings := make([]model.GroupMapping, 0, len(req.Mappings))
		for _, mp := range req.Mappings {
			roleID, _, err := m.iam.GetRoleByName(ctx, tx, t.ID, mp.Role)
			if err != nil {
				return err
			}
			if roleID == "" {
				return errors.Validation(map[string]string{"mappings": "role " + mp.Role + " does not exist"})
			}
			resourceID := c.OrganizationID
			if mp.Resource != nil {
				resourceID, _, err = m.iam.FindResource(ctx, tx, t.ID, model.ResourceRef{Type: mp.Resource.Type, ID: mp.Resource.ID})
				if err != nil {
					return err
				}
				under := false
				if resourceID != "" {
					if under, err = m.iam.IsUnder(ctx, tx, t.ID, resourceID, c.OrganizationID); err != nil {
						return err
					}
				}
				if !under {
					return errors.Validation(map[string]string{"mappings": "a resource is not inside this organization"})
				}
			}
			mappings = append(mappings, model.GroupMapping{ExternalGroup: strings.TrimSpace(mp.Group), RoleID: roleID, ResourceID: resourceID})
		}
		if err := m.repo.ReplaceGroupMappings(ctx, tx, t.ID, c.ID, mappings); err != nil {
			return err
		}
		defaultRoleID := c.DefaultRoleID
		if req.DefaultRole != "" {
			defaultRoleID, _, err = m.iam.GetRoleByName(ctx, tx, t.ID, req.DefaultRole)
			if err != nil {
				return err
			}
			if defaultRoleID == "" {
				return errors.Validation(map[string]string{"default_role": "does not exist"})
			}
		}
		trust := c.TrustIdPSecondFactor
		if req.TrustIdPSecondFactor != nil {
			trust = *req.TrustIdPSecondFactor
		}
		if err := m.repo.SetConnectionDefaultRole(ctx, tx, t.ID, c.ID, defaultRoleID, trust); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "sso.mappings_changed", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, TargetType: "sso_connection", TargetID: c.ID,
			Data: map[string]any{"mappings": len(mappings), "default_role": req.DefaultRole}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		c, err = m.repo.GetConnection(ctx, tx, t.ID, c.ID)
		if err != nil {
			return err
		}
		out, err = m.view(ctx, tx, t, c)
		return err
	})
	if err != nil {
		return nil, passThrough("setup mappings", err)
	}
	return out, nil
}

func (m *enterpriseModule) SetupAddDomain(ctx context.Context, t *model.Tenant, token string, req request.DomainRequest, meta model.RequestMeta) (*response.Domain, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var out *response.Domain
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		id, err := m.repo.CreateDomain(ctx, tx, t.ID, c.OrganizationID, req.Domain, secret.HexID(16))
		if err != nil {
			return err
		}
		d, err := m.repo.GetDomain(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		r := toDomain(*d)
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("add domain", err)
	}
	return out, nil
}

// SetupVerifyDomain does the DNS lookup (ENT-2 step 4). It is called
// again when the record has not spread yet.
func (m *enterpriseModule) SetupVerifyDomain(ctx context.Context, t *model.Tenant, token, domainID string, meta model.RequestMeta) (*response.Domain, error) {
	var out *response.Domain
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		d, err := m.repo.GetDomain(ctx, tx, t.ID, domainID)
		if err != nil {
			return err
		}
		if d == nil || d.OrganizationID != c.OrganizationID {
			return errors.NotFound("domain")
		}
		records, _ := m.dns(ctx, constant.DomainVerificationPrefix+d.Domain)
		found := false
		for _, r := range records {
			if strings.TrimSpace(r) == "aos-verify="+d.TXTValue {
				found = true
			}
		}
		if err := m.repo.MarkDomainChecked(ctx, tx, t.ID, d.ID, found, m.now()); err != nil {
			if postgres.IsUniqueViolation(err) {
				return errDomainTaken
			}
			return err
		}
		if found && d.VerifiedAt == nil {
			if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "sso.domain_verified", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, TargetType: "domain", TargetID: d.Domain,
				RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			}); err != nil {
				return err
			}
		}
		d, err = m.repo.GetDomain(ctx, tx, t.ID, d.ID)
		if err != nil {
			return err
		}
		r := toDomain(*d)
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("verify domain", err)
	}
	return out, nil
}

// SetupTest starts a test sign-in. The answer is shown on the page, and
// no session is made (ENT-1 step 8).
func (m *enterpriseModule) SetupTest(ctx context.Context, t *model.Tenant, token string, req request.SocialStartRequest, meta model.RequestMeta) (*response.SSOStart, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var c *model.SSOConnection
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		c, err = m.bySetupToken(ctx, tx, t, token)
		return err
	})
	if err != nil {
		return nil, passThrough("setup test", err)
	}
	return m.start(ctx, t, c, req.RedirectURI, req.SessionKind, true)
}

func (m *enterpriseModule) SetupActivate(ctx context.Context, t *model.Tenant, token string, meta model.RequestMeta) (*response.SSOConnection, error) {
	var out *response.SSOConnection
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		if c.Protocol == constant.SSOProtocolSAML {
			return errSAMLNotBuilt
		}
		domains, err := m.repo.ListDomains(ctx, tx, t.ID, c.OrganizationID)
		if err != nil {
			return err
		}
		verified := false
		for _, d := range domains {
			if d.VerifiedAt != nil {
				verified = true
			}
		}
		tested, _ := c.LastTest["ok"].(bool)
		if c.Issuer == "" || c.ClientID == "" || !verified || !tested {
			return errNotReady
		}
		if err := m.repo.SetConnectionStatus(ctx, tx, t.ID, c.ID, constant.SSOStatusActive, m.now()); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "sso.connection.activated", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, TargetType: "sso_connection", TargetID: c.ID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "sso.connection.activated", map[string]any{"connection_id": c.ID, "organization_id": c.OrganizationID}); err != nil {
			return err
		}
		c, err = m.repo.GetConnection(ctx, tx, t.ID, c.ID)
		if err != nil {
			return err
		}
		out, err = m.view(ctx, tx, t, c)
		return err
	})
	if err != nil {
		return nil, passThrough("activate connection", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *enterpriseModule) SetupCreateDirectory(ctx context.Context, t *model.Tenant, token string, req request.CreateDirectoryRequest, meta model.RequestMeta) (*response.Directory, error) {
	raw := secret.Token(32)
	var out *response.Directory
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.bySetupToken(ctx, tx, t, token)
		if err != nil {
			return err
		}
		roleID := c.DefaultRoleID
		if req.DefaultRole != "" {
			roleID, _, err = m.iam.GetRoleByName(ctx, tx, t.ID, req.DefaultRole)
			if err != nil {
				return err
			}
			if roleID == "" {
				return errors.Validation(map[string]string{"default_role": "does not exist"})
			}
		}
		// One live directory per organization: a new token replaces the old.
		existing, err := m.repo.ListDirectories(ctx, tx, t.ID, c.OrganizationID)
		if err != nil {
			return err
		}
		for _, d := range existing {
			if d.DisabledAt == nil {
				if err := m.repo.DisableDirectory(ctx, tx, t.ID, d.ID, m.now()); err != nil {
					return err
				}
			}
		}
		id, err := m.repo.CreateDirectory(ctx, tx, t.ID, c.OrganizationID, secret.Hash(raw), roleID)
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "directory.created", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, TargetType: "directory", TargetID: id,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		out = &response.Directory{ID: id, DefaultRole: req.DefaultRole, SCIMURL: m.scimURL(t), CreatedAt: m.now(), Token: raw}
		return nil
	})
	if err != nil {
		return nil, passThrough("create directory", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Enterprise sign-in (ENT-3, ENT-4)
// ---------------------------------------------------------------------

func (m *enterpriseModule) ConnectionForEmail(ctx context.Context, tx pgx.Tx, t *model.Tenant, email string) (*model.SSOConnection, *model.OrgPolicies, error) {
	c, err := m.repo.ConnectionForDomain(ctx, tx, t.ID, authcore.EmailDomain(email))
	if err != nil || c == nil {
		return nil, nil, err
	}
	p, err := m.orgs.GetPolicies(ctx, tx, t.ID, c.OrganizationID)
	return c, p, err
}

func (m *enterpriseModule) StartSSO(ctx context.Context, t *model.Tenant, req request.SSOStartRequest, meta model.RequestMeta) (*response.SSOStart, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var c *model.SSOConnection
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		c, _, err = m.ConnectionForEmail(ctx, tx, t, req.Email)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("start sso: %w", err)
	}
	if c == nil {
		return nil, errNoConnection
	}
	return m.start(ctx, t, c, req.RedirectURI, req.SessionKind, false)
}

func (m *enterpriseModule) start(ctx context.Context, t *model.Tenant, c *model.SSOConnection, redirectURI, kind string, test bool) (*response.SSOStart, error) {
	if c.Protocol != constant.SSOProtocolOIDC {
		return nil, errSAMLNotBuilt
	}
	if c.Issuer == "" || c.ClientID == "" {
		return nil, errNotReady
	}
	state := secret.Token(24)
	nonce := secret.Token(16)
	verifier, err := oidc.NewVerifier()
	if err != nil {
		return nil, err
	}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		// The browser may only be sent back to the application.
		if ok, err := m.redirectAllowed(ctx, tx, t, redirectURI); err != nil || !ok {
			if err != nil {
				return err
			}
			return errors.Validation(map[string]string{"redirect_uri": "must be on one of the application's allowed origins"})
		}
		_, err := m.users.CreateChallenge(ctx, tx, t.ID, model.NewChallenge{
			Kind: constant.ChallengeOAuthState, TokenHash: secret.Hash(state),
			Data:      map[string]any{"sso": c.ID, "nonce": nonce, "verifier": verifier, "redirect_uri": redirectURI, "kind": kind, "test": test},
			ExpiresAt: m.now().Add(constant.SocialCeremonyTTL),
		})
		return err
	})
	if err != nil {
		return nil, passThrough("start sso", err)
	}
	discovered, err := m.oidc.Discover(ctx, c.Issuer)
	if err != nil {
		m.log.Error(ctx, "identity provider unreachable", "connection_id", c.ID, "error", err.Error())
		return nil, errSSOFailed
	}
	return &response.SSOStart{
		AuthorizationURL: oidc.AuthorizationURL(discovered, c.ClientID, redirectURI, state, nonce, verifier, []string{"openid", "email", "profile", "groups"}),
		State:            state, ConnectionID: c.ID,
	}, nil
}

func (m *enterpriseModule) redirectAllowed(ctx context.Context, tx pgx.Tx, t *model.Tenant, redirectURI string) (bool, error) {
	if t.AppURL != "" && strings.HasPrefix(redirectURI, strings.TrimRight(t.AppURL, "/")) {
		return true, nil
	}
	i := strings.Index(redirectURI, "://")
	if i < 0 {
		return false, nil
	}
	rest := redirectURI[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM aos.allowed_origins WHERE tenant_id = $1 AND origin = $2)`, t.ID, redirectURI[:i+3]+rest).Scan(&ok)
	return ok, err
}

func (m *enterpriseModule) FinishSSO(ctx context.Context, t *model.Tenant, req request.SocialFinishRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	var (
		c   *model.SSOConnection
		ch  *model.Challenge
		sec string
	)
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		ch, err = m.users.LockChallengeByToken(ctx, tx, t.ID, constant.ChallengeOAuthState, secret.Hash(req.State))
		if err != nil {
			return err
		}
		if ch == nil {
			return errSSOFailed
		}
		connID, _ := ch.Data["sso"].(string)
		if ch.ConsumedAt != nil || !now.Before(ch.ExpiresAt) || connID == "" {
			return errSSOFailed
		}
		if err := m.users.ConsumeChallenge(ctx, tx, t.ID, ch.ID, now); err != nil {
			return err
		}
		c, err = m.repo.GetConnection(ctx, tx, t.ID, connID)
		if err != nil {
			return err
		}
		if c == nil || c.Status == constant.SSOStatusDisabled {
			return errSSOFailed
		}
		if len(c.ClientSecretEncrypted) > 0 {
			key, err := m.keys.DataKeyByID(ctx, tx, t.ID, c.DataKeyID)
			if err != nil {
				return err
			}
			plain, err := secret.Open(key, c.ClientSecretEncrypted, secretContext(t.ID, c.ID))
			if err != nil {
				return err
			}
			sec = string(plain)
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("finish sso", err)
	}
	test, _ := ch.Data["test"].(bool)
	str := func(k string) string { v, _ := ch.Data[k].(string); return v }

	discovered, err := m.oidc.Discover(ctx, c.Issuer)
	if err != nil {
		return nil, errSSOFailed
	}
	identity, err := m.oidc.Exchange(ctx, discovered, c.ClientID, sec, str("redirect_uri"), req.Code, str("verifier"), str("nonce"), now)
	if err != nil {
		m.log.Debug(ctx, "enterprise sign-in refused", "connection_id", c.ID, "error", err.Error())
		return nil, errSSOFailed
	}
	groups := groupsOf(identity.Claims)

	if test {
		result := map[string]any{"ok": true, "email": identity.Email, "name": identity.Name, "subject": identity.Subject, "groups": groups, "at": now}
		err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
			return m.repo.SetConnectionTest(ctx, tx, t.ID, c.ID, result)
		})
		if err != nil {
			return nil, fmt.Errorf("record test: %w", err)
		}
		return &response.AuthResponse{TestResult: result}, nil
	}
	if c.Status != constant.SSOStatusActive {
		return nil, errSSOFailed
	}

	var out *response.AuthResponse
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		principalID, created, err := m.resolvePerson(ctx, tx, t, c, identity, meta, now)
		if err != nil {
			return err
		}
		if err := m.applyMappings(ctx, tx, t, c, principalID, groups, created, meta); err != nil {
			return err
		}
		var secondFactorAt *time.Time
		if c.TrustIdPSecondFactor {
			secondFactorAt = &now
		}
		out, err = m.auth.FinishExternalSignIn(ctx, tx, t, principalID, constant.MethodEnterprise, str("kind"), secondFactorAt, c.OrganizationID, meta)
		return err
	})
	if err != nil {
		return nil, passThrough("finish sso", err)
	}
	m.notify.Wake()
	return out, nil
}

func groupsOf(claims map[string]any) []string {
	var out []string
	if raw, ok := claims["groups"].([]any); ok {
		for _, g := range raw {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// resolvePerson finds the account behind an identity: by the provider's
// id, else by a verified address, else it is made (ENT-4).
func (m *enterpriseModule) resolvePerson(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.SSOConnection, id *oidc.Identity, meta model.RequestMeta, now time.Time) (string, bool, error) {
	principalID, err := m.repo.FindConnectionIdentity(ctx, tx, t.ID, c.ID, id.Subject)
	if err != nil {
		return "", false, err
	}
	if principalID != "" {
		return principalID, false, nil
	}
	if id.Email == "" {
		return "", false, errSSOFailed
	}
	// An existing account is linked only when its address is in a domain
	// this organization has verified.
	domains, err := m.repo.ListDomains(ctx, tx, t.ID, c.OrganizationID)
	if err != nil {
		return "", false, err
	}
	owned := false
	for _, d := range domains {
		if d.VerifiedAt != nil && d.Domain == authcore.EmailDomain(id.Email) {
			owned = true
		}
	}
	existing, err := m.users.FindUserByEmail(ctx, tx, t.ID, id.Email)
	if err != nil {
		return "", false, err
	}
	created := false
	switch {
	case existing != nil && owned:
		principalID = existing.PrincipalID
		if !existing.EmailVerified {
			if err := m.users.MarkEmailVerified(ctx, tx, t.ID, principalID, now); err != nil {
				return "", false, err
			}
		}
	case existing != nil:
		return "", false, errors.Conflict("account_exists", "an account with this address exists outside the company's verified domains")
	default:
		principalID, err = m.users.CreateUser(ctx, tx, t.ID, id.Email, id.Name)
		if err != nil {
			return "", false, err
		}
		if err := m.users.MarkEmailVerified(ctx, tx, t.ID, principalID, now); err != nil {
			return "", false, err
		}
		created = true
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.created", Result: model.AuditSuccess, ReasonCode: "enterprise", OrganizationID: c.OrganizationID, ActorID: principalID,
			TargetType: "user", TargetID: principalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return "", false, err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.created", map[string]any{"user_id": principalID, "by": "enterprise", "connection_id": c.ID}); err != nil {
			return "", false, err
		}
	}
	if err := m.repo.LinkConnectionIdentity(ctx, tx, t.ID, c.ID, principalID, id.Subject, id.Email, map[string]any{"name": id.Name}, now); err != nil {
		return "", false, err
	}
	return principalID, created, nil
}

// applyMappings turns the provider's groups into grants (ENT-4 step 3).
func (m *enterpriseModule) applyMappings(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.SSOConnection, principalID string, groups []string, created bool, meta model.RequestMeta) error {
	mappings, err := m.repo.ListGroupMappings(ctx, tx, t.ID, c.ID)
	if err != nil {
		return err
	}
	wasMember, err := m.orgs.IsMember(ctx, tx, t.ID, c.OrganizationID, principalID)
	if err != nil {
		return err
	}
	var grants []model.NewGrant
	for _, mp := range mappings {
		for _, g := range groups {
			if strings.EqualFold(g, mp.ExternalGroup) {
				grants = append(grants, model.NewGrant{RoleID: mp.RoleID, ResourceID: mp.ResourceID})
			}
		}
	}
	if len(grants) == 0 && c.DefaultRoleID != "" {
		grants = append(grants, model.NewGrant{RoleID: c.DefaultRoleID, ResourceID: c.OrganizationID})
	}
	if err := m.repo.ReplaceSSOGrants(ctx, tx, t.ID, c.ID, principalID, grants); err != nil {
		return err
	}
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "signin.enterprise", Result: model.AuditSuccess, OrganizationID: c.OrganizationID, ActorID: principalID,
		Data:      map[string]any{"connection_id": c.ID, "groups": groups, "grants": len(grants), "created": created},
		RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return err
	}
	if !wasMember && len(grants) > 0 {
		return m.notify.Emit(ctx, tx, t.ID, "member.added", map[string]any{"organization_id": c.OrganizationID, "principal_id": principalID, "by": "enterprise"})
	}
	return nil
}

// ---------------------------------------------------------------------
// Policies (ENT-6, ENT-7)
// ---------------------------------------------------------------------

func toPolicies(p *model.OrgPolicies) *response.OrgPolicies {
	out := &response.OrgPolicies{MFARequired: p.MFARequired, SessionMaxSeconds: p.SessionMaxSeconds, AllowedAuthMethods: p.AllowedAuthMethods,
		IPAllowlist: p.IPAllowlist, EnforceSSO: p.EnforceSSO, BreakGlassPrincipalID: p.BreakGlassPrincipalID}
	if out.AllowedAuthMethods == nil {
		out.AllowedAuthMethods = []string{}
	}
	if out.IPAllowlist == nil {
		out.IPAllowlist = []string{}
	}
	return out
}

func (m *enterpriseModule) GetPolicies(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string) (*response.OrgPolicies, error) {
	if !postgres.IsUUID(organizationID) {
		return nil, errors.NotFound("organization")
	}
	var out *response.OrgPolicies
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if err := m.require(ctx, tx, t, actor, constant.PermOrganizationManage, organizationID); err != nil {
			return err
		}
		p, err := m.orgs.GetPolicies(ctx, tx, t.ID, organizationID)
		if err != nil {
			return err
		}
		if p == nil {
			return errors.NotFound("organization")
		}
		out = toPolicies(p)
		return nil
	})
	if err != nil {
		return nil, passThrough("get policies", err)
	}
	return out, nil
}

func (m *enterpriseModule) SetPolicies(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string, req request.OrgPoliciesRequest, meta model.RequestMeta) (*response.OrgPolicies, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if !postgres.IsUUID(organizationID) {
		return nil, errors.NotFound("organization")
	}
	var out *response.OrgPolicies
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if err := m.require(ctx, tx, t, actor, constant.PermOrganizationManage, organizationID); err != nil {
			return err
		}
		p, err := m.orgs.GetPolicies(ctx, tx, t.ID, organizationID)
		if err != nil {
			return err
		}
		if p == nil {
			return errors.NotFound("organization")
		}
		if req.MFARequired != nil {
			p.MFARequired = *req.MFARequired
		}
		if req.SessionMaxSeconds != nil {
			p.SessionMaxSeconds = *req.SessionMaxSeconds
		}
		if req.AllowedAuthMethods != nil {
			p.AllowedAuthMethods = req.AllowedAuthMethods
		}
		if req.IPAllowlist != nil {
			p.IPAllowlist = req.IPAllowlist
		}
		if req.EnforceSSO != nil {
			p.EnforceSSO = *req.EnforceSSO
		}
		if req.BreakGlassPrincipalID != nil {
			p.BreakGlassPrincipalID = *req.BreakGlassPrincipalID
			if p.BreakGlassPrincipalID != "" {
				member, err := m.orgs.IsMember(ctx, tx, t.ID, organizationID, p.BreakGlassPrincipalID)
				if err != nil {
					return err
				}
				if !member {
					return errors.Validation(map[string]string{"break_glass_principal_id": "must be a member of the organization"})
				}
			}
		}
		if p.EnforceSSO {
			conns, err := m.repo.ListConnections(ctx, tx, t.ID, organizationID)
			if err != nil {
				return err
			}
			active := false
			for _, c := range conns {
				if c.Status == constant.SSOStatusActive {
					active = true
				}
			}
			if !active {
				return errors.Validation(map[string]string{"enforce_sso": "needs an active enterprise connection first"})
			}
		}
		if err := m.orgs.SetPolicies(ctx, tx, t.ID, organizationID, *p); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "organization.policies_changed", Result: model.AuditSuccess, OrganizationID: organizationID, ActorID: actor.PrincipalID, SessionID: actor.SessionID,
			TargetType: "organization", TargetID: organizationID,
			Data:      map[string]any{"mfa_required": p.MFARequired, "session_max_seconds": p.SessionMaxSeconds, "enforce_sso": p.EnforceSSO, "allowed_auth_methods": p.AllowedAuthMethods, "ip_allowlist": p.IPAllowlist},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		out = toPolicies(p)
		return nil
	})
	if err != nil {
		return nil, passThrough("set policies", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Directory sync (ENT-5)
// ---------------------------------------------------------------------

func (m *enterpriseModule) ResolveDirectory(ctx context.Context, token string) (string, string, string, error) {
	if token == "" {
		return "", "", "", errDirectoryGone
	}
	var tenantID, directoryID, organizationID string
	err := m.db.Resolver(ctx, func(tx pgx.Tx) (err error) {
		tenantID, directoryID, organizationID, err = m.repo.ResolveDirectoryToken(ctx, tx, secret.Hash(token))
		return err
	})
	if err != nil {
		return "", "", "", fmt.Errorf("resolve directory: %w", err)
	}
	if tenantID == "" {
		return "", "", "", errDirectoryGone
	}
	return tenantID, directoryID, organizationID, nil
}

func (m *enterpriseModule) directory(ctx context.Context, tx pgx.Tx, tenantID, directoryID string) (*model.SCIMDirectory, error) {
	d, err := m.repo.GetDirectory(ctx, tx, tenantID, directoryID)
	if err != nil {
		return nil, err
	}
	if d == nil || d.DisabledAt != nil {
		return nil, errDirectoryGone
	}
	return d, m.repo.TouchDirectory(ctx, tx, tenantID, d.ID, m.now())
}

func (m *enterpriseModule) SCIMListUsers(ctx context.Context, tenantID, directoryID, filterEmail string) ([]model.DirectoryUser, error) {
	var out []model.DirectoryUser
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		out, err = m.repo.ListDirectoryUsers(ctx, tx, tenantID, d.ID, strings.ToLower(filterEmail))
		return err
	})
	if err != nil {
		return nil, passThrough("scim list users", err)
	}
	return out, nil
}

func (m *enterpriseModule) SCIMGetUser(ctx context.Context, tenantID, directoryID, id string) (*model.DirectoryUser, error) {
	var out *model.DirectoryUser
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		out, err = m.repo.FindDirectoryUserByPrincipal(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return err
		}
		if out == nil {
			return errors.NotFound("user")
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("scim get user", err)
	}
	return out, nil
}

func (m *enterpriseModule) SCIMCreateUser(ctx context.Context, tenantID, directoryID, externalID, email, name string, active bool) (*model.DirectoryUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, errors.Validation(map[string]string{"userName": "is required"})
	}
	now := m.now()
	var out *model.DirectoryUser
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		if externalID == "" {
			externalID = email
		}
		if existing, err := m.repo.FindDirectoryUser(ctx, tx, tenantID, d.ID, externalID); err != nil || existing != nil {
			if err != nil {
				return err
			}
			return errors.Conflict("uniqueness", "a user with this externalId already exists")
		}
		// A person who already has an account in this tenant is claimed,
		// not duplicated: one person can belong to two customers.
		var principalID string
		if user, err := m.users.FindUserByEmail(ctx, tx, tenantID, email); err != nil {
			return err
		} else if user != nil {
			principalID = user.PrincipalID
		} else {
			principalID, err = m.users.CreateUser(ctx, tx, tenantID, email, name)
			if err != nil {
				return err
			}
			if err := m.users.MarkEmailVerified(ctx, tx, tenantID, principalID, now); err != nil {
				return err
			}
			if err := m.notify.Emit(ctx, tx, tenantID, "user.created", map[string]any{"user_id": principalID, "by": "directory", "directory_id": d.ID}); err != nil {
				return err
			}
		}
		if err := m.repo.LinkDirectoryUser(ctx, tx, tenantID, d.ID, principalID, externalID, email, now); err != nil {
			return err
		}
		if active {
			if err := m.giveDirectoryAccess(ctx, tx, tenantID, d, principalID); err != nil {
				return err
			}
		}
		if err := m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "directory.user_created", Result: model.AuditSuccess, OrganizationID: d.OrganizationID, TargetType: "user", TargetID: principalID,
			Data: map[string]any{"directory_id": d.ID, "external_id": externalID, "active": active},
		}); err != nil {
			return err
		}
		out, err = m.repo.FindDirectoryUserByPrincipal(ctx, tx, tenantID, d.ID, principalID)
		return err
	})
	if err != nil {
		return nil, passThrough("scim create user", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *enterpriseModule) giveDirectoryAccess(ctx context.Context, tx pgx.Tx, tenantID string, d *model.SCIMDirectory, principalID string) error {
	if d.DefaultRoleID == "" {
		return nil
	}
	member, err := m.orgs.IsMember(ctx, tx, tenantID, d.OrganizationID, principalID)
	if err != nil {
		return err
	}
	if _, err := m.iam.CreateGrant(ctx, tx, tenantID, model.NewGrant{
		PrincipalID: principalID, RoleID: d.DefaultRoleID, ResourceID: d.OrganizationID, Effect: constant.EffectAllow,
		Source: constant.GrantSourceDirectory, Reason: "directory:" + d.ID,
	}); err != nil {
		return err
	}
	if !member {
		return m.notify.Emit(ctx, tx, tenantID, "member.added", map[string]any{"organization_id": d.OrganizationID, "principal_id": principalID, "by": "directory"})
	}
	return nil
}

// removeDirectoryAccess takes the person's access in this organization
// away: grants under it, sessions working in it. The account stays.
func (m *enterpriseModule) removeDirectoryAccess(ctx context.Context, tx pgx.Tx, tenantID string, d *model.SCIMDirectory, principalID string) error {
	if _, err := m.orgs.RemoveMember(ctx, tx, tenantID, d.OrganizationID, principalID); err != nil {
		return err
	}
	if err := m.users.ClearActiveResourceFor(ctx, tx, tenantID, principalID, d.OrganizationID); err != nil {
		return err
	}
	return m.notify.Emit(ctx, tx, tenantID, "member.removed", map[string]any{"organization_id": d.OrganizationID, "principal_id": principalID, "by": "directory"})
}

func (m *enterpriseModule) SCIMUpdateUser(ctx context.Context, tenantID, directoryID, id string, email, name *string, active *bool) (*model.DirectoryUser, error) {
	now := m.now()
	var out *model.DirectoryUser
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		u, err := m.repo.FindDirectoryUserByPrincipal(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return err
		}
		if u == nil {
			return errors.NotFound("user")
		}
		if email != nil && strings.ToLower(*email) != u.Email {
			if err := m.users.UpdateEmail(ctx, tx, tenantID, u.PrincipalID, strings.ToLower(*email), now); err != nil {
				return err
			}
		}
		if name != nil {
			if _, err := tx.Exec(ctx, `UPDATE aos.users SET name = NULLIF($3, ''), updated_at = $4 WHERE tenant_id = $1 AND principal_id = $2`, tenantID, u.PrincipalID, *name, now); err != nil {
				return err
			}
		}
		if active != nil {
			member, err := m.orgs.IsMember(ctx, tx, tenantID, d.OrganizationID, u.PrincipalID)
			if err != nil {
				return err
			}
			switch {
			case *active && !member:
				if err := m.giveDirectoryAccess(ctx, tx, tenantID, d, u.PrincipalID); err != nil {
					return err
				}
			case !*active && member:
				if err := m.removeDirectoryAccess(ctx, tx, tenantID, d, u.PrincipalID); err != nil {
					return err
				}
			}
		}
		if err := m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "directory.user_updated", Result: model.AuditSuccess, OrganizationID: d.OrganizationID, TargetType: "user", TargetID: u.PrincipalID,
			Data: map[string]any{"directory_id": d.ID, "active": active},
		}); err != nil {
			return err
		}
		out, err = m.repo.FindDirectoryUserByPrincipal(ctx, tx, tenantID, d.ID, u.PrincipalID)
		if err != nil {
			return err
		}
		if active != nil {
			out.Active = *active
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("scim update user", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *enterpriseModule) SCIMDeleteUser(ctx context.Context, tenantID, directoryID, id string) error {
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		u, err := m.repo.FindDirectoryUserByPrincipal(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return err
		}
		if u == nil {
			return errors.NotFound("user")
		}
		if err := m.removeDirectoryAccess(ctx, tx, tenantID, d, u.PrincipalID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM aos.external_identities WHERE tenant_id = $1 AND directory_id = $2 AND principal_id = $3`, tenantID, d.ID, u.PrincipalID); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "directory.user_removed", Result: model.AuditSuccess, OrganizationID: d.OrganizationID, TargetType: "user", TargetID: u.PrincipalID,
			Data: map[string]any{"directory_id": d.ID},
		})
	})
	if err != nil {
		return passThrough("scim delete user", err)
	}
	m.notify.Wake()
	return nil
}

func (m *enterpriseModule) SCIMListGroups(ctx context.Context, tenantID, directoryID string) ([]model.Group, error) {
	var out []model.Group
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		out, err = m.repo.ListDirectoryGroups(ctx, tx, tenantID, d.ID)
		return err
	})
	if err != nil {
		return nil, passThrough("scim list groups", err)
	}
	return out, nil
}

func (m *enterpriseModule) SCIMGetGroup(ctx context.Context, tenantID, directoryID, id string) (*model.Group, error) {
	var out *model.Group
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		out, err = m.repo.FindDirectoryGroup(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return err
		}
		if out == nil {
			return errors.NotFound("group")
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("scim get group", err)
	}
	return out, nil
}

// directoryMembers keeps only the directory's own people.
func (m *enterpriseModule) directoryMembers(ctx context.Context, tx pgx.Tx, tenantID string, d *model.SCIMDirectory, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		u, err := m.repo.FindDirectoryUserByPrincipal(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return nil, err
		}
		if u != nil {
			out = append(out, u.PrincipalID)
		}
	}
	return out, nil
}

func (m *enterpriseModule) SCIMCreateGroup(ctx context.Context, tenantID, directoryID, externalID, name string, members []string) (*model.Group, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.Validation(map[string]string{"displayName": "is required"})
	}
	var out *model.Group
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		if externalID != "" {
			if existing, err := m.repo.FindDirectoryGroup(ctx, tx, tenantID, d.ID, externalID); err != nil || existing != nil {
				if err != nil {
					return err
				}
				return errors.Conflict("uniqueness", "a group with this externalId already exists")
			}
		}
		id, err := m.repo.CreateDirectoryGroup(ctx, tx, tenantID, d.ID, d.OrganizationID, externalID, name)
		if err != nil {
			return err
		}
		people, err := m.directoryMembers(ctx, tx, tenantID, d, members)
		if err != nil {
			return err
		}
		if err := m.repo.ReplaceGroupMembers(ctx, tx, tenantID, id, people); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "directory.group_created", Result: model.AuditSuccess, OrganizationID: d.OrganizationID, TargetType: "group", TargetID: id,
			Data: map[string]any{"directory_id": d.ID, "name": name, "members": len(people)},
		}); err != nil {
			return err
		}
		out, err = m.repo.FindDirectoryGroup(ctx, tx, tenantID, d.ID, id)
		return err
	})
	if err != nil {
		return nil, passThrough("scim create group", err)
	}
	return out, nil
}

func (m *enterpriseModule) SCIMUpdateGroup(ctx context.Context, tenantID, directoryID, id string, name *string, members []string, add, remove []string) (*model.Group, error) {
	var out *model.Group
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		g, err := m.repo.FindDirectoryGroup(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return err
		}
		if g == nil {
			return errors.NotFound("group")
		}
		if name != nil && strings.TrimSpace(*name) != "" {
			if err := m.repo.RenameGroup(ctx, tx, tenantID, g.ID, *name); err != nil {
				return err
			}
		}
		current := g.Members
		if members != nil {
			current = members
		}
		current = append(current, add...)
		if len(remove) > 0 {
			drop := map[string]bool{}
			for _, r := range remove {
				drop[r] = true
			}
			kept := current[:0]
			for _, c := range current {
				if !drop[c] {
					kept = append(kept, c)
				}
			}
			current = kept
		}
		people, err := m.directoryMembers(ctx, tx, tenantID, d, current)
		if err != nil {
			return err
		}
		if err := m.repo.ReplaceGroupMembers(ctx, tx, tenantID, g.ID, people); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "directory.group_updated", Result: model.AuditSuccess, OrganizationID: d.OrganizationID, TargetType: "group", TargetID: g.ID,
			Data: map[string]any{"directory_id": d.ID, "members": len(people)},
		}); err != nil {
			return err
		}
		out, err = m.repo.FindDirectoryGroup(ctx, tx, tenantID, d.ID, g.ID)
		return err
	})
	if err != nil {
		return nil, passThrough("scim update group", err)
	}
	return out, nil
}

func (m *enterpriseModule) SCIMDeleteGroup(ctx context.Context, tenantID, directoryID, id string) error {
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := m.directory(ctx, tx, tenantID, directoryID)
		if err != nil {
			return err
		}
		g, err := m.repo.FindDirectoryGroup(ctx, tx, tenantID, d.ID, id)
		if err != nil {
			return err
		}
		if g == nil {
			return errors.NotFound("group")
		}
		if err := m.repo.DeleteGroup(ctx, tx, tenantID, g.ID); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, tenantID, model.AuditEntry{
			Action: "directory.group_removed", Result: model.AuditSuccess, OrganizationID: d.OrganizationID, TargetType: "group", TargetID: g.ID,
			Data: map[string]any{"directory_id": d.ID},
		})
	})
	return passThrough("scim delete group", err)
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
