// Package enterprise stores SSO connections, group mappings, verified
// domains and company directories.
package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
)

type enterpriseRepository struct {
	log logger.Logger
}

func NewEnterpriseRepository(log logger.Logger) storage.EnterpriseRepository {
	return &enterpriseRepository{log: log}
}

// ---- connections ----

const connectionColumns = `id::text, organization_id::text, COALESCE(name, ''), protocol, status, COALESCE(oidc_issuer, ''), COALESCE(oidc_client_id, ''),
	oidc_client_secret_encrypted, COALESCE(data_key_id::text, ''), COALESCE(saml_idp_entity_id, ''), COALESCE(saml_idp_sso_url, ''), COALESCE(saml_idp_certificate, ''),
	trust_idp_second_factor, COALESCE(default_role_id::text, ''), last_test, created_at, activated_at`

func scanConnection(row pgx.CollectableRow) (model.SSOConnection, error) {
	var c model.SSOConnection
	var test []byte
	if err := row.Scan(&c.ID, &c.OrganizationID, &c.Name, &c.Protocol, &c.Status, &c.Issuer, &c.ClientID, &c.ClientSecretEncrypted, &c.DataKeyID,
		&c.SAMLEntityID, &c.SAMLSSOURL, &c.SAMLCertificate, &c.TrustIdPSecondFactor, &c.DefaultRoleID, &test, &c.CreatedAt, &c.ActivatedAt); err != nil {
		return c, err
	}
	if len(test) > 0 {
		_ = json.Unmarshal(test, &c.LastTest)
	}
	return c, nil
}

func (r *enterpriseRepository) CreateConnection(ctx context.Context, tx pgx.Tx, tenantID string, c model.SSOConnection) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.sso_connections (tenant_id, organization_id, name, protocol, status)
		VALUES ($1, $2, NULLIF($3, ''), $4, 'draft') RETURNING id::text`, tenantID, c.OrganizationID, c.Name, c.Protocol).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create connection: %w", err)
	}
	return id, nil
}

func (r *enterpriseRepository) GetConnection(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.SSOConnection, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+connectionColumns+` FROM aos.sso_connections WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get connection: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, scanConnection)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get connection: %w", err)
	}
	return &c, nil
}

func (r *enterpriseRepository) ListConnections(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.SSOConnection, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+connectionColumns+` FROM aos.sso_connections
		WHERE tenant_id = $1 AND ($2 = '' OR organization_id = $2::uuid) ORDER BY created_at`, tenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanConnection)
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	return out, nil
}

func (r *enterpriseRepository) UpdateConnectionSettings(ctx context.Context, tx pgx.Tx, tenantID string, c model.SSOConnection) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sso_connections SET name = COALESCE(NULLIF($3, ''), name), oidc_issuer = NULLIF($4, ''), oidc_client_id = NULLIF($5, ''),
		       oidc_client_secret_encrypted = COALESCE($6, oidc_client_secret_encrypted), data_key_id = COALESCE($7::uuid, data_key_id),
		       saml_idp_entity_id = NULLIF($8, ''), saml_idp_sso_url = NULLIF($9, ''), saml_idp_certificate = NULLIF($10, '')
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, c.ID, c.Name, c.Issuer, c.ClientID, c.ClientSecretEncrypted, postgres.NullString(c.DataKeyID), c.SAMLEntityID, c.SAMLSSOURL, c.SAMLCertificate); err != nil {
		return fmt.Errorf("update connection: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) SetConnectionStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sso_connections SET status = $3, activated_at = CASE WHEN $3 = 'active' THEN $4::timestamptz ELSE activated_at END
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, status, at); err != nil {
		return fmt.Errorf("set connection status: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) SetConnectionTest(ctx context.Context, tx pgx.Tx, tenantID, id string, result map[string]any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE aos.sso_connections SET last_test = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, raw); err != nil {
		return fmt.Errorf("set connection test: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) SetConnectionDefaultRole(ctx context.Context, tx pgx.Tx, tenantID, id, roleID string, trustIdPFactor bool) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.sso_connections SET default_role_id = $3, trust_idp_second_factor = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, postgres.NullString(roleID), trustIdPFactor); err != nil {
		return fmt.Errorf("set connection role: %w", err)
	}
	return nil
}

// ---- group mappings ----

func (r *enterpriseRepository) ReplaceGroupMappings(ctx context.Context, tx pgx.Tx, tenantID, connectionID string, mappings []model.GroupMapping) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.sso_group_mappings WHERE tenant_id = $1 AND connection_id = $2`, tenantID, connectionID); err != nil {
		return fmt.Errorf("replace group mappings: %w", err)
	}
	for _, m := range mappings {
		if _, err := tx.Exec(ctx, `
			INSERT INTO aos.sso_group_mappings (tenant_id, connection_id, external_group, role_id, resource_id)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, tenantID, connectionID, m.ExternalGroup, m.RoleID, m.ResourceID); err != nil {
			return fmt.Errorf("replace group mappings: %w", err)
		}
	}
	return nil
}

func (r *enterpriseRepository) ListGroupMappings(ctx context.Context, tx pgx.Tx, tenantID, connectionID string) ([]model.GroupMapping, error) {
	rows, err := tx.Query(ctx, `
		SELECT m.external_group, m.role_id::text, ro.name, m.resource_id::text
		FROM aos.sso_group_mappings m JOIN aos.roles ro ON ro.tenant_id = m.tenant_id AND ro.id = m.role_id
		WHERE m.tenant_id = $1 AND m.connection_id = $2 ORDER BY m.external_group`, tenantID, connectionID)
	if err != nil {
		return nil, fmt.Errorf("list group mappings: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.GroupMapping, error) {
		var m model.GroupMapping
		err := row.Scan(&m.ExternalGroup, &m.RoleID, &m.RoleName, &m.ResourceID)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("list group mappings: %w", err)
	}
	return out, nil
}

// ---- domains ----

const domainColumns = `id::text, organization_id::text, domain::text, txt_value, verified_at, last_checked_at, created_at`

func scanDomain(row pgx.CollectableRow) (model.VerifiedDomain, error) {
	var d model.VerifiedDomain
	err := row.Scan(&d.ID, &d.OrganizationID, &d.Domain, &d.TXTValue, &d.VerifiedAt, &d.LastCheckedAt, &d.CreatedAt)
	return d, err
}

func (r *enterpriseRepository) CreateDomain(ctx context.Context, tx pgx.Tx, tenantID, organizationID, domain, txtValue string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.verified_domains (tenant_id, organization_id, domain, txt_value) VALUES ($1, $2, $3, $4) RETURNING id::text`,
		tenantID, organizationID, domain, txtValue).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create domain: %w", err)
	}
	return id, nil
}

func (r *enterpriseRepository) ListDomains(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.VerifiedDomain, error) {
	rows, err := tx.Query(ctx, `SELECT `+domainColumns+` FROM aos.verified_domains WHERE tenant_id = $1 AND organization_id = $2 ORDER BY created_at`, tenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanDomain)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	return out, nil
}

func (r *enterpriseRepository) GetDomain(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.VerifiedDomain, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+domainColumns+` FROM aos.verified_domains WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}
	d, err := pgx.CollectOneRow(rows, scanDomain)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}
	return &d, nil
}

func (r *enterpriseRepository) MarkDomainChecked(ctx context.Context, tx pgx.Tx, tenantID, id string, verified bool, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.verified_domains SET last_checked_at = $3,
		       verified_at = CASE WHEN $4 THEN COALESCE(verified_at, $3::timestamptz) ELSE NULL END
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, at, verified); err != nil {
		return fmt.Errorf("mark domain checked: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) ConnectionForDomain(ctx context.Context, tx pgx.Tx, tenantID, domain string) (*model.SSOConnection, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+connectionColumns+` FROM aos.sso_connections c
		WHERE c.tenant_id = $1 AND c.status = 'active'
		  AND c.organization_id = (SELECT d.organization_id FROM aos.verified_domains d WHERE d.tenant_id = $1 AND d.domain = $2 AND d.verified_at IS NOT NULL)
		ORDER BY c.activated_at DESC LIMIT 1`, tenantID, domain)
	if err != nil {
		return nil, fmt.Errorf("connection for domain: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, scanConnection)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("connection for domain: %w", err)
	}
	return &c, nil
}

func (r *enterpriseRepository) DeleteDomain(ctx context.Context, tx pgx.Tx, tenantID, id string) (bool, error) {
	if !postgres.IsUUID(id) {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `DELETE FROM aos.verified_domains WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return false, fmt.Errorf("delete domain: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---- identities and grants from a connection ----

func (r *enterpriseRepository) FindConnectionIdentity(ctx context.Context, tx pgx.Tx, tenantID, connectionID, subject string) (string, error) {
	var principalID string
	err := tx.QueryRow(ctx, `
		SELECT principal_id::text FROM aos.external_identities WHERE tenant_id = $1 AND connection_id = $2 AND subject = $3`,
		tenantID, connectionID, subject).Scan(&principalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find connection identity: %w", err)
	}
	return principalID, nil
}

func (r *enterpriseRepository) LinkConnectionIdentity(ctx context.Context, tx pgx.Tx, tenantID, connectionID, principalID, subject, email string, profile map[string]any, at time.Time) error {
	if profile == nil {
		profile = map[string]any{}
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.external_identities (tenant_id, principal_id, provider, connection_id, subject, email, email_verified, profile, last_sign_in_at)
		VALUES ($1, $2, 'enterprise', $3, $4, NULLIF($5, ''), true, $6, $7)`, tenantID, principalID, connectionID, subject, email, raw, at); err != nil {
		return fmt.Errorf("link connection identity: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) ReplaceSSOGrants(ctx context.Context, tx pgx.Tx, tenantID, connectionID, principalID string, grants []model.NewGrant) error {
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.grants WHERE tenant_id = $1 AND principal_id = $2 AND source = 'sso' AND reason = $3`,
		tenantID, principalID, "sso:"+connectionID); err != nil {
		return fmt.Errorf("replace sso grants: %w", err)
	}
	for _, g := range grants {
		if _, err := tx.Exec(ctx, `
			INSERT INTO aos.grants (tenant_id, principal_id, role_id, resource_id, effect, source, reason)
			VALUES ($1, $2, $3, $4, 'allow', 'sso', $5)`, tenantID, principalID, g.RoleID, g.ResourceID, "sso:"+connectionID); err != nil {
			return fmt.Errorf("replace sso grants: %w", err)
		}
	}
	return nil
}

// ---- directories ----

const directoryColumns = `id::text, organization_id::text, COALESCE(default_role_id::text, ''), created_at, last_request_at, disabled_at`

func scanDirectory(row pgx.CollectableRow) (model.SCIMDirectory, error) {
	var d model.SCIMDirectory
	err := row.Scan(&d.ID, &d.OrganizationID, &d.DefaultRoleID, &d.CreatedAt, &d.LastRequestAt, &d.DisabledAt)
	return d, err
}

func (r *enterpriseRepository) CreateDirectory(ctx context.Context, tx pgx.Tx, tenantID, organizationID string, tokenHash []byte, defaultRoleID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.scim_directories (tenant_id, organization_id, token_hash, default_role_id) VALUES ($1, $2, $3, $4) RETURNING id::text`,
		tenantID, organizationID, tokenHash, postgres.NullString(defaultRoleID)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}
	return id, nil
}

func (r *enterpriseRepository) GetDirectory(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.SCIMDirectory, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+directoryColumns+` FROM aos.scim_directories WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get directory: %w", err)
	}
	d, err := pgx.CollectOneRow(rows, scanDirectory)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get directory: %w", err)
	}
	return &d, nil
}

func (r *enterpriseRepository) ListDirectories(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.SCIMDirectory, error) {
	rows, err := tx.Query(ctx, `SELECT `+directoryColumns+` FROM aos.scim_directories WHERE tenant_id = $1 AND organization_id = $2 ORDER BY created_at`, tenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list directories: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanDirectory)
	if err != nil {
		return nil, fmt.Errorf("list directories: %w", err)
	}
	return out, nil
}

func (r *enterpriseRepository) DisableDirectory(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.scim_directories SET disabled_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("disable directory: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) TouchDirectory(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.scim_directories SET last_request_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("touch directory: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) ResolveDirectoryToken(ctx context.Context, tx pgx.Tx, tokenHash []byte) (string, string, string, error) {
	var tenantID, directoryID, organizationID string
	err := tx.QueryRow(ctx, `SELECT tenant_id::text, directory_id::text, organization_id::text FROM aos.resolve_scim_token($1)`, tokenHash).Scan(&tenantID, &directoryID, &organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", nil
	}
	if err != nil {
		return "", "", "", fmt.Errorf("resolve directory token: %w", err)
	}
	return tenantID, directoryID, organizationID, nil
}

const directoryUserColumns = `p.id::text, i.subject, COALESCE(u.email::text, ''), COALESCE(u.name, ''), p.status = 'active', p.created_at`

func scanDirectoryUser(row pgx.CollectableRow) (model.DirectoryUser, error) {
	var u model.DirectoryUser
	err := row.Scan(&u.PrincipalID, &u.ExternalID, &u.Email, &u.Name, &u.Active, &u.CreatedAt)
	return u, err
}

func (r *enterpriseRepository) FindDirectoryUser(ctx context.Context, tx pgx.Tx, tenantID, directoryID, externalID string) (*model.DirectoryUser, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+directoryUserColumns+` FROM aos.external_identities i
		JOIN aos.principals p ON p.tenant_id = i.tenant_id AND p.id = i.principal_id
		LEFT JOIN aos.users u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		WHERE i.tenant_id = $1 AND i.directory_id = $2 AND i.subject = $3`, tenantID, directoryID, externalID)
	if err != nil {
		return nil, fmt.Errorf("find directory user: %w", err)
	}
	u, err := pgx.CollectOneRow(rows, scanDirectoryUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find directory user: %w", err)
	}
	return &u, nil
}

func (r *enterpriseRepository) FindDirectoryUserByPrincipal(ctx context.Context, tx pgx.Tx, tenantID, directoryID, principalID string) (*model.DirectoryUser, error) {
	if !postgres.IsUUID(principalID) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT `+directoryUserColumns+` FROM aos.external_identities i
		JOIN aos.principals p ON p.tenant_id = i.tenant_id AND p.id = i.principal_id
		LEFT JOIN aos.users u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		WHERE i.tenant_id = $1 AND i.directory_id = $2 AND i.principal_id = $3`, tenantID, directoryID, principalID)
	if err != nil {
		return nil, fmt.Errorf("find directory user: %w", err)
	}
	u, err := pgx.CollectOneRow(rows, scanDirectoryUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find directory user: %w", err)
	}
	return &u, nil
}

func (r *enterpriseRepository) ListDirectoryUsers(ctx context.Context, tx pgx.Tx, tenantID, directoryID, emailFilter string) ([]model.DirectoryUser, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+directoryUserColumns+` FROM aos.external_identities i
		JOIN aos.principals p ON p.tenant_id = i.tenant_id AND p.id = i.principal_id
		LEFT JOIN aos.users u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		WHERE i.tenant_id = $1 AND i.directory_id = $2 AND ($3 = '' OR u.email = $3::citext)
		ORDER BY p.created_at`, tenantID, directoryID, emailFilter)
	if err != nil {
		return nil, fmt.Errorf("list directory users: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanDirectoryUser)
	if err != nil {
		return nil, fmt.Errorf("list directory users: %w", err)
	}
	return out, nil
}

func (r *enterpriseRepository) LinkDirectoryUser(ctx context.Context, tx pgx.Tx, tenantID, directoryID, principalID, externalID, email string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.external_identities (tenant_id, principal_id, provider, directory_id, subject, email, email_verified, last_sign_in_at)
		VALUES ($1, $2, 'directory', $3, $4, NULLIF($5, ''), true, $6)`, tenantID, principalID, directoryID, externalID, email, at); err != nil {
		return fmt.Errorf("link directory user: %w", err)
	}
	return nil
}

// ---- directory groups ----

func scanGroup(row pgx.CollectableRow) (model.Group, error) {
	var g model.Group
	err := row.Scan(&g.ID, &g.Name, &g.OrganizationID, &g.ExternalID, &g.CreatedAt, &g.Members)
	return g, err
}

const groupColumns = `g.id::text, g.name, COALESCE(g.organization_id::text, ''), COALESCE(g.external_id, ''), g.created_at,
	COALESCE((SELECT array_agg(gm.principal_id::text ORDER BY gm.principal_id) FROM aos.group_members gm WHERE gm.tenant_id = g.tenant_id AND gm.group_id = g.id), '{}')`

func (r *enterpriseRepository) FindDirectoryGroup(ctx context.Context, tx pgx.Tx, tenantID, directoryID, externalID string) (*model.Group, error) {
	rows, err := tx.Query(ctx, `SELECT `+groupColumns+` FROM aos.groups g WHERE g.tenant_id = $1 AND g.directory_id = $2 AND (g.external_id = $3 OR g.id::text = $3)`, tenantID, directoryID, externalID)
	if err != nil {
		return nil, fmt.Errorf("find directory group: %w", err)
	}
	g, err := pgx.CollectOneRow(rows, scanGroup)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find directory group: %w", err)
	}
	return &g, nil
}

func (r *enterpriseRepository) CreateDirectoryGroup(ctx context.Context, tx pgx.Tx, tenantID, directoryID, organizationID, externalID, name string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.groups (tenant_id, organization_id, name, directory_id, external_id) VALUES ($1, $2, $3, $4, NULLIF($5, '')) RETURNING id::text`,
		tenantID, organizationID, name, directoryID, externalID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create directory group: %w", err)
	}
	return id, nil
}

func (r *enterpriseRepository) RenameGroup(ctx context.Context, tx pgx.Tx, tenantID, groupID, name string) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.groups SET name = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, groupID, name); err != nil {
		return fmt.Errorf("rename group: %w", err)
	}
	return nil
}

func (r *enterpriseRepository) ListDirectoryGroups(ctx context.Context, tx pgx.Tx, tenantID, directoryID string) ([]model.Group, error) {
	rows, err := tx.Query(ctx, `SELECT `+groupColumns+` FROM aos.groups g WHERE g.tenant_id = $1 AND g.directory_id = $2 ORDER BY g.created_at`, tenantID, directoryID)
	if err != nil {
		return nil, fmt.Errorf("list directory groups: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanGroup)
	if err != nil {
		return nil, fmt.Errorf("list directory groups: %w", err)
	}
	return out, nil
}

func (r *enterpriseRepository) ReplaceGroupMembers(ctx context.Context, tx pgx.Tx, tenantID, groupID string, principalIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.group_members WHERE tenant_id = $1 AND group_id = $2`, tenantID, groupID); err != nil {
		return fmt.Errorf("replace group members: %w", err)
	}
	for _, p := range principalIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO aos.group_members (tenant_id, group_id, principal_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, tenantID, groupID, p); err != nil {
			return fmt.Errorf("replace group members: %w", err)
		}
	}
	return nil
}

func (r *enterpriseRepository) DeleteGroup(ctx context.Context, tx pgx.Tx, tenantID, groupID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.groups WHERE tenant_id = $1 AND id = $2`, tenantID, groupID); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}
