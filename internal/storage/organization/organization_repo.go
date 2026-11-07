// Package organization is the SQL for organizations, their members and
// their invitations.
package organization

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
)

type organizationRepository struct {
	log logger.Logger
}

func NewOrganizationRepository(log logger.Logger) storage.OrganizationRepository {
	return &organizationRepository{log: log}
}

func (r *organizationRepository) CreateOrganization(ctx context.Context, tx pgx.Tx, tenantID, resourceID, slug, name, createdBy string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.organizations (resource_id, tenant_id, slug, name, created_by)
		VALUES ($1, $2, $3, $4, $5)`, resourceID, tenantID, slug, name, postgres.NullString(createdBy)); err != nil {
		return fmt.Errorf("create organization: %w", err)
	}
	return nil
}

const orgColumns = `o.resource_id::text, o.slug, o.name, o.status, o.created_at`

func scanOrg(row pgx.CollectableRow) (model.Organization, error) {
	var o model.Organization
	err := row.Scan(&o.ID, &o.Slug, &o.Name, &o.Status, &o.CreatedAt)
	return o, err
}

func (r *organizationRepository) GetOrganization(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) (*model.Organization, error) {
	rows, err := tx.Query(ctx, `SELECT `+orgColumns+` FROM aos.organizations o WHERE o.tenant_id = $1 AND o.resource_id = $2 AND o.status = 'active'`,
		tenantID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	o, err := pgx.CollectOneRow(rows, scanOrg)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	return &o, nil
}

func (r *organizationRepository) ListOrganizationsFor(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.Organization, error) {
	// An organization the principal belongs to is one where it holds a
	// grant on the organization's node or on anything beneath it.
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT `+orgColumns+`
		FROM aos.organizations o
		JOIN aos.resource_ancestors a ON a.tenant_id = o.tenant_id AND a.ancestor_id = o.resource_id
		JOIN aos.grants g ON g.tenant_id = a.tenant_id AND g.resource_id = a.resource_id
		WHERE o.tenant_id = $1 AND o.status = 'active'
		  AND (g.principal_id = $2
		       OR g.group_id IN (SELECT gm.group_id FROM aos.group_members gm WHERE gm.tenant_id = $1 AND gm.principal_id = $2))
		ORDER BY o.name`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	orgs, err := pgx.CollectRows(rows, scanOrg)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	return orgs, nil
}

func (r *organizationRepository) ListOrganizations(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.Organization, error) {
	rows, err := tx.Query(ctx, `SELECT `+orgColumns+` FROM aos.organizations o WHERE o.tenant_id = $1 AND o.status = 'active' ORDER BY o.name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	orgs, err := pgx.CollectRows(rows, scanOrg)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	return orgs, nil
}

func (r *organizationRepository) IsMember(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM aos.resource_ancestors a
			JOIN aos.grants g ON g.tenant_id = a.tenant_id AND g.resource_id = a.resource_id
			WHERE a.tenant_id = $1 AND a.ancestor_id = $2
			  AND (g.principal_id = $3
			       OR g.group_id IN (SELECT gm.group_id FROM aos.group_members gm WHERE gm.tenant_id = $1 AND gm.principal_id = $3)))`,
		tenantID, resourceID, principalID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("is member: %w", err)
	}
	return ok, nil
}

func (r *organizationRepository) ListMembers(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) ([]model.Member, error) {
	rows, err := tx.Query(ctx, `
		SELECT p.id::text, COALESCE(u.email::text, ''), COALESCE(u.name, p.display_name, ''), p.status,
		       array_agg(DISTINCT ro.name ORDER BY ro.name)
		FROM aos.resource_ancestors a
		JOIN aos.grants g ON g.tenant_id = a.tenant_id AND g.resource_id = a.resource_id
		JOIN aos.roles ro ON ro.tenant_id = g.tenant_id AND ro.id = g.role_id
		JOIN aos.principals p ON p.tenant_id = g.tenant_id AND p.id = g.principal_id
		LEFT JOIN aos.users u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		WHERE a.tenant_id = $1 AND a.ancestor_id = $2 AND g.principal_id IS NOT NULL
		GROUP BY p.id, u.email, u.name, p.display_name, p.status
		ORDER BY u.email, p.id`, tenantID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	members, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.Member, error) {
		var m model.Member
		err := row.Scan(&m.PrincipalID, &m.Email, &m.Name, &m.Status, &m.Roles)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return members, nil
}

func (r *organizationRepository) CountOwners(ctx context.Context, tx pgx.Tx, tenantID, resourceID, ownerRoleID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT principal_id) FROM aos.grants
		WHERE tenant_id = $1 AND resource_id = $2 AND role_id = $3 AND effect = 'allow'
		  AND principal_id IS NOT NULL AND (expires_at IS NULL OR expires_at > now())`,
		tenantID, resourceID, ownerRoleID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count owners: %w", err)
	}
	return n, nil
}

func (r *organizationRepository) HoldsRoleOn(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID, roleID string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM aos.grants
		               WHERE tenant_id = $1 AND resource_id = $2 AND principal_id = $3 AND role_id = $4 AND effect = 'allow')`,
		tenantID, resourceID, principalID, roleID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("holds role: %w", err)
	}
	return ok, nil
}

func (r *organizationRepository) ReplaceRoleOn(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID, roleID, createdBy string) error {
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.grants WHERE tenant_id = $1 AND resource_id = $2 AND principal_id = $3 AND effect = 'allow'`,
		tenantID, resourceID, principalID); err != nil {
		return fmt.Errorf("replace role: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.grants (tenant_id, principal_id, role_id, resource_id, effect, source, created_by)
		VALUES ($1, $2, $3, $4, 'allow', 'manual', $5)`,
		tenantID, principalID, roleID, resourceID, postgres.NullString(createdBy)); err != nil {
		return fmt.Errorf("replace role: %w", err)
	}
	return nil
}

func (r *organizationRepository) RemoveMember(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM aos.grants g
		USING aos.resource_ancestors a
		WHERE g.tenant_id = $1 AND g.principal_id = $3
		  AND a.tenant_id = g.tenant_id AND a.resource_id = g.resource_id AND a.ancestor_id = $2`,
		tenantID, resourceID, principalID)
	if err != nil {
		return 0, fmt.Errorf("remove member: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.group_members gm
		USING aos.groups g
		WHERE gm.tenant_id = $1 AND gm.principal_id = $3
		  AND g.tenant_id = gm.tenant_id AND g.id = gm.group_id AND g.organization_id = $2`,
		tenantID, resourceID, principalID); err != nil {
		return 0, fmt.Errorf("remove member: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *organizationRepository) DeleteOrganization(ctx context.Context, tx pgx.Tx, tenantID, resourceID string, at, purgeAfter time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.organizations SET status = 'deleted', deleted_at = $3, purge_after = $4
		WHERE tenant_id = $1 AND resource_id = $2`, tenantID, resourceID, at, purgeAfter); err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	// The whole subtree stops answering, and every grant in it goes.
	if _, err := tx.Exec(ctx, `
		UPDATE aos.resources re SET deleted_at = $3
		FROM aos.resource_ancestors a
		WHERE re.tenant_id = $1 AND a.tenant_id = re.tenant_id AND a.resource_id = re.id AND a.ancestor_id = $2`,
		tenantID, resourceID, at); err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.grants g USING aos.resource_ancestors a
		WHERE g.tenant_id = $1 AND a.tenant_id = g.tenant_id AND a.resource_id = g.resource_id AND a.ancestor_id = $2`,
		tenantID, resourceID); err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE aos.invitations SET revoked_at = $3
		FROM aos.resource_ancestors a
		WHERE invitations.tenant_id = $1 AND a.tenant_id = invitations.tenant_id
		  AND a.resource_id = invitations.resource_id AND a.ancestor_id = $2
		  AND invitations.accepted_at IS NULL AND invitations.revoked_at IS NULL`,
		tenantID, resourceID, at); err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	return nil
}

// ---- invitations ----

func (r *organizationRepository) CreateInvitation(ctx context.Context, tx pgx.Tx, tenantID string, inv model.NewInvitation) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.invitations (tenant_id, email, role_id, resource_id, inviter_principal_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id::text`,
		tenantID, inv.Email, inv.RoleID, inv.ResourceID, postgres.NullString(inv.InviterID), inv.TokenHash, inv.ExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create invitation: %w", err)
	}
	return id, nil
}

const invitationQuery = `
	SELECT i.id::text, i.email::text, i.role_id::text, ro.name, i.resource_id::text, re.type, re.external_id,
	       COALESCE(o.resource_id::text, ''), COALESCE(o.name, ''),
	       COALESCE(i.inviter_principal_id::text, ''), COALESCE(iu.name, iu.email::text, ''),
	       i.expires_at, i.accepted_at, i.declined_at, i.revoked_at, i.created_at
	FROM aos.invitations i
	JOIN aos.roles ro ON ro.tenant_id = i.tenant_id AND ro.id = i.role_id
	JOIN aos.resources re ON re.tenant_id = i.tenant_id AND re.id = i.resource_id
	LEFT JOIN LATERAL (
		SELECT org.resource_id, org.name FROM aos.resource_ancestors a
		JOIN aos.organizations org ON org.tenant_id = a.tenant_id AND org.resource_id = a.ancestor_id
		WHERE a.tenant_id = i.tenant_id AND a.resource_id = i.resource_id
		ORDER BY a.depth LIMIT 1) o ON true
	LEFT JOIN aos.users iu ON iu.tenant_id = i.tenant_id AND iu.principal_id = i.inviter_principal_id
	WHERE i.tenant_id = $1 AND `

func scanInvitation(row pgx.CollectableRow) (model.Invitation, error) {
	var i model.Invitation
	err := row.Scan(&i.ID, &i.Email, &i.RoleID, &i.RoleName, &i.ResourceID, &i.ResourceType, &i.ResourceExtID,
		&i.OrganizationID, &i.OrganizationName, &i.InviterID, &i.InviterName,
		&i.ExpiresAt, &i.AcceptedAt, &i.DeclinedAt, &i.RevokedAt, &i.CreatedAt)
	return i, err
}

func (r *organizationRepository) LockInvitationByToken(ctx context.Context, tx pgx.Tx, tenantID string, tokenHash []byte) (*model.Invitation, error) {
	rows, err := tx.Query(ctx, invitationQuery+`i.token_hash = $2 FOR UPDATE OF i`, tenantID, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("lock invitation: %w", err)
	}
	i, err := pgx.CollectOneRow(rows, scanInvitation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock invitation: %w", err)
	}
	return &i, nil
}

func (r *organizationRepository) GetInvitation(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Invitation, error) {
	rows, err := tx.Query(ctx, invitationQuery+`i.id = $2`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get invitation: %w", err)
	}
	i, err := pgx.CollectOneRow(rows, scanInvitation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get invitation: %w", err)
	}
	return &i, nil
}

func (r *organizationRepository) ListInvitations(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) ([]model.Invitation, error) {
	rows, err := tx.Query(ctx, invitationQuery+`
		i.accepted_at IS NULL AND i.declined_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
		AND EXISTS (SELECT 1 FROM aos.resource_ancestors a WHERE a.tenant_id = i.tenant_id AND a.resource_id = i.resource_id AND a.ancestor_id = $2)
		ORDER BY i.created_at`, tenantID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	invitations, err := pgx.CollectRows(rows, scanInvitation)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	return invitations, nil
}

func (r *organizationRepository) MarkInvitationAccepted(ctx context.Context, tx pgx.Tx, tenantID, id, principalID string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.invitations SET accepted_at = $3, accepted_by = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, principalID); err != nil {
		return fmt.Errorf("mark invitation accepted: %w", err)
	}
	return nil
}

func (r *organizationRepository) MarkInvitationDeclined(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.invitations SET declined_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("mark invitation declined: %w", err)
	}
	return nil
}

func (r *organizationRepository) MarkInvitationRevoked(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.invitations SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("mark invitation revoked: %w", err)
	}
	return nil
}

func (r *organizationRepository) RevokeInvitationsFor(ctx context.Context, tx pgx.Tx, tenantID, resourceID, email string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.invitations i SET revoked_at = $4
		FROM aos.resource_ancestors a
		WHERE i.tenant_id = $1 AND i.email = $3 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.declined_at IS NULL
		  AND a.tenant_id = i.tenant_id AND a.resource_id = i.resource_id AND a.ancestor_id = $2`,
		tenantID, resourceID, email, at); err != nil {
		return fmt.Errorf("revoke invitations: %w", err)
	}
	return nil
}

func (r *organizationRepository) SlugTaken(ctx context.Context, tx pgx.Tx, tenantID, slug string) (bool, error) {
	var taken bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM aos.organizations WHERE tenant_id = $1 AND slug = $2)`, tenantID, slug).Scan(&taken)
	if err != nil {
		return false, fmt.Errorf("slug taken: %w", err)
	}
	return taken, nil
}

func (r *organizationRepository) CountOrganizations(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.organizations WHERE tenant_id = $1 AND status = 'active'`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count organizations: %w", err)
	}
	return n, nil
}

func (r *organizationRepository) GetPolicies(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) (*model.OrgPolicies, error) {
	var p model.OrgPolicies
	var maxSeconds *int
	var methods, allow []string
	var breakGlass *string
	err := tx.QueryRow(ctx, `
		SELECT mfa_required, session_max_seconds, allowed_auth_methods, ip_allowlist::text[], enforce_sso, break_glass_principal_id::text
		FROM aos.organizations WHERE tenant_id = $1 AND resource_id = $2`, tenantID, resourceID).Scan(
		&p.MFARequired, &maxSeconds, &methods, &allow, &p.EnforceSSO, &breakGlass)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get policies: %w", err)
	}
	if maxSeconds != nil {
		p.SessionMaxSeconds = *maxSeconds
	}
	if breakGlass != nil {
		p.BreakGlassPrincipalID = *breakGlass
	}
	p.AllowedAuthMethods, p.IPAllowlist = methods, allow
	return &p, nil
}

func (r *organizationRepository) SetPolicies(ctx context.Context, tx pgx.Tx, tenantID, resourceID string, p model.OrgPolicies) error {
	var maxSeconds *int
	if p.SessionMaxSeconds > 0 {
		maxSeconds = &p.SessionMaxSeconds
	}
	var methods any
	if p.AllowedAuthMethods != nil {
		methods = p.AllowedAuthMethods
	}
	var allow any
	if p.IPAllowlist != nil {
		allow = p.IPAllowlist
	}
	if _, err := tx.Exec(ctx, `
		UPDATE aos.organizations SET mfa_required = $3, session_max_seconds = $4, allowed_auth_methods = $5::text[],
		       ip_allowlist = $6::cidr[], enforce_sso = $7, break_glass_principal_id = $8
		WHERE tenant_id = $1 AND resource_id = $2`,
		tenantID, resourceID, p.MFARequired, maxSeconds, methods, allow, p.EnforceSSO, postgres.NullString(p.BreakGlassPrincipalID)); err != nil {
		return fmt.Errorf("set policies: %w", err)
	}
	return nil
}
