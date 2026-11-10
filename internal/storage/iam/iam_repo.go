// Package iam is the SQL for permissions, roles, resources and grants.
package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
)

type iamRepository struct {
	log logger.Logger
}

func NewIAMRepository(log logger.Logger) storage.IAMRepository {
	return &iamRepository{log: log}
}

func (r *iamRepository) UpsertPermission(ctx context.Context, tx pgx.Tx, tenantID, name, description, source string) (string, error) {
	// On a repeat, the description is refreshed and a retired permission
	// comes back. The source is not touched: a permission remembers
	// where it was first created.
	var stored string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.permissions AS p (tenant_id, name, description, source)
		VALUES ($1, $2, NULLIF($3, ''), $4)
		ON CONFLICT (tenant_id, name) DO UPDATE SET
			description = COALESCE(EXCLUDED.description, p.description),
			retired_at  = NULL
		RETURNING source`, tenantID, name, description, source).Scan(&stored)
	if err != nil {
		return "", fmt.Errorf("upsert permission: %w", err)
	}
	return stored, nil
}

func (r *iamRepository) GetRoleByName(ctx context.Context, tx pgx.Tx, tenantID, name string) (string, string, error) {
	var id, source string
	err := tx.QueryRow(ctx, `
		SELECT id::text, source FROM aos.roles
		WHERE tenant_id = $1 AND name = $2 AND organization_id IS NULL`, tenantID, name).Scan(&id, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("get role: %w", err)
	}
	return id, source, nil
}

func (r *iamRepository) UpsertRole(ctx context.Context, tx pgx.Tx, tenantID, name, description, source string) (string, string, error) {
	var id, stored string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.roles AS r (tenant_id, name, description, source)
		VALUES ($1, $2, NULLIF($3, ''), $4)
		ON CONFLICT (tenant_id, name) WHERE organization_id IS NULL DO UPDATE SET
			description = COALESCE(EXCLUDED.description, r.description)
		RETURNING id::text, source`, tenantID, name, description, source).Scan(&id, &stored)
	if err != nil {
		return "", "", fmt.Errorf("upsert role: %w", err)
	}
	return id, stored, nil
}

func (r *iamRepository) ReplaceRolePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, patterns []string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM aos.role_permissions WHERE tenant_id = $1 AND role_id = $2`, tenantID, roleID); err != nil {
		return fmt.Errorf("replace role permissions: %w", err)
	}
	if len(patterns) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.role_permissions (tenant_id, role_id, pattern)
		SELECT $1, $2, p FROM unnest($3::text[]) AS p
		ON CONFLICT DO NOTHING`, tenantID, roleID, patterns); err != nil {
		return fmt.Errorf("replace role permissions: %w", err)
	}
	return nil
}

func (r *iamRepository) EnsureResourceType(ctx context.Context, tx pgx.Tx, tenantID, name string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.resource_types (tenant_id, name, source) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, tenantID, name, constant.SourceCode); err != nil {
		return fmt.Errorf("ensure resource type: %w", err)
	}
	return nil
}

func (r *iamRepository) FindResource(ctx context.Context, tx pgx.Tx, tenantID string, ref model.ResourceRef) (string, string, error) {
	var id string
	var parent *string
	err := tx.QueryRow(ctx, `
		SELECT id::text, parent_id::text FROM aos.resources
		WHERE tenant_id = $1 AND type = $2 AND external_id = $3 AND deleted_at IS NULL`,
		tenantID, ref.Type, ref.ID).Scan(&id, &parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("find resource: %w", err)
	}
	if parent != nil {
		return id, *parent, nil
	}
	return id, "", nil
}

func (r *iamRepository) CreateResource(ctx context.Context, tx pgx.Tx, tenantID string, ref model.ResourceRef, parentID, displayName string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.resources (tenant_id, type, external_id, parent_id, display_name)
		VALUES ($1, $2, $3, $4, NULLIF($5, '')) RETURNING id::text`,
		tenantID, ref.Type, ref.ID, parentID, displayName).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create resource: %w", err)
	}
	return id, nil
}

func (r *iamRepository) GetPrincipalStatus(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (string, error) {
	var status string
	err := tx.QueryRow(ctx,
		`SELECT status FROM aos.principals WHERE tenant_id = $1 AND id = $2`, tenantID, principalID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get principal status: %w", err)
	}
	return status, nil
}

func (r *iamRepository) CreateGrant(ctx context.Context, tx pgx.Tx, tenantID string, g model.NewGrant) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.grants (tenant_id, principal_id, group_id, role_id, resource_id, effect, expires_at, source, reason, created_by, condition)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, NULLIF($11, '')) RETURNING id::text`,
		tenantID, postgres.NullString(g.PrincipalID), postgres.NullString(g.GroupID), g.RoleID, g.ResourceID,
		g.Effect, g.ExpiresAt, g.Source, g.Reason, postgres.NullString(g.CreatedBy), g.Condition).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create grant: %w", err)
	}
	return id, nil
}

func (r *iamRepository) DeleteGrant(ctx context.Context, tx pgx.Tx, tenantID, grantID string) (string, error) {
	var principalID *string
	err := tx.QueryRow(ctx, `
		DELETE FROM aos.grants WHERE tenant_id = $1 AND id = $2
		RETURNING principal_id::text`, tenantID, grantID).Scan(&principalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("delete grant: %w", err)
	}
	if principalID == nil {
		// A grant made to a group. It existed, so say so.
		return "group", nil
	}
	return *principalID, nil
}

func (r *iamRepository) MatchingGrants(ctx context.Context, tx pgx.Tx, tenantID, principalID, resourceID, permission, excludeGrantID string, now time.Time) ([]model.MatchedGrant, error) {
	// The closure table gives the resource and everything above it in one
	// lookup. A grant on any of those nodes applies. The role must hold a
	// pattern that matches the permission, and the grant must be made to
	// the principal or to one of its groups, and not have expired.
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT g.id::text, g.effect, ro.name, COALESCE(g.condition, ''), a.depth
		FROM aos.resource_ancestors a
		JOIN aos.grants g            ON g.tenant_id = a.tenant_id AND g.resource_id = a.ancestor_id
		JOIN aos.roles ro            ON ro.tenant_id = g.tenant_id AND ro.id = g.role_id
		JOIN aos.role_permissions rp ON rp.tenant_id = g.tenant_id AND rp.role_id = g.role_id
		WHERE a.tenant_id = $1
		  AND a.resource_id = $2
		  AND (g.principal_id = $3
		       OR g.group_id IN (SELECT gm.group_id FROM aos.group_members gm
		                         WHERE gm.tenant_id = $1 AND gm.principal_id = $3))
		  AND (g.expires_at IS NULL OR g.expires_at > $4)
		  AND aos.permission_matches(rp.pattern, $5)
		  AND ($6 = '' OR g.id::text <> $6)
		ORDER BY a.depth`, tenantID, resourceID, principalID, now, permission, excludeGrantID)
	if err != nil {
		return nil, fmt.Errorf("matching grants: %w", err)
	}
	grants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.MatchedGrant, error) {
		var g model.MatchedGrant
		err := row.Scan(&g.ID, &g.Effect, &g.RoleName, &g.Condition, &g.Depth)
		g.Conditional = g.Condition != ""
		return g, err
	})
	if err != nil {
		return nil, fmt.Errorf("matching grants: %w", err)
	}
	return grants, nil
}

func (r *iamRepository) LogDecision(ctx context.Context, tx pgx.Tx, tenantID string, d model.Decision) error {
	decision := "deny"
	if d.Allowed {
		decision = "allow"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.decision_log (tenant_id, principal_id, permission, resource_id, decision,
		                              reason_code, via, grant_id, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, 'service', $7, $8)`,
		tenantID, postgres.NullString(d.PrincipalID), d.Permission, postgres.NullString(d.ResourceID),
		decision, d.ReasonCode, postgres.NullString(d.GrantID), postgres.NullString(d.RequestID)); err != nil {
		return fmt.Errorf("log decision: %w", err)
	}
	return nil
}

func (r *iamRepository) TouchPermission(ctx context.Context, tx pgx.Tx, tenantID, name string, now time.Time) error {
	// At most one write an hour per permission. Enough to tell a
	// permission that is in use from one that no check ever asks about.
	if _, err := tx.Exec(ctx, `
		UPDATE aos.permissions SET last_checked_at = $3
		WHERE tenant_id = $1 AND name = $2
		  AND (last_checked_at IS NULL OR last_checked_at < $3::timestamptz - interval '1 hour')`,
		tenantID, name, now); err != nil {
		return fmt.Errorf("touch permission: %w", err)
	}
	return nil
}

func (r *iamRepository) ListGrantsForPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.GrantInfo, error) {
	rows, err := tx.Query(ctx, `
		SELECT g.id::text, ro.name, re.type, re.external_id, g.effect, g.expires_at, g.created_at
		FROM aos.grants g
		JOIN aos.roles ro ON ro.tenant_id = g.tenant_id AND ro.id = g.role_id
		JOIN aos.resources re ON re.tenant_id = g.tenant_id AND re.id = g.resource_id
		WHERE g.tenant_id = $1 AND g.principal_id = $2
		ORDER BY g.created_at`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	grants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.GrantInfo, error) {
		var g model.GrantInfo
		err := row.Scan(&g.ID, &g.Role, &g.ResourceType, &g.ResourceID, &g.Effect, &g.ExpiresAt, &g.CreatedAt)
		return g, err
	})
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	return grants, nil
}

func (r *iamRepository) Ancestors(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) ([]model.ResourceNode, error) {
	rows, err := tx.Query(ctx, `
		SELECT re.id::text, re.type, re.external_id, a.depth
		FROM aos.resource_ancestors a
		JOIN aos.resources re ON re.tenant_id = a.tenant_id AND re.id = a.ancestor_id
		WHERE a.tenant_id = $1 AND a.resource_id = $2
		ORDER BY a.depth`, tenantID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("ancestors: %w", err)
	}
	nodes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.ResourceNode, error) {
		var n model.ResourceNode
		err := row.Scan(&n.ID, &n.Type, &n.ExternalID, &n.Depth)
		return n, err
	})
	if err != nil {
		return nil, fmt.Errorf("ancestors: %w", err)
	}
	return nodes, nil
}

func (r *iamRepository) ActorPatterns(ctx context.Context, tx pgx.Tx, tenantID, principalID, resourceID string, now time.Time) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT rp.pattern
		FROM aos.resource_ancestors a
		JOIN aos.grants g            ON g.tenant_id = a.tenant_id AND g.resource_id = a.ancestor_id
		JOIN aos.role_permissions rp ON rp.tenant_id = g.tenant_id AND rp.role_id = g.role_id
		WHERE a.tenant_id = $1 AND a.resource_id = $2
		  AND g.effect = 'allow' AND g.condition IS NULL
		  AND (g.principal_id = $3
		       OR g.group_id IN (SELECT gm.group_id FROM aos.group_members gm
		                         WHERE gm.tenant_id = $1 AND gm.principal_id = $3))
		  AND (g.expires_at IS NULL OR g.expires_at > $4)`, tenantID, resourceID, principalID, now)
	if err != nil {
		return nil, fmt.Errorf("actor patterns: %w", err)
	}
	patterns, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("actor patterns: %w", err)
	}
	return patterns, nil
}

func (r *iamRepository) RolePatterns(ctx context.Context, tx pgx.Tx, tenantID, roleID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT pattern FROM aos.role_permissions WHERE tenant_id = $1 AND role_id = $2 ORDER BY pattern`, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("role patterns: %w", err)
	}
	patterns, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("role patterns: %w", err)
	}
	return patterns, nil
}

func (r *iamRepository) AllowedResources(ctx context.Context, tx pgx.Tx, tenantID, principalID, permission, resourceType string, now time.Time, limit int) ([]string, []string, error) {
	// One pass over every grant that reaches a resource of the type:
	// an allow without a condition, an allow with one, or a deny.
	rows, err := tx.Query(ctx, `
		WITH reach AS (
			SELECT re.id, re.external_id, g.effect, g.condition IS NOT NULL AS conditional
			FROM aos.grants g
			JOIN aos.role_permissions rp ON rp.tenant_id = g.tenant_id AND rp.role_id = g.role_id
			JOIN aos.resource_ancestors a ON a.tenant_id = g.tenant_id AND a.ancestor_id = g.resource_id
			JOIN aos.resources re ON re.tenant_id = a.tenant_id AND re.id = a.resource_id
			WHERE g.tenant_id = $1
			  AND re.type = $4 AND re.deleted_at IS NULL
			  AND (g.principal_id = $2
			       OR g.group_id IN (SELECT gm.group_id FROM aos.group_members gm
			                         WHERE gm.tenant_id = $1 AND gm.principal_id = $2))
			  AND (g.expires_at IS NULL OR g.expires_at > $5)
			  AND aos.permission_matches(rp.pattern, $3)
		)
		SELECT external_id,
		       bool_or(effect = 'deny')                        AS denied,
		       bool_or(effect = 'allow' AND NOT conditional)    AS allowed,
		       bool_or(effect = 'allow' AND conditional)        AS conditional
		FROM reach
		GROUP BY id, external_id
		ORDER BY external_id
		LIMIT $6`, tenantID, principalID, permission, resourceType, now, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("allowed resources: %w", err)
	}
	defer rows.Close()
	var allowed, conditional []string
	for rows.Next() {
		var ext string
		var denied, ok, cond bool
		if err := rows.Scan(&ext, &denied, &ok, &cond); err != nil {
			return nil, nil, fmt.Errorf("allowed resources: %w", err)
		}
		switch {
		case denied:
		case ok:
			allowed = append(allowed, ext)
		case cond:
			conditional = append(conditional, ext)
		}
	}
	return allowed, conditional, rows.Err()
}

func (r *iamRepository) CandidatePrincipals(ctx context.Context, tx pgx.Tx, tenantID, resourceID, permission string, now time.Time) ([]model.Principal, error) {
	rows, err := tx.Query(ctx, `
		WITH holders AS (
			SELECT g.principal_id AS id FROM aos.resource_ancestors a
			JOIN aos.grants g ON g.tenant_id = a.tenant_id AND g.resource_id = a.ancestor_id
			JOIN aos.role_permissions rp ON rp.tenant_id = g.tenant_id AND rp.role_id = g.role_id
			WHERE a.tenant_id = $1 AND a.resource_id = $2 AND g.effect = 'allow' AND g.principal_id IS NOT NULL
			  AND (g.expires_at IS NULL OR g.expires_at > $4) AND aos.permission_matches(rp.pattern, $3)
			UNION
			SELECT gm.principal_id FROM aos.resource_ancestors a
			JOIN aos.grants g ON g.tenant_id = a.tenant_id AND g.resource_id = a.ancestor_id
			JOIN aos.role_permissions rp ON rp.tenant_id = g.tenant_id AND rp.role_id = g.role_id
			JOIN aos.group_members gm ON gm.tenant_id = g.tenant_id AND gm.group_id = g.group_id
			WHERE a.tenant_id = $1 AND a.resource_id = $2 AND g.effect = 'allow' AND g.group_id IS NOT NULL
			  AND (g.expires_at IS NULL OR g.expires_at > $4) AND aos.permission_matches(rp.pattern, $3)
		)
		SELECT p.id::text, p.kind, COALESCE(u.email::text, ''), COALESCE(u.name, p.display_name, ''), p.status
		FROM holders h
		JOIN aos.principals p ON p.tenant_id = $1 AND p.id = h.id
		LEFT JOIN aos.users u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		ORDER BY u.email, p.id`, tenantID, resourceID, permission, now)
	if err != nil {
		return nil, fmt.Errorf("candidate principals: %w", err)
	}
	principals, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.Principal, error) {
		var p model.Principal
		err := row.Scan(&p.ID, &p.Kind, &p.Email, &p.Name, &p.Status)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("candidate principals: %w", err)
	}
	return principals, nil
}

func (r *iamRepository) GetGrant(ctx context.Context, tx pgx.Tx, tenantID, grantID string) (*model.GrantInfo, []string, error) {
	var g model.GrantInfo
	var principalID, groupID *string
	err := tx.QueryRow(ctx, `
		SELECT g.id::text, g.principal_id::text, g.group_id::text, ro.name, re.type, re.external_id, g.effect, g.expires_at, g.created_at
		FROM aos.grants g
		JOIN aos.roles ro ON ro.tenant_id = g.tenant_id AND ro.id = g.role_id
		JOIN aos.resources re ON re.tenant_id = g.tenant_id AND re.id = g.resource_id
		WHERE g.tenant_id = $1 AND g.id = $2`, tenantID, grantID).Scan(
		&g.ID, &principalID, &groupID, &g.Role, &g.ResourceType, &g.ResourceID, &g.Effect, &g.ExpiresAt, &g.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get grant: %w", err)
	}
	if principalID != nil {
		return &g, []string{*principalID}, nil
	}
	rows, err := tx.Query(ctx, `SELECT principal_id::text FROM aos.group_members WHERE tenant_id = $1 AND group_id = $2`, tenantID, *groupID)
	if err != nil {
		return nil, nil, fmt.Errorf("get grant: %w", err)
	}
	members, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, fmt.Errorf("get grant: %w", err)
	}
	return &g, members, nil
}

func (r *iamRepository) IsUnder(ctx context.Context, tx pgx.Tx, tenantID, resourceID, ancestorID string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM aos.resource_ancestors WHERE tenant_id = $1 AND resource_id = $2 AND ancestor_id = $3)`,
		tenantID, resourceID, ancestorID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("is under: %w", err)
	}
	return ok, nil
}

// ---- groups ----

func (r *iamRepository) UpsertGroup(ctx context.Context, tx pgx.Tx, tenantID, name, organizationID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		SELECT id::text FROM aos.groups
		WHERE tenant_id = $1 AND name = $2 AND organization_id IS NOT DISTINCT FROM $3::uuid`,
		tenantID, name, postgres.NullString(organizationID)).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("upsert group: %w", err)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.groups (tenant_id, name, organization_id) VALUES ($1, $2, $3) RETURNING id::text`,
		tenantID, name, postgres.NullString(organizationID)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert group: %w", err)
	}
	return id, nil
}

func (r *iamRepository) ListGroups(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.Group, error) {
	rows, err := tx.Query(ctx, `
		SELECT g.id::text, g.name, COALESCE(g.organization_id::text, ''),
		       (SELECT count(*) FROM aos.group_members gm WHERE gm.tenant_id = g.tenant_id AND gm.group_id = g.id), g.created_at
		FROM aos.groups g
		WHERE g.tenant_id = $1 AND ($2 = '' OR g.organization_id::text = $2)
		ORDER BY g.name`, tenantID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.Group, error) {
		var g model.Group
		err := row.Scan(&g.ID, &g.Name, &g.OrganizationID, &g.MemberCount, &g.CreatedAt)
		return g, err
	})
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	return groups, nil
}

func (r *iamRepository) DeleteGroup(ctx context.Context, tx pgx.Tx, tenantID, groupID string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM aos.groups WHERE tenant_id = $1 AND id = $2`, tenantID, groupID)
	if err != nil {
		return false, fmt.Errorf("delete group: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *iamRepository) AddGroupMember(ctx context.Context, tx pgx.Tx, tenantID, groupID, principalID string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.group_members (tenant_id, group_id, principal_id) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, tenantID, groupID, principalID); err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

func (r *iamRepository) RemoveGroupMember(ctx context.Context, tx pgx.Tx, tenantID, groupID, principalID string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM aos.group_members WHERE tenant_id = $1 AND group_id = $2 AND principal_id = $3`,
		tenantID, groupID, principalID)
	if err != nil {
		return false, fmt.Errorf("remove group member: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *iamRepository) GroupExists(ctx context.Context, tx pgx.Tx, tenantID, groupID string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM aos.groups WHERE tenant_id = $1 AND id = $2)`, tenantID, groupID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("group exists: %w", err)
	}
	return ok, nil
}

func (r *iamRepository) SetPermissionStepUp(ctx context.Context, tx pgx.Tx, tenantID, name string, seconds int) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.permissions SET step_up_seconds = NULLIF($3, 0) WHERE tenant_id = $1 AND name = $2`,
		tenantID, name, seconds); err != nil {
		return fmt.Errorf("set permission step-up: %w", err)
	}
	return nil
}

func (r *iamRepository) PermissionStepUp(ctx context.Context, tx pgx.Tx, tenantID, name string) (int, error) {
	var seconds *int
	err := tx.QueryRow(ctx, `SELECT step_up_seconds FROM aos.permissions WHERE tenant_id = $1 AND name = $2`, tenantID, name).Scan(&seconds)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && seconds == nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("permission step-up: %w", err)
	}
	return *seconds, nil
}

func (r *iamRepository) SessionSecondFactorAt(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (*time.Time, bool, error) {
	var at *time.Time
	err := tx.QueryRow(ctx, `SELECT second_factor_at FROM aos.sessions WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, sessionID).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("session second factor: %w", err)
	}
	return at, true, nil
}

func (r *iamRepository) SetPermissionNeedsApproval(ctx context.Context, tx pgx.Tx, tenantID, name string, needs bool) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.permissions SET needs_approval = $3 WHERE tenant_id = $1 AND name = $2`, tenantID, name, needs); err != nil {
		return fmt.Errorf("set permission approval: %w", err)
	}
	return nil
}

func (r *iamRepository) PermissionNeedsApproval(ctx context.Context, tx pgx.Tx, tenantID, name string) (bool, error) {
	var needs bool
	err := tx.QueryRow(ctx, `SELECT needs_approval FROM aos.permissions WHERE tenant_id = $1 AND name = $2`, tenantID, name).Scan(&needs)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("permission approval: %w", err)
	}
	return needs, nil
}

func (r *iamRepository) GetPrincipalKind(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (string, error) {
	if !postgres.IsUUID(principalID) {
		return "", nil
	}
	var kind string
	err := tx.QueryRow(ctx, `SELECT kind FROM aos.principals WHERE tenant_id = $1 AND id = $2`, tenantID, principalID).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("principal kind: %w", err)
	}
	return kind, nil
}
