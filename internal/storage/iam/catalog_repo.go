package iam

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant/model"
)

func (r *iamRepository) ListPermissions(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.CatalogPermission, error) {
	rows, err := tx.Query(ctx, `
		SELECT name, COALESCE(description, ''), source, COALESCE(step_up_seconds, 0), needs_approval
		FROM aos.permissions WHERE tenant_id = $1 AND retired_at IS NULL ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.CatalogPermission, error) {
		var p model.CatalogPermission
		err := row.Scan(&p.Name, &p.Description, &p.Source, &p.StepUpSeconds, &p.NeedsApproval)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	return out, nil
}

func (r *iamRepository) ListRoles(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.CatalogRole, error) {
	rows, err := tx.Query(ctx, `
		SELECT ro.id::text, ro.name, COALESCE(ro.description, ''), ro.source,
		       COALESCE((SELECT array_agg(rp.pattern ORDER BY rp.pattern) FROM aos.role_permissions rp
		                 WHERE rp.tenant_id = ro.tenant_id AND rp.role_id = ro.id), '{}')
		FROM aos.roles ro WHERE ro.tenant_id = $1 AND ro.organization_id IS NULL ORDER BY ro.name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.CatalogRole, error) {
		var ro model.CatalogRole
		err := row.Scan(&ro.ID, &ro.Name, &ro.Description, &ro.Source, &ro.Patterns)
		return ro, err
	})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}
