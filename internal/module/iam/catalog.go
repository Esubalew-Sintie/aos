package iam

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/model"
)

func (m *iamModule) ListPermissions(ctx context.Context, t *model.Tenant) ([]response.Permission, error) {
	var rows []model.CatalogPermission
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		rows, err = m.repo.ListPermissions(ctx, tx, t.ID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	out := make([]response.Permission, 0, len(rows))
	for _, p := range rows {
		out = append(out, response.Permission{Name: p.Name, Description: p.Description, Source: p.Source, StepUpSeconds: p.StepUpSeconds, NeedsApproval: p.NeedsApproval})
	}
	return out, nil
}

func (m *iamModule) ListRoles(ctx context.Context, t *model.Tenant) ([]response.Role, error) {
	var rows []model.CatalogRole
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		rows, err = m.repo.ListRoles(ctx, tx, t.ID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	out := make([]response.Role, 0, len(rows))
	for _, r := range rows {
		patterns := r.Patterns
		if patterns == nil {
			patterns = []string{}
		}
		out = append(out, response.Role{ID: r.ID, Name: r.Name, Description: r.Description, Source: r.Source, Permissions: patterns})
	}
	return out, nil
}
