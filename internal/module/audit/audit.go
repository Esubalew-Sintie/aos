// Package audit reads the tenant's audit log for its admins. Writing
// to the log is done by each module, in the transaction of the change.
package audit

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
)

type auditModule struct {
	db   *postgres.DB
	repo storage.AuditRepository
	log  logger.Logger
}

func NewAuditModule(db *postgres.DB, repo storage.AuditRepository, log logger.Logger) module.Audit {
	return &auditModule{db: db, repo: repo, log: log}
}

func (m *auditModule) List(ctx context.Context, t *model.Tenant, req request.ListAuditRequest) (*response.AuditPage, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	limit := req.Limit
	if limit <= 0 {
		limit = constant.DefaultPageSize
	}
	if limit > constant.MaxPageSize {
		limit = constant.MaxPageSize
	}
	filter := model.AuditFilter{Before: req.Before, ActionPrefix: req.Action, ActorID: req.ActorID, TargetID: req.TargetID}

	// One more than asked tells whether another page follows.
	var entries []model.AuditRecord
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		entries, err = m.repo.List(ctx, tx, t.ID, filter, limit+1)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}

	page := &response.AuditPage{Entries: make([]response.AuditRecord, 0, len(entries))}
	for i, e := range entries {
		if i == limit {
			page.NextBefore = entries[i-1].Seq
			break
		}
		page.Entries = append(page.Entries, response.AuditRecord{
			Seq: e.Seq, OccurredAt: e.OccurredAt, Action: e.Action, Result: e.Result, ReasonCode: e.ReasonCode,
			ActorType: e.ActorType, ActorID: e.ActorID, ActorEmail: e.ActorEmail,
			TargetType: e.TargetType, TargetID: e.TargetID, OrganizationID: e.OrganizationID, IP: e.IP,
		})
	}
	return page, nil
}
