// Package audit is the SQL for the tenant's audit log.
//
// An entry is written in the same transaction as the change it records,
// so neither exists without the other. Each entry carries the hash of
// the entry before it. Changing or removing any entry breaks every hash
// after it, which Verify detects.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
)

type auditRepository struct {
	log logger.Logger
}

func NewAuditRepository(log logger.Logger) storage.AuditRepository {
	return &auditRepository{log: log}
}

func (r *auditRepository) Append(ctx context.Context, tx pgx.Tx, tenantID string, e model.AuditEntry) error {
	if e.Action == "" || e.Result == "" {
		return errors.New("audit: an entry needs an action and a result")
	}

	// Lock the head row. This gives the chain exactly one order per tenant.
	var seq int64
	var prev []byte
	err := tx.QueryRow(ctx,
		`SELECT last_seq, last_hash FROM aos.audit_heads WHERE tenant_id = $1 FOR UPDATE`, tenantID).Scan(&seq, &prev)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO aos.audit_heads (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, tenantID); err != nil {
			return fmt.Errorf("audit: create head: %w", err)
		}
		err = tx.QueryRow(ctx,
			`SELECT last_seq, last_hash FROM aos.audit_heads WHERE tenant_id = $1 FOR UPDATE`, tenantID).Scan(&seq, &prev)
	}
	if err != nil {
		return fmt.Errorf("audit: lock head: %w", err)
	}
	seq++

	// Postgres keeps microseconds. Round first, so the stored time and
	// the hashed time are the same value.
	at := time.Now().UTC().Truncate(time.Microsecond)
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	data, err := json.Marshal(e.Data)
	if err != nil {
		return fmt.Errorf("audit: encode data: %w", err)
	}
	hash := entryHash(prev, seq, at, e, data)

	_, err = tx.Exec(ctx, `
		INSERT INTO aos.audit_log (
			tenant_id, seq, occurred_at, organization_id, actor_principal_id,
			impersonator_principal_id, on_behalf_of_principal_id, action, target_type,
			target_id, result, reason_code, session_id, request_id, data, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		tenantID, seq, at, postgres.NullString(e.OrganizationID), postgres.NullString(e.ActorID),
		postgres.NullString(e.ImpersonatorID), postgres.NullString(e.OnBehalfOfID), e.Action,
		postgres.NullString(e.TargetType), postgres.NullString(e.TargetID), e.Result,
		postgres.NullString(e.ReasonCode), postgres.NullString(e.SessionID), postgres.NullString(e.RequestID),
		data, prev, hash)
	if err != nil {
		return fmt.Errorf("audit: insert entry: %w", err)
	}

	if e.IP != "" || e.UserAgent != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO aos.audit_log_personal (tenant_id, seq, ip, user_agent)
			VALUES ($1, $2, NULLIF($3, '')::inet, NULLIF($4, ''))`,
			tenantID, seq, e.IP, e.UserAgent); err != nil {
			return fmt.Errorf("audit: insert personal details: %w", err)
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE aos.audit_heads SET last_seq = $2, last_hash = $3 WHERE tenant_id = $1`, tenantID, seq, hash); err != nil {
		return fmt.Errorf("audit: move head: %w", err)
	}
	return nil
}

func (r *auditRepository) Verify(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	rows, err := tx.Query(ctx, `
		SELECT seq, occurred_at, COALESCE(organization_id::text, ''), COALESCE(actor_principal_id::text, ''),
		       COALESCE(impersonator_principal_id::text, ''), COALESCE(on_behalf_of_principal_id::text, ''),
		       action, COALESCE(target_type, ''), COALESCE(target_id, ''), result,
		       COALESCE(reason_code, ''), COALESCE(session_id::text, ''), COALESCE(request_id, ''),
		       data, prev_hash, hash
		FROM aos.audit_log WHERE tenant_id = $1 ORDER BY seq`, tenantID)
	if err != nil {
		return 0, fmt.Errorf("audit: read log: %w", err)
	}
	defer rows.Close()

	var count int64
	var prev []byte
	for rows.Next() {
		var (
			seq                 int64
			at                  time.Time
			e                   model.AuditEntry
			storedPrev, storedH []byte
			rawData             []byte
		)
		if err := rows.Scan(&seq, &at, &e.OrganizationID, &e.ActorID, &e.ImpersonatorID, &e.OnBehalfOfID,
			&e.Action, &e.TargetType, &e.TargetID, &e.Result, &e.ReasonCode, &e.SessionID, &e.RequestID,
			&rawData, &storedPrev, &storedH); err != nil {
			return count, fmt.Errorf("audit: read entry: %w", err)
		}
		count++
		if seq != count {
			return count, fmt.Errorf("audit: chain broken: expected entry %d, found %d (an entry is missing)", count, seq)
		}
		if !bytes.Equal(storedPrev, prev) {
			return count, fmt.Errorf("audit: chain broken at entry %d: it does not follow the entry before it", seq)
		}
		// The database stores JSON in its own layout. Decode and encode
		// again to get the same bytes that were hashed when it was written.
		var decoded map[string]any
		if err := json.Unmarshal(rawData, &decoded); err != nil {
			return count, fmt.Errorf("audit: entry %d: unreadable data: %w", seq, err)
		}
		data, err := json.Marshal(decoded)
		if err != nil {
			return count, fmt.Errorf("audit: entry %d: %w", seq, err)
		}
		if want := entryHash(prev, seq, at.UTC(), e, data); !bytes.Equal(want, storedH) {
			return count, fmt.Errorf("audit: chain broken at entry %d: its contents were changed", seq)
		}
		prev = storedH
	}
	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("audit: read log: %w", err)
	}

	// The head must point at the last entry, or entries were cut off the end.
	var headSeq int64
	err = tx.QueryRow(ctx, `SELECT last_seq FROM aos.audit_heads WHERE tenant_id = $1`, tenantID).Scan(&headSeq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return count, fmt.Errorf("audit: read head: %w", err)
	}
	if headSeq != count {
		return count, fmt.Errorf("audit: chain broken: the log has %d entries but %d were written (the end was cut off)", count, headSeq)
	}
	return count, nil
}

// entryHash is SHA-256 over the previous hash and every field of the
// entry, in a fixed order with fixed separators.
func entryHash(prev []byte, seq int64, at time.Time, e model.AuditEntry, data []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	fields := []string{
		fmt.Sprint(seq), at.Format(time.RFC3339Nano), e.OrganizationID, e.ActorID, e.ImpersonatorID,
		e.OnBehalfOfID, e.Action, e.TargetType, e.TargetID, e.Result, e.ReasonCode, e.SessionID, e.RequestID,
	}
	for _, f := range fields {
		// Length first, so "ab"+"c" and "a"+"bc" cannot hash the same.
		fmt.Fprintf(h, "%d:%s|", len(f), f)
	}
	h.Write(data)
	return h.Sum(nil)
}

func (r *auditRepository) ListForPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID string, limit int) ([]model.AuditView, error) {
	rows, err := tx.Query(ctx, `
		SELECT seq, occurred_at, action, result, COALESCE(reason_code, ''), COALESCE(target_type, ''), COALESCE(target_id, '')
		FROM aos.audit_log
		WHERE tenant_id = $1 AND (actor_principal_id = $2 OR (target_type = 'user' AND target_id = $2::text))
		ORDER BY seq DESC LIMIT $3`, tenantID, principalID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list entries: %w", err)
	}
	entries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.AuditView, error) {
		var v model.AuditView
		err := row.Scan(&v.Seq, &v.OccurredAt, &v.Action, &v.Result, &v.ReasonCode, &v.TargetType, &v.TargetID)
		return v, err
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list entries: %w", err)
	}
	return entries, nil
}

func (r *auditRepository) ListSince(ctx context.Context, tx pgx.Tx, tenantID, organizationID string, afterSeq int64, limit int) ([]model.AuditExportEntry, error) {
	rows, err := tx.Query(ctx, `
		SELECT seq, occurred_at, COALESCE(organization_id::text, ''), COALESCE(actor_principal_id::text, ''), action,
		       COALESCE(target_type, ''), COALESCE(target_id, ''), result, COALESCE(reason_code, ''), data, hash
		FROM aos.audit_log
		WHERE tenant_id = $1 AND organization_id = $2 AND seq > $3
		ORDER BY seq LIMIT $4`, tenantID, organizationID, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit since: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.AuditExportEntry, error) {
		var e model.AuditExportEntry
		var data []byte
		if err := row.Scan(&e.Seq, &e.OccurredAt, &e.OrganizationID, &e.ActorID, &e.Action, &e.TargetType, &e.TargetID, &e.Result, &e.ReasonCode, &data, &e.Hash); err != nil {
			return e, err
		}
		return e, json.Unmarshal(data, &e.Data)
	})
	if err != nil {
		return nil, fmt.Errorf("list audit since: %w", err)
	}
	return out, nil
}
