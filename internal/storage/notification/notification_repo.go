// Package notification is the SQL for the outbox: messages waiting to be
// sent, events waiting to be delivered, and the endpoints they go to.
package notification

import (
	"context"
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

type notificationRepository struct {
	log logger.Logger
}

func NewNotificationRepository(log logger.Logger) storage.NotificationRepository {
	return &notificationRepository{log: log}
}

// ---- messages ----

func (r *notificationRepository) CreateMessage(ctx context.Context, tx pgx.Tx, tenantID string, m model.Message, body []byte, dataKeyID string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.messages (tenant_id, channel, recipient, template, body_encrypted, data_key_id)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		tenantID, m.Channel, m.Recipient, m.Template, body, dataKeyID); err != nil {
		return fmt.Errorf("create message: %w", err)
	}
	return nil
}

func (r *notificationRepository) DueMessages(ctx context.Context, tx pgx.Tx, limit int) ([]model.DueMessage, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, message_id::text FROM aos.due_messages($1)`, limit)
	if err != nil {
		return nil, fmt.Errorf("due messages: %w", err)
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.DueMessage, error) {
		var d model.DueMessage
		err := row.Scan(&d.TenantID, &d.ID)
		return d, err
	})
	if err != nil {
		return nil, fmt.Errorf("due messages: %w", err)
	}
	return due, nil
}

func (r *notificationRepository) LockMessage(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.StoredMessage, error) {
	var m model.StoredMessage
	var keyID *string
	// SKIP LOCKED: if another worker holds this message, leave it to them.
	err := tx.QueryRow(ctx, `
		SELECT channel, recipient, template, body_encrypted, data_key_id::text, attempts
		FROM aos.messages
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
		FOR UPDATE SKIP LOCKED`, tenantID, id).Scan(
		&m.Channel, &m.Recipient, &m.Template, &m.Body, &keyID, &m.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock message: %w", err)
	}
	if keyID != nil {
		m.DataKeyID = *keyID
	}
	return &m, nil
}

func (r *notificationRepository) MarkMessageSent(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.messages
		SET status = 'sent', body_encrypted = NULL, sent_at = $3, attempts = attempts + 1
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("mark message sent: %w", err)
	}
	return nil
}

func (r *notificationRepository) MarkMessageRetry(ctx context.Context, tx pgx.Tx, tenantID, id string, nextAttempt time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.messages SET attempts = attempts + 1, next_attempt_at = $3
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, nextAttempt); err != nil {
		return fmt.Errorf("mark message retry: %w", err)
	}
	return nil
}

func (r *notificationRepository) MarkMessageFailed(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	// A message that will never be sent must not keep its body either.
	if _, err := tx.Exec(ctx, `
		UPDATE aos.messages SET status = 'failed', body_encrypted = NULL, attempts = attempts + 1
		WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
		return fmt.Errorf("mark message failed: %w", err)
	}
	return nil
}

// ---- events ----

func (r *notificationRepository) CreateEvent(ctx context.Context, tx pgx.Tx, tenantID, eventType string, payload map[string]any) (string, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("create event: %w", err)
	}
	var id string
	if err := tx.QueryRow(ctx,
		`INSERT INTO aos.events (tenant_id, type, payload) VALUES ($1, $2, $3) RETURNING id::text`,
		tenantID, eventType, body).Scan(&id); err != nil {
		return "", fmt.Errorf("create event: %w", err)
	}
	return id, nil
}

// ---- webhook endpoints ----

func (r *notificationRepository) CreateWebhookEndpoint(ctx context.Context, tx pgx.Tx, tenantID string, e model.WebhookEndpoint) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.webhook_endpoints (tenant_id, organization_id, kind, url, label, signing_secret_encrypted,
		                                   data_key_id, event_types, timeout_ms, enabled)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, true) RETURNING id::text`,
		tenantID, postgres.NullString(e.OrganizationID), e.Kind, e.URL, e.Label, e.SecretEncrypted,
		e.DataKeyID, e.EventTypes, e.TimeoutMs).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create webhook endpoint: %w", err)
	}
	return id, nil
}

func (r *notificationRepository) ListWebhookEndpoints(ctx context.Context, tx pgx.Tx, tenantID, kind string) ([]model.WebhookEndpoint, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, kind, url, COALESCE(label, ''), event_types, timeout_ms, enabled,
		       signing_secret_encrypted, data_key_id::text, COALESCE(organization_id::text, ''),
		       created_at, last_success_at, last_failure_at, COALESCE(last_error, '')
		FROM aos.webhook_endpoints
		WHERE tenant_id = $1 AND enabled AND ($2 = '' OR kind = $2)
		ORDER BY created_at`, tenantID, kind)
	if err != nil {
		return nil, fmt.Errorf("list webhook endpoints: %w", err)
	}
	endpoints, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.WebhookEndpoint, error) {
		var e model.WebhookEndpoint
		err := row.Scan(&e.ID, &e.Kind, &e.URL, &e.Label, &e.EventTypes, &e.TimeoutMs, &e.Enabled,
			&e.SecretEncrypted, &e.DataKeyID, &e.OrganizationID, &e.CreatedAt, &e.LastSuccessAt, &e.LastFailureAt, &e.LastError)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("list webhook endpoints: %w", err)
	}
	return endpoints, nil
}

func (r *notificationRepository) DeleteWebhookEndpoint(ctx context.Context, tx pgx.Tx, tenantID, id string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM aos.webhook_endpoints WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return false, fmt.Errorf("delete webhook endpoint: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---- deliveries ----

func (r *notificationRepository) CreateDeliveries(ctx context.Context, tx pgx.Tx, tenantID, eventID string, endpointIDs []string) error {
	if len(endpointIDs) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.webhook_deliveries (tenant_id, endpoint_id, event_id)
		SELECT $1, e::uuid, $2 FROM unnest($3::text[]) AS e
		ON CONFLICT DO NOTHING`, tenantID, eventID, endpointIDs); err != nil {
		return fmt.Errorf("create deliveries: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE aos.events SET dispatched_at = now() WHERE tenant_id = $1 AND id = $2`,
		tenantID, eventID); err != nil {
		return fmt.Errorf("create deliveries: %w", err)
	}
	return nil
}

func (r *notificationRepository) DueDeliveries(ctx context.Context, tx pgx.Tx, limit int) ([]model.DueDelivery, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, delivery_id::text FROM aos.due_deliveries($1)`, limit)
	if err != nil {
		return nil, fmt.Errorf("due deliveries: %w", err)
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.DueDelivery, error) {
		var d model.DueDelivery
		err := row.Scan(&d.TenantID, &d.ID)
		return d, err
	})
	if err != nil {
		return nil, fmt.Errorf("due deliveries: %w", err)
	}
	return due, nil
}

func (r *notificationRepository) LockDelivery(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.StoredDelivery, error) {
	var d model.StoredDelivery
	err := tx.QueryRow(ctx, `
		SELECT d.id::text, d.endpoint_id::text, d.event_id::text, ev.type, ev.payload, ev.created_at, d.attempts,
		       w.url, w.signing_secret_encrypted, w.data_key_id::text, w.timeout_ms
		FROM aos.webhook_deliveries d
		JOIN aos.events ev ON ev.tenant_id = d.tenant_id AND ev.id = d.event_id
		JOIN aos.webhook_endpoints w ON w.tenant_id = d.tenant_id AND w.id = d.endpoint_id
		WHERE d.tenant_id = $1 AND d.id = $2 AND d.status = 'pending'
		FOR UPDATE OF d SKIP LOCKED`, tenantID, id).Scan(
		&d.ID, &d.EndpointID, &d.EventID, &d.EventType, &d.Payload, &d.EventCreatedAt, &d.Attempts,
		&d.URL, &d.SecretEncrypted, &d.DataKeyID, &d.TimeoutMs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock delivery: %w", err)
	}
	return &d, nil
}

func (r *notificationRepository) MarkDeliveryDelivered(ctx context.Context, tx pgx.Tx, tenantID, id string, statusCode int, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.webhook_deliveries
		SET status = 'delivered', attempts = attempts + 1, last_status_code = $3, last_error = NULL, delivered_at = $4
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, statusCode, at); err != nil {
		return fmt.Errorf("mark delivery delivered: %w", err)
	}
	return nil
}

func (r *notificationRepository) MarkDeliveryRetry(ctx context.Context, tx pgx.Tx, tenantID, id string, statusCode int, errMsg string, nextAttempt time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.webhook_deliveries
		SET attempts = attempts + 1, last_status_code = NULLIF($3, 0), last_error = left($4, 500), next_attempt_at = $5
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, statusCode, errMsg, nextAttempt); err != nil {
		return fmt.Errorf("mark delivery retry: %w", err)
	}
	return nil
}

func (r *notificationRepository) MarkDeliveryFailed(ctx context.Context, tx pgx.Tx, tenantID, id string, statusCode int, errMsg string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.webhook_deliveries
		SET status = 'failed', attempts = attempts + 1, last_status_code = NULLIF($3, 0), last_error = left($4, 500)
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, statusCode, errMsg); err != nil {
		return fmt.Errorf("mark delivery failed: %w", err)
	}
	return nil
}

func (r *notificationRepository) RecordEndpointResult(ctx context.Context, tx pgx.Tx, tenantID, endpointID string, ok bool, errMsg string, at time.Time) error {
	var err error
	if ok {
		_, err = tx.Exec(ctx, `
			UPDATE aos.webhook_endpoints SET last_success_at = $3, last_error = NULL
			WHERE tenant_id = $1 AND id = $2`, tenantID, endpointID, at)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE aos.webhook_endpoints SET last_failure_at = $3, last_error = left($4, 500)
			WHERE tenant_id = $1 AND id = $2`, tenantID, endpointID, at, errMsg)
	}
	if err != nil {
		return fmt.Errorf("record endpoint result: %w", err)
	}
	return nil
}

func (r *notificationRepository) AuditExportEndpoints(ctx context.Context, tx pgx.Tx) ([]struct{ TenantID, EndpointID string }, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, endpoint_id::text FROM aos.audit_export_endpoints()`)
	if err != nil {
		return nil, fmt.Errorf("audit export endpoints: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (struct{ TenantID, EndpointID string }, error) {
		var e struct{ TenantID, EndpointID string }
		err := row.Scan(&e.TenantID, &e.EndpointID)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("audit export endpoints: %w", err)
	}
	return out, nil
}

func (r *notificationRepository) GetAuditEndpoint(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.AuditEndpoint, error) {
	var e model.AuditEndpoint
	err := tx.QueryRow(ctx, `
		SELECT id::text, url, COALESCE(organization_id::text, ''), signing_secret_encrypted, data_key_id::text, timeout_ms, audit_cursor
		FROM aos.webhook_endpoints WHERE tenant_id = $1 AND id = $2 AND enabled AND kind = 'audit_export'`, tenantID, id).Scan(
		&e.ID, &e.URL, &e.OrganizationID, &e.SecretEncrypted, &e.DataKeyID, &e.TimeoutMs, &e.Cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit endpoint: %w", err)
	}
	return &e, nil
}

func (r *notificationRepository) SetAuditCursor(ctx context.Context, tx pgx.Tx, tenantID, id string, cursor int64) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.webhook_endpoints SET audit_cursor = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, cursor); err != nil {
		return fmt.Errorf("set audit cursor: %w", err)
	}
	return nil
}
