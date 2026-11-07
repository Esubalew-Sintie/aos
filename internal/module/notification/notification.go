// Package notification is the outbox. A message or an event is written
// in the same transaction as the change that caused it, and delivered
// afterwards. If the change is rolled back, nothing is sent. If delivery
// fails, it is tried again.
//
// It also asks the application's before-hooks whether an action may go
// ahead, and refuses the action when they cannot be reached.
package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	apperrors "github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/module"
	"github.com/flash-softeware/aos/internal/module/notification/core"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/mailer"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

type notificationModule struct {
	db           *postgres.DB
	repo         storage.NotificationRepository
	audit        storage.AuditRepository
	keys         module.KeyRing
	sender       mailer.Sender
	client       *http.Client
	allowPrivate bool
	now          func() time.Time
	log          logger.Logger
	wake         chan struct{}
}

// NewNotificationModule builds the outbox. allowPrivate lets webhooks
// and hooks call addresses on this machine or a private network. It is
// for development only: in production such a call could reach services
// that are not meant to be reachable from outside.
func NewNotificationModule(db *postgres.DB, repo storage.NotificationRepository, audit storage.AuditRepository,
	keys module.KeyRing, sender mailer.Sender, allowPrivate bool, now func() time.Time, log logger.Logger) module.Notification {
	return &notificationModule{
		db: db, repo: repo, audit: audit, keys: keys, sender: sender, allowPrivate: allowPrivate, now: now, log: log,
		// Redirects are never followed: a listed address must answer itself.
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		wake:   make(chan struct{}, 1),
	}
}

// ---------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------

func (m *notificationModule) Enqueue(ctx context.Context, tx pgx.Tx, t *model.Tenant, msg model.Message) error {
	data := map[string]string{"app": t.Name}
	for k, v := range msg.Data {
		data[k] = v
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("enqueue message: %w", err)
	}
	// The body can hold a raw token, so it is never stored in clear.
	keyID, key, err := m.keys.DataKey(ctx, tx, t.ID)
	if err != nil {
		return fmt.Errorf("enqueue message: %w", err)
	}
	sealed, err := secret.Seal(key, plain, messageContext(t.ID))
	if err != nil {
		return fmt.Errorf("enqueue message: %w", err)
	}
	return m.repo.CreateMessage(ctx, tx, t.ID, msg, sealed, keyID)
}

func (m *notificationModule) DeliverDue(ctx context.Context) (int, error) {
	var due []model.DueMessage
	err := m.db.Resolver(ctx, func(tx pgx.Tx) (err error) {
		due, err = m.repo.DueMessages(ctx, tx, constant.MessageBatchSize)
		return err
	})
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, d := range due {
		ok, err := m.deliverMessage(ctx, d)
		if err != nil {
			// One bad message must not stop the others.
			m.log.Error(ctx, "message could not be processed", "message_id", d.ID, "error", err.Error())
			continue
		}
		if ok {
			sent++
		}
	}
	return sent, nil
}

func (m *notificationModule) deliverMessage(ctx context.Context, d model.DueMessage) (bool, error) {
	sent := false
	err := m.db.Tenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		msg, err := m.repo.LockMessage(ctx, tx, d.TenantID, d.ID)
		if err != nil {
			return err
		}
		if msg == nil {
			return nil // another worker has it, or it is done
		}
		email, err := m.render(ctx, tx, d.TenantID, msg)
		if err != nil {
			// It can never be sent. Do not retry forever.
			m.log.Error(ctx, "message dropped: it could not be built", "message_id", d.ID, "error", err.Error())
			return m.repo.MarkMessageFailed(ctx, tx, d.TenantID, d.ID)
		}
		if err := m.sender.Send(ctx, email); err != nil {
			if msg.Attempts+1 >= constant.MessageMaxAttempts {
				m.log.Error(ctx, "message dropped: too many failed attempts", "message_id", d.ID, "error", err.Error())
				return m.repo.MarkMessageFailed(ctx, tx, d.TenantID, d.ID)
			}
			m.log.Warn(ctx, "message not sent, will retry", "message_id", d.ID, "error", err.Error())
			return m.repo.MarkMessageRetry(ctx, tx, d.TenantID, d.ID, m.now().Add(backoff(msg.Attempts)))
		}
		sent = true
		return m.repo.MarkMessageSent(ctx, tx, d.TenantID, d.ID, m.now())
	})
	return sent, err
}

func (m *notificationModule) render(ctx context.Context, tx pgx.Tx, tenantID string, msg *model.StoredMessage) (mailer.Email, error) {
	if msg.Channel != constant.ChannelEmail {
		return mailer.Email{}, fmt.Errorf("channel %q is not supported yet", msg.Channel)
	}
	key, err := m.keys.DataKeyByID(ctx, tx, tenantID, msg.DataKeyID)
	if err != nil {
		return mailer.Email{}, err
	}
	plain, err := secret.Open(key, msg.Body, messageContext(tenantID))
	if err != nil {
		return mailer.Email{}, err
	}
	var data map[string]string
	if err := json.Unmarshal(plain, &data); err != nil {
		return mailer.Email{}, err
	}
	subject, body, err := core.Render(msg.Template, data)
	if err != nil {
		return mailer.Email{}, err
	}
	return mailer.Email{To: msg.Recipient, Subject: subject, Body: body}, nil
}

// ---------------------------------------------------------------------
// Events and webhooks
// ---------------------------------------------------------------------

func (m *notificationModule) Emit(ctx context.Context, tx pgx.Tx, tenantID, eventType string, payload map[string]any) error {
	eventID, err := m.repo.CreateEvent(ctx, tx, tenantID, eventType, payload)
	if err != nil {
		return err
	}
	endpoints, err := m.repo.ListWebhookEndpoints(ctx, tx, tenantID, constant.WebhookKindEvents)
	if err != nil {
		return err
	}
	var wanted []string
	for _, e := range endpoints {
		if wants(e.EventTypes, eventType) {
			wanted = append(wanted, e.ID)
		}
	}
	return m.repo.CreateDeliveries(ctx, tx, tenantID, eventID, wanted)
}

// wants reports whether a list of event names covers one event. A name
// matches exactly, "*" matches everything, and "user.*" matches a prefix.
func wants(types []string, eventType string) bool {
	for _, t := range types {
		switch {
		case t == "*", t == eventType:
			return true
		case strings.HasSuffix(t, ".*") && strings.HasPrefix(eventType, t[:len(t)-1]):
			return true
		}
	}
	return false
}

func (m *notificationModule) DeliverWebhooks(ctx context.Context) (int, error) {
	var due []model.DueDelivery
	err := m.db.Resolver(ctx, func(tx pgx.Tx) (err error) {
		due, err = m.repo.DueDeliveries(ctx, tx, constant.WebhookBatchSize)
		return err
	})
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, d := range due {
		ok, err := m.deliverWebhook(ctx, d)
		if err != nil {
			m.log.Error(ctx, "webhook delivery could not be processed", "delivery_id", d.ID, "error", err.Error())
			continue
		}
		if ok {
			delivered++
		}
	}
	return delivered, nil
}

func (m *notificationModule) deliverWebhook(ctx context.Context, due model.DueDelivery) (bool, error) {
	delivered := false
	err := m.db.Tenant(ctx, due.TenantID, func(tx pgx.Tx) error {
		d, err := m.repo.LockDelivery(ctx, tx, due.TenantID, due.ID)
		if err != nil {
			return err
		}
		if d == nil {
			return nil
		}
		key, err := m.keys.DataKeyByID(ctx, tx, due.TenantID, d.DataKeyID)
		if err != nil {
			return err
		}
		signingSecret, err := secret.Open(key, d.SecretEncrypted, webhookContext(due.TenantID))
		if err != nil {
			return err
		}

		body, err := json.Marshal(map[string]any{
			"id": d.ID, "event": d.EventType, "created_at": d.EventCreatedAt.UTC(),
			"data": json.RawMessage(d.Payload),
		})
		if err != nil {
			return err
		}
		headers := map[string]string{"X-AOS-Event": d.EventType, "X-AOS-Delivery": d.ID}
		status, _, err := m.post(ctx, d.URL, time.Duration(d.TimeoutMs)*time.Millisecond, signingSecret, body, headers)
		now := m.now()
		if err == nil && status >= 200 && status < 300 {
			delivered = true
			if err := m.repo.RecordEndpointResult(ctx, tx, due.TenantID, d.EndpointID, true, "", now); err != nil {
				return err
			}
			return m.repo.MarkDeliveryDelivered(ctx, tx, due.TenantID, d.ID, status, now)
		}
		problem := fmt.Sprintf("answered %d", status)
		if err != nil {
			problem = err.Error()
		}
		if err := m.repo.RecordEndpointResult(ctx, tx, due.TenantID, d.EndpointID, false, problem, now); err != nil {
			return err
		}
		if d.Attempts+1 >= constant.WebhookMaxAttempts {
			m.log.Error(ctx, "webhook delivery dropped: too many failed attempts", "delivery_id", d.ID, "problem", problem)
			return m.repo.MarkDeliveryFailed(ctx, tx, due.TenantID, d.ID, status, problem)
		}
		return m.repo.MarkDeliveryRetry(ctx, tx, due.TenantID, d.ID, status, problem, now.Add(backoff(d.Attempts)))
	})
	return delivered, err
}

// ---------------------------------------------------------------------
// Before-hooks
// ---------------------------------------------------------------------

// hookAnswer is what a before-hook endpoint must send back.
type hookAnswer struct {
	Allow   bool   `json:"allow"`
	Message string `json:"message"`
}

func (m *notificationModule) Hook(ctx context.Context, t *model.Tenant, name string, payload map[string]any) error {
	// The endpoints and their secrets are read in a short transaction.
	// The calls themselves happen outside any transaction.
	type target struct {
		endpoint model.WebhookEndpoint
		secret   []byte
	}
	var targets []target
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		endpoints, err := m.repo.ListWebhookEndpoints(ctx, tx, t.ID, constant.WebhookKindBeforeHook)
		if err != nil {
			return err
		}
		for _, e := range endpoints {
			if !wants(e.EventTypes, name) {
				continue
			}
			key, err := m.keys.DataKeyByID(ctx, tx, t.ID, e.DataKeyID)
			if err != nil {
				return err
			}
			s, err := secret.Open(key, e.SecretEncrypted, webhookContext(t.ID))
			if err != nil {
				return err
			}
			targets = append(targets, target{endpoint: e, secret: s})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("hook %s: %w", name, err)
	}

	body, err := json.Marshal(map[string]any{"hook": name, "tenant_id": t.ID, "data": payload})
	if err != nil {
		return err
	}
	for _, tg := range targets {
		status, answer, err := m.post(ctx, tg.endpoint.URL, time.Duration(tg.endpoint.TimeoutMs)*time.Millisecond,
			tg.secret, body, map[string]string{"X-AOS-Hook": name})
		// The rule when unsure is to refuse.
		if err != nil || status < 200 || status >= 300 {
			m.log.Warn(ctx, "before-hook did not answer, action refused", "hook", name, "url", tg.endpoint.URL, "status", status)
			return apperrors.New(apperrors.ErrorTypeForbidden, http.StatusForbidden, "hook_unavailable",
				"the application could not confirm this action. try again later")
		}
		var a hookAnswer
		if err := json.Unmarshal(answer, &a); err != nil || !a.Allow {
			msg := strings.TrimSpace(a.Message)
			if msg == "" {
				msg = "the application refused this action"
			}
			if len(msg) > 200 {
				msg = msg[:200]
			}
			return apperrors.New(apperrors.ErrorTypeForbidden, http.StatusForbidden, "refused_by_hook", msg)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------

func (m *notificationModule) CreateEndpoint(ctx context.Context, t *model.Tenant, req request.CreateWebhookRequest, meta model.RequestMeta) (*response.Webhook, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.checkURL(req.URL); err != nil {
		return nil, apperrors.Validation(map[string]string{"url": err.Error()})
	}
	signingSecret := secret.Token(32)

	var id string
	var createdAt time.Time
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		keyID, key, err := m.keys.DataKey(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		sealed, err := secret.Seal(key, []byte(signingSecret), webhookContext(t.ID))
		if err != nil {
			return err
		}
		id, err = m.repo.CreateWebhookEndpoint(ctx, tx, t.ID, model.WebhookEndpoint{
			Kind: req.Kind, URL: req.URL, Label: req.Label, EventTypes: req.EventTypes, TimeoutMs: req.TimeoutMs,
			SecretEncrypted: sealed, DataKeyID: keyID, OrganizationID: req.OrganizationID,
		})
		if err != nil {
			return err
		}
		createdAt = m.now()
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "webhook.created", Result: model.AuditSuccess, TargetType: "webhook", TargetID: id,
			Data: map[string]any{"kind": req.Kind, "url": req.URL}, RequestID: meta.RequestID,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}
	return &response.Webhook{
		ID: id, Kind: req.Kind, URL: req.URL, Label: req.Label, EventTypes: req.EventTypes,
		TimeoutMs: req.TimeoutMs, Secret: signingSecret, CreatedAt: createdAt,
	}, nil
}

func (m *notificationModule) ListEndpoints(ctx context.Context, t *model.Tenant) ([]response.Webhook, error) {
	var endpoints []model.WebhookEndpoint
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		endpoints, err = m.repo.ListWebhookEndpoints(ctx, tx, t.ID, "")
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	out := make([]response.Webhook, 0, len(endpoints))
	for _, e := range endpoints {
		out = append(out, response.Webhook{
			ID: e.ID, Kind: e.Kind, URL: e.URL, Label: e.Label, EventTypes: e.EventTypes, TimeoutMs: e.TimeoutMs,
			CreatedAt: e.CreatedAt, LastSuccessAt: e.LastSuccessAt, LastFailureAt: e.LastFailureAt, LastError: e.LastError,
		})
	}
	return out, nil
}

func (m *notificationModule) DeleteEndpoint(ctx context.Context, t *model.Tenant, id string, meta model.RequestMeta) error {
	if !postgres.IsUUID(id) {
		return apperrors.NotFound("webhook")
	}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		found, err := m.repo.DeleteWebhookEndpoint(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		if !found {
			return apperrors.NotFound("webhook")
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "webhook.deleted", Result: model.AuditSuccess, TargetType: "webhook", TargetID: id, RequestID: meta.RequestID,
		})
	})
	if _, ok := apperrors.AsAppError(err); ok {
		return err
	}
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// The HTTP call
// ---------------------------------------------------------------------

// post sends a signed JSON body and returns the status and the answer.
// The signature covers the time and the body, so a captured call cannot
// be replayed later or with another body.
func (m *notificationModule) post(ctx context.Context, rawURL string, timeout time.Duration, signingSecret, body []byte, headers map[string]string) (int, []byte, error) {
	if err := m.checkURL(rawURL); err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	ts := strconv.FormatInt(m.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aos-webhooks/1")
	req.Header.Set("X-AOS-Signature", "t="+ts+",v1="+Sign(signingSecret, ts, body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, answer, nil
}

// Sign computes the signature the receiver checks: HMAC-SHA256 over
// "<timestamp>.<body>", as hex.
func Sign(signingSecret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, signingSecret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// checkURL refuses addresses that would make the engine call into the
// network it runs on.
func (m *notificationModule) checkURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return errors.New("is not a valid address")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && m.allowPrivate) {
		return errors.New("must use https")
	}
	if m.allowPrivate {
		return nil
	}
	host := u.Hostname()
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil || len(addrs) == 0 {
		return errors.New("could not be resolved")
	}
	for _, a := range addrs {
		a = a.Unmap()
		if isInternal(a) {
			return errors.New("points at an internal address")
		}
	}
	return nil
}

func isInternal(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast()
}

// ---------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------

func (m *notificationModule) Wake() {
	select {
	case m.wake <- struct{}{}:
	default: // a wake-up is already waiting
	}
}

func (m *notificationModule) Run(ctx context.Context) {
	ticker := time.NewTicker(constant.MessagePollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		if _, err := m.DeliverDue(ctx); err != nil && ctx.Err() == nil {
			m.log.Error(ctx, "message delivery failed", "error", err.Error())
		}
		if _, err := m.DeliverWebhooks(ctx); err != nil && ctx.Err() == nil {
			m.log.Error(ctx, "webhook delivery failed", "error", err.Error())
		}
	}
}

// backoff grows from 30 seconds to about an hour.
func backoff(attempts int) time.Duration {
	d := 30 * time.Second << min(attempts, 7)
	return min(d, time.Hour)
}

func messageContext(tenantID string) []byte { return []byte("aos:message|" + tenantID) }
func webhookContext(tenantID string) []byte { return []byte("aos:webhook|" + tenantID) }

// ExportAudit sends new audit entries of each organization to its export
// endpoint (user-flow ENT-8), in order, signed, with the cursor moved
// only after the receiver answered 2xx.
func (m *notificationModule) ExportAudit(ctx context.Context) (int, error) {
	var endpoints []struct{ TenantID, EndpointID string }
	err := m.db.Resolver(ctx, func(tx pgx.Tx) (err error) {
		endpoints, err = m.repo.AuditExportEndpoints(ctx, tx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("audit export: %w", err)
	}
	sent := 0
	for _, e := range endpoints {
		n, err := m.exportOne(ctx, e.TenantID, e.EndpointID)
		if err != nil {
			m.log.Error(ctx, "audit export failed", "tenant_id", e.TenantID, "endpoint_id", e.EndpointID, "error", err.Error())
			continue
		}
		sent += n
	}
	return sent, nil
}

func (m *notificationModule) exportOne(ctx context.Context, tenantID, endpointID string) (int, error) {
	sent := 0
	err := m.db.Tenant(ctx, tenantID, func(tx pgx.Tx) error {
		e, err := m.repo.GetAuditEndpoint(ctx, tx, tenantID, endpointID)
		if err != nil || e == nil || e.OrganizationID == "" {
			return err
		}
		entries, err := m.audit.ListSince(ctx, tx, tenantID, e.OrganizationID, e.Cursor, constant.AuditExportBatch)
		if err != nil || len(entries) == 0 {
			return err
		}
		key, err := m.keys.DataKeyByID(ctx, tx, tenantID, e.DataKeyID)
		if err != nil {
			return err
		}
		signingSecret, err := secret.Open(key, e.SecretEncrypted, webhookContext(tenantID))
		if err != nil {
			return err
		}
		lines := make([]map[string]any, 0, len(entries))
		for _, a := range entries {
			lines = append(lines, map[string]any{
				"seq": a.Seq, "occurred_at": a.OccurredAt.UTC(), "organization_id": a.OrganizationID, "actor_id": a.ActorID,
				"action": a.Action, "target_type": a.TargetType, "target_id": a.TargetID, "result": a.Result, "reason_code": a.ReasonCode,
				"data": a.Data, "hash": hex.EncodeToString(a.Hash),
			})
		}
		body, err := json.Marshal(map[string]any{"organization_id": e.OrganizationID, "entries": lines})
		if err != nil {
			return err
		}
		timeout := time.Duration(e.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		status, _, err := m.post(ctx, e.URL, timeout, signingSecret, body, map[string]string{"X-AOS-Event": "audit.export"})
		now := m.now()
		if err != nil || status < 200 || status >= 300 {
			problem := fmt.Sprintf("answered %d", status)
			if err != nil {
				problem = err.Error()
			}
			return m.repo.RecordEndpointResult(ctx, tx, tenantID, e.ID, false, problem, now)
		}
		if err := m.repo.RecordEndpointResult(ctx, tx, tenantID, e.ID, true, "", now); err != nil {
			return err
		}
		sent = len(entries)
		return m.repo.SetAuditCursor(ctx, tx, tenantID, e.ID, entries[len(entries)-1].Seq)
	})
	return sent, err
}
