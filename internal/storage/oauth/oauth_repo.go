// Package oauth stores what the tenant keeps as an OAuth and OpenID
// Connect provider: clients, codes, consents, device codes.
package oauth

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

type oauthRepository struct {
	log logger.Logger
}

func NewOAuthRepository(log logger.Logger) storage.OAuthRepository {
	return &oauthRepository{log: log}
}

const clientColumns = `id::text, client_id, name, COALESCE(description, ''), kind, secret_hash, COALESCE(metadata_url, ''), redirect_uris, allowed_scopes, grant_types,
	COALESCE(service_principal_id::text, ''), created_at, disabled_at`

func scanClient(row pgx.CollectableRow) (model.OAuthClient, error) {
	var c model.OAuthClient
	err := row.Scan(&c.ID, &c.ClientID, &c.Name, &c.Description, &c.Kind, &c.SecretHash, &c.MetadataURL, &c.RedirectURIs, &c.AllowedScopes, &c.GrantTypes,
		&c.ServicePrincipalID, &c.CreatedAt, &c.DisabledAt)
	return c, err
}

func (r *oauthRepository) UpsertClient(ctx context.Context, tx pgx.Tx, tenantID string, c model.OAuthClient) (string, error) {
	for _, p := range []*[]string{&c.RedirectURIs, &c.AllowedScopes, &c.GrantTypes} {
		if *p == nil {
			*p = []string{}
		}
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.oauth_clients (tenant_id, client_id, name, description, kind, secret_hash, metadata_url, redirect_uris, allowed_scopes, grant_types, service_principal_id)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), $8, $9, $10, $11)
		ON CONFLICT (tenant_id, client_id) DO UPDATE SET
			name = EXCLUDED.name, description = EXCLUDED.description, kind = EXCLUDED.kind,
			secret_hash = COALESCE(EXCLUDED.secret_hash, aos.oauth_clients.secret_hash), metadata_url = EXCLUDED.metadata_url,
			redirect_uris = EXCLUDED.redirect_uris, allowed_scopes = EXCLUDED.allowed_scopes, grant_types = EXCLUDED.grant_types,
			service_principal_id = EXCLUDED.service_principal_id, disabled_at = NULL
		RETURNING id::text`,
		tenantID, c.ClientID, c.Name, c.Description, c.Kind, c.SecretHash, c.MetadataURL, c.RedirectURIs, c.AllowedScopes, c.GrantTypes,
		postgres.NullString(c.ServicePrincipalID)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert client: %w", err)
	}
	return id, nil
}

func (r *oauthRepository) one(ctx context.Context, tx pgx.Tx, query string, args ...any) (*model.OAuthClient, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, scanClient)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	return &c, nil
}

func (r *oauthRepository) GetClient(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.OAuthClient, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	return r.one(ctx, tx, `SELECT `+clientColumns+` FROM aos.oauth_clients WHERE tenant_id = $1 AND id = $2`, tenantID, id)
}

func (r *oauthRepository) GetClientByClientID(ctx context.Context, tx pgx.Tx, tenantID, clientID string) (*model.OAuthClient, error) {
	return r.one(ctx, tx, `SELECT `+clientColumns+` FROM aos.oauth_clients WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID)
}

func (r *oauthRepository) ListClients(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.OAuthClient, error) {
	rows, err := tx.Query(ctx, `SELECT `+clientColumns+` FROM aos.oauth_clients WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanClient)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	return out, nil
}

func (r *oauthRepository) DisableClient(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) (bool, error) {
	if !postgres.IsUUID(id) {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE aos.oauth_clients SET disabled_at = $3 WHERE tenant_id = $1 AND id = $2 AND disabled_at IS NULL`, tenantID, id, at)
	if err != nil {
		return false, fmt.Errorf("disable client: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---- codes ----

func (r *oauthRepository) CreateCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte, c model.AuthorizationCode) (string, error) {
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.oauth_authorization_codes (tenant_id, code_hash, client_id, principal_id, redirect_uri, scopes, code_challenge, resource, nonce, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10) RETURNING id::text`,
		tenantID, hash, c.ClientID, c.PrincipalID, c.RedirectURI, c.Scopes, c.CodeChallenge, c.Resource, c.Nonce, c.ExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create code: %w", err)
	}
	return id, nil
}

func (r *oauthRepository) LockCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte) (*model.AuthorizationCode, error) {
	var c model.AuthorizationCode
	err := tx.QueryRow(ctx, `
		SELECT id::text, client_id::text, principal_id::text, redirect_uri, scopes, code_challenge, COALESCE(resource, ''), COALESCE(nonce, ''), expires_at, used_at
		FROM aos.oauth_authorization_codes WHERE tenant_id = $1 AND code_hash = $2 FOR UPDATE`, tenantID, hash).Scan(
		&c.ID, &c.ClientID, &c.PrincipalID, &c.RedirectURI, &c.Scopes, &c.CodeChallenge, &c.Resource, &c.Nonce, &c.ExpiresAt, &c.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock code: %w", err)
	}
	return &c, nil
}

func (r *oauthRepository) MarkCodeUsed(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.oauth_authorization_codes SET used_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("mark code used: %w", err)
	}
	return nil
}

// ---- consents ----

func (r *oauthRepository) UpsertConsent(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string, scopes []string, at time.Time) error {
	if scopes == nil {
		scopes = []string{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.oauth_consents (tenant_id, principal_id, client_id, scopes, granted_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (principal_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = EXCLUDED.granted_at, revoked_at = NULL`,
		tenantID, principalID, clientID, scopes, at); err != nil {
		return fmt.Errorf("upsert consent: %w", err)
	}
	return nil
}

const consentColumns = `c.client_id::text, cl.name, cl.client_id, c.scopes, c.granted_at, c.revoked_at`

func scanConsent(row pgx.CollectableRow) (model.Consent, error) {
	var c model.Consent
	err := row.Scan(&c.ClientID, &c.ClientName, &c.ClientKey, &c.Scopes, &c.GrantedAt, &c.RevokedAt)
	return c, err
}

func (r *oauthRepository) GetConsent(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string) (*model.Consent, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+consentColumns+` FROM aos.oauth_consents c JOIN aos.oauth_clients cl ON cl.tenant_id = c.tenant_id AND cl.id = c.client_id
		WHERE c.tenant_id = $1 AND c.principal_id = $2 AND c.client_id = $3 AND c.revoked_at IS NULL`, tenantID, principalID, clientID)
	if err != nil {
		return nil, fmt.Errorf("get consent: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, scanConsent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get consent: %w", err)
	}
	return &c, nil
}

func (r *oauthRepository) ListConsents(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.Consent, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+consentColumns+` FROM aos.oauth_consents c JOIN aos.oauth_clients cl ON cl.tenant_id = c.tenant_id AND cl.id = c.client_id
		WHERE c.tenant_id = $1 AND c.principal_id = $2 AND c.revoked_at IS NULL ORDER BY c.granted_at`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanConsent)
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	return out, nil
}

func (r *oauthRepository) RevokeConsent(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string, at time.Time) (bool, error) {
	if !postgres.IsUUID(clientID) {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE aos.oauth_consents SET revoked_at = $4 WHERE tenant_id = $1 AND principal_id = $2 AND client_id = $3 AND revoked_at IS NULL`,
		tenantID, principalID, clientID, at)
	if err != nil {
		return false, fmt.Errorf("revoke consent: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---- device codes ----

const deviceColumns = `id::text, client_id::text, user_code, COALESCE(principal_id::text, ''), scopes, status, expires_at, last_polled_at`

func scanDevice(row pgx.CollectableRow) (model.DeviceCode, error) {
	var d model.DeviceCode
	err := row.Scan(&d.ID, &d.ClientID, &d.UserCode, &d.PrincipalID, &d.Scopes, &d.Status, &d.ExpiresAt, &d.LastPolledAt)
	return d, err
}

func (r *oauthRepository) CreateDeviceCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte, d model.DeviceCode) (string, error) {
	if d.Scopes == nil {
		d.Scopes = []string{}
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.device_codes (tenant_id, client_id, device_code_hash, user_code, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`, tenantID, d.ClientID, hash, d.UserCode, d.Scopes, d.ExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create device code: %w", err)
	}
	return id, nil
}

func (r *oauthRepository) lockDevice(ctx context.Context, tx pgx.Tx, query string, args ...any) (*model.DeviceCode, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("lock device code: %w", err)
	}
	d, err := pgx.CollectOneRow(rows, scanDevice)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock device code: %w", err)
	}
	return &d, nil
}

func (r *oauthRepository) LockDeviceCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte) (*model.DeviceCode, error) {
	return r.lockDevice(ctx, tx, `SELECT `+deviceColumns+` FROM aos.device_codes WHERE tenant_id = $1 AND device_code_hash = $2 FOR UPDATE`, tenantID, hash)
}

func (r *oauthRepository) LockDeviceCodeByUserCode(ctx context.Context, tx pgx.Tx, tenantID, userCode string) (*model.DeviceCode, error) {
	return r.lockDevice(ctx, tx, `SELECT `+deviceColumns+` FROM aos.device_codes WHERE tenant_id = $1 AND user_code = $2 FOR UPDATE`, tenantID, userCode)
}

func (r *oauthRepository) DecideDeviceCode(ctx context.Context, tx pgx.Tx, tenantID, id, principalID, status string) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.device_codes SET status = $3, principal_id = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, status, postgres.NullString(principalID)); err != nil {
		return fmt.Errorf("decide device code: %w", err)
	}
	return nil
}

func (r *oauthRepository) TouchDeviceCode(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.device_codes SET last_polled_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("touch device code: %w", err)
	}
	return nil
}

func (r *oauthRepository) SetDeviceCodeStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.device_codes SET status = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, status); err != nil {
		return fmt.Errorf("set device code status: %w", err)
	}
	return nil
}

// ---- token families held by clients ----

func (r *oauthRepository) CreateClientTokenFamily(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string, scopes []string, audience string) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.token_families (tenant_id, principal_id, client_id, scopes, audience)
		VALUES ($1, $2, $3, $4, NULLIF($5, '')) RETURNING id::text`, tenantID, principalID, clientID, scopes, audience).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create client token family: %w", err)
	}
	return id, nil
}

func (r *oauthRepository) RevokeClientTokenFamilies(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID, reason string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.token_families SET revoked_at = $4, revoked_reason = $5
		WHERE tenant_id = $1 AND principal_id = $2 AND client_id = $3 AND revoked_at IS NULL`, tenantID, principalID, clientID, at, reason); err != nil {
		return fmt.Errorf("revoke client token families: %w", err)
	}
	return nil
}

func (r *oauthRepository) PublishableKey(ctx context.Context, tx pgx.Tx, tenantID string) (string, error) {
	var key string
	err := tx.QueryRow(ctx, `
		SELECT public_id FROM aos.tenant_keys WHERE tenant_id = $1 AND kind = 'publishable' AND revoked_at IS NULL
		ORDER BY created_at LIMIT 1`, tenantID).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return key, err
}
