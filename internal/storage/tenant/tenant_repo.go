// Package tenant is the SQL for tenants, their keys and their settings.
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
)

type tenantRepository struct {
	log logger.Logger
}

func NewTenantRepository(log logger.Logger) storage.TenantRepository {
	return &tenantRepository{log: log}
}

func (r *tenantRepository) ResolveKey(ctx context.Context, tx pgx.Tx, publicID string) (*model.ResolvedKey, error) {
	var k model.ResolvedKey
	err := tx.QueryRow(ctx,
		`SELECT tenant_id::text, key_id::text, kind, secret_hash, tenant_status FROM aos.resolve_tenant_key($1)`,
		publicID).Scan(&k.TenantID, &k.KeyID, &k.Kind, &k.SecretHash, &k.TenantStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolve key: %w", err)
	}
	return &k, nil
}

func (r *tenantRepository) ResolveSlug(ctx context.Context, tx pgx.Tx, slug string) (string, string, error) {
	var id, status string
	err := tx.QueryRow(ctx, `SELECT tenant_id::text, tenant_status FROM aos.resolve_tenant_slug($1)`, slug).Scan(&id, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("resolve slug: %w", err)
	}
	return id, status, nil
}

func (r *tenantRepository) GetTenant(ctx context.Context, tx pgx.Tx, tenantID string) (*model.Tenant, error) {
	var (
		t                 model.Tenant
		idleSec, absSec   int
		rawSettings       []byte
		defaultRole, root *string
	)
	err := tx.QueryRow(ctx, `
		SELECT id::text, slug, name, kind, environment, status, signup_policy, signup_domains, org_creation_policy, mfa_policy,
		       default_role_id::text, session_idle_seconds, session_absolute_seconds,
		       root_resource_id::text, settings
		FROM aos.tenants WHERE id = $1`, tenantID).Scan(
		&t.ID, &t.Slug, &t.Name, &t.Kind, &t.Environment, &t.Status, &t.SignupPolicy, &t.SignupDomains, &t.OrgCreationPolicy, &t.MFAPolicy,
		&defaultRole, &idleSec, &absSec, &root, &rawSettings)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	t.SessionIdle = time.Duration(idleSec) * time.Second
	t.SessionAbsolute = time.Duration(absSec) * time.Second
	if defaultRole != nil {
		t.DefaultRoleID = *defaultRole
	}
	if root != nil {
		t.RootResourceID = *root
	}
	var settings struct {
		AppURL string `json:"app_url"`
	}
	if err := json.Unmarshal(rawSettings, &settings); err != nil {
		return nil, fmt.Errorf("get tenant: read settings: %w", err)
	}
	t.AppURL = settings.AppURL
	return &t, nil
}

func (r *tenantRepository) IsAllowedOrigin(ctx context.Context, tx pgx.Tx, tenantID, origin string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM aos.allowed_origins WHERE tenant_id = $1 AND origin = $2)`,
		tenantID, origin).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check origin: %w", err)
	}
	return ok, nil
}

func (r *tenantRepository) CreateTenant(ctx context.Context, tx pgx.Tx, t model.NewTenant) (string, error) {
	settings, err := json.Marshal(t.Settings)
	if err != nil {
		return "", fmt.Errorf("create tenant: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.tenants (slug, name, kind, environment, settings)
		VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
		t.Slug, t.Name, t.Kind, t.Environment, settings).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create tenant: %w", err)
	}
	return id, nil
}

func (r *tenantRepository) CreateResourceType(ctx context.Context, tx pgx.Tx, tenantID, name, source string) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO aos.resource_types (tenant_id, name, source) VALUES ($1, $2, $3)`,
		tenantID, name, source); err != nil {
		return fmt.Errorf("create resource type: %w", err)
	}
	return nil
}

func (r *tenantRepository) CreateRootResource(ctx context.Context, tx pgx.Tx, tenantID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.resources (tenant_id, type, external_id)
		VALUES ($1, $2, $3) RETURNING id::text`,
		tenantID, constant.ResourceTypeTenant, constant.RootExternalID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create root resource: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE aos.tenants SET root_resource_id = $2 WHERE id = $1`, tenantID, id); err != nil {
		return "", fmt.Errorf("record root resource: %w", err)
	}
	return id, nil
}

func (r *tenantRepository) CreateOwnerRole(ctx context.Context, tx pgx.Tx, tenantID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.roles (tenant_id, name, description, source)
		VALUES ($1, $2, 'Holds every permission.', $3) RETURNING id::text`,
		tenantID, constant.RoleOwner, constant.SourceSystem).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create owner role: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO aos.role_permissions (tenant_id, role_id, pattern) VALUES ($1, $2, '*')`,
		tenantID, id); err != nil {
		return "", fmt.Errorf("create owner role: %w", err)
	}
	return id, nil
}

func (r *tenantRepository) CreateDataKey(ctx context.Context, tx pgx.Tx, tenantID string, wrapped []byte, masterKeyRef string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.data_keys (tenant_id, wrapped_key, master_key_ref)
		VALUES ($1, $2, $3) RETURNING id::text`, tenantID, wrapped, masterKeyRef).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create data key: %w", err)
	}
	return id, nil
}

func (r *tenantRepository) CreateSigningKey(ctx context.Context, tx pgx.Tx, tenantID string, key model.SigningKey) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.signing_keys (tenant_id, kid, public_key, private_key_encrypted, data_key_id, status, activated_at)
		VALUES ($1, $2, $3, $4, $5, 'active', now())`,
		tenantID, key.KID, key.Public, key.PrivateEncrypted, key.DataKeyID); err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}
	return nil
}

func (r *tenantRepository) CreateTenantKey(ctx context.Context, tx pgx.Tx, tenantID, kind, publicID string, secretHash []byte) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.tenant_keys (tenant_id, kind, public_id, secret_hash)
		VALUES ($1, $2, $3, $4)`, tenantID, kind, publicID, secretHash); err != nil {
		return fmt.Errorf("create tenant key: %w", err)
	}
	return nil
}

func (r *tenantRepository) AddAllowedOrigin(ctx context.Context, tx pgx.Tx, tenantID, origin string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.allowed_origins (tenant_id, origin) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, tenantID, origin); err != nil {
		return fmt.Errorf("add allowed origin: %w", err)
	}
	return nil
}

func (r *tenantRepository) GetActiveDataKey(ctx context.Context, tx pgx.Tx, tenantID string) (*model.DataKey, error) {
	var k model.DataKey
	err := tx.QueryRow(ctx, `
		SELECT id::text, wrapped_key FROM aos.data_keys
		WHERE tenant_id = $1 AND status = 'active'
		ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&k.ID, &k.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("get active data key: %w", err)
	}
	return &k, nil
}

func (r *tenantRepository) GetDataKey(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.DataKey, error) {
	var k model.DataKey
	err := tx.QueryRow(ctx,
		`SELECT id::text, wrapped_key FROM aos.data_keys WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&k.ID, &k.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("get data key: %w", err)
	}
	return &k, nil
}

func (r *tenantRepository) GetActiveSigningKey(ctx context.Context, tx pgx.Tx, tenantID string) (*model.SigningKey, error) {
	var k model.SigningKey
	err := tx.QueryRow(ctx, `
		SELECT kid, public_key, private_key_encrypted, data_key_id::text FROM aos.signing_keys
		WHERE tenant_id = $1 AND status = 'active'
		ORDER BY activated_at DESC LIMIT 1`, tenantID).Scan(&k.KID, &k.Public, &k.PrivateEncrypted, &k.DataKeyID)
	if err != nil {
		return nil, fmt.Errorf("get active signing key: %w", err)
	}
	return &k, nil
}

func (r *tenantRepository) ListSigningKeys(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.SigningKey, error) {
	rows, err := tx.Query(ctx, `
		SELECT kid, public_key FROM aos.signing_keys
		WHERE tenant_id = $1 AND status IN ('next', 'active', 'retiring')
		ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.SigningKey, error) {
		var k model.SigningKey
		err := row.Scan(&k.KID, &k.Public)
		return k, err
	})
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	return keys, nil
}

func (r *tenantRepository) CreateSystemPermissions(ctx context.Context, tx pgx.Tx, tenantID string, permissions map[string]string) error {
	for name, description := range permissions {
		if _, err := tx.Exec(ctx, `
			INSERT INTO aos.permissions (tenant_id, name, description, source) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, name) DO NOTHING`, tenantID, name, description, constant.SourceSystem); err != nil {
			return fmt.Errorf("create system permissions: %w", err)
		}
	}
	return nil
}

func (r *tenantRepository) ListTenantKeys(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.TenantKey, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, kind, public_id, created_at, last_used_at, revoked_at
		FROM aos.tenant_keys WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.TenantKey, error) {
		var k model.TenantKey
		err := row.Scan(&k.ID, &k.Kind, &k.PublicID, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
		return k, err
	})
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	return keys, nil
}

func (r *tenantRepository) RevokeTenantKey(ctx context.Context, tx pgx.Tx, tenantID, keyID string, at time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE aos.tenant_keys SET revoked_at = $3
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, tenantID, keyID, at)
	if err != nil {
		return false, fmt.Errorf("revoke key: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *tenantRepository) ListAllowedOrigins(ctx context.Context, tx pgx.Tx, tenantID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT origin FROM aos.allowed_origins WHERE tenant_id = $1 ORDER BY origin`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list origins: %w", err)
	}
	origins, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("list origins: %w", err)
	}
	return origins, nil
}

func (r *tenantRepository) RemoveAllowedOrigin(ctx context.Context, tx pgx.Tx, tenantID, origin string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.allowed_origins WHERE tenant_id = $1 AND origin = $2`, tenantID, origin); err != nil {
		return fmt.Errorf("remove origin: %w", err)
	}
	return nil
}

func (r *tenantRepository) UpdateTenantSettings(ctx context.Context, tx pgx.Tx, tenantID string, s model.TenantSettings) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.tenants SET
			name = $2, signup_policy = $3, signup_domains = $4, org_creation_policy = $5,
			default_role_id = $6, session_idle_seconds = $7, session_absolute_seconds = $8,
			settings = settings || jsonb_build_object('app_url', $9::text)
		WHERE id = $1`,
		tenantID, s.Name, s.SignupPolicy, s.SignupDomains, s.OrgCreationPolicy, postgres.NullString(s.DefaultRoleID),
		int(s.SessionIdle.Seconds()), int(s.SessionAbsolute.Seconds()), s.AppURL); err != nil {
		return fmt.Errorf("update tenant settings: %w", err)
	}
	return nil
}

func (r *tenantRepository) SetTenantStatus(ctx context.Context, tx pgx.Tx, tenantID, status string) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.tenants SET status = $2 WHERE id = $1`, tenantID, status); err != nil {
		return fmt.Errorf("set tenant status: %w", err)
	}
	return nil
}
