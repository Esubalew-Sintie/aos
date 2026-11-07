// Package machine stores service accounts, agents, API keys, delegations
// and approvals.
package machine

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

type machineRepository struct {
	log logger.Logger
}

func NewMachineRepository(log logger.Logger) storage.MachineRepository {
	return &machineRepository{log: log}
}

// ---------------------------------------------------------------------
// Service accounts and agents
// ---------------------------------------------------------------------

func (r *machineRepository) CreateMachine(ctx context.Context, tx pgx.Tx, tenantID, kind, name, purpose, ownerID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.principals (tenant_id, kind, display_name, purpose, owner_principal_id)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5) RETURNING id::text`,
		tenantID, kind, name, purpose, postgres.NullString(ownerID)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", kind, err)
	}
	return id, nil
}

const machineColumns = `id::text, kind, COALESCE(display_name, ''), COALESCE(purpose, ''), COALESCE(owner_principal_id::text, ''), status, created_at, suspended_at`

func scanMachine(row pgx.CollectableRow) (model.Machine, error) {
	var m model.Machine
	err := row.Scan(&m.ID, &m.Kind, &m.Name, &m.Purpose, &m.OwnerID, &m.Status, &m.CreatedAt, &m.SuspendedAt)
	return m, err
}

func (r *machineRepository) GetMachine(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Machine, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+machineColumns+` FROM aos.principals WHERE tenant_id = $1 AND id = $2 AND kind IN ('service', 'agent')`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("get machine: %w", err)
	}
	m, err := pgx.CollectOneRow(rows, scanMachine)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get machine: %w", err)
	}
	return &m, nil
}

func (r *machineRepository) ListMachines(ctx context.Context, tx pgx.Tx, tenantID, kind string) ([]model.Machine, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+machineColumns+` FROM aos.principals
		WHERE tenant_id = $1 AND kind = $2 AND status <> 'deleted' ORDER BY created_at`, tenantID, kind)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanMachine)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	return out, nil
}

func (r *machineRepository) SetMachineStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status, reason string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.principals SET status = $3, status_reason = NULLIF($4, ''),
		       suspended_at = CASE WHEN $3 = 'suspended' THEN $5::timestamptz ELSE NULL END
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, status, reason, at); err != nil {
		return fmt.Errorf("set machine status: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------

const keyColumns = `id::text, principal_id::text, name, public_id, secret_hash, scopes, expires_at, revoked_at, last_used_at, COALESCE(created_by::text, ''), created_at`

func scanKey(row pgx.CollectableRow) (model.APIKey, error) {
	var k model.APIKey
	err := row.Scan(&k.ID, &k.PrincipalID, &k.Name, &k.PublicID, &k.SecretHash, &k.Scopes, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt, &k.CreatedBy, &k.CreatedAt)
	return k, err
}

func (r *machineRepository) CreateAPIKey(ctx context.Context, tx pgx.Tx, tenantID string, k model.APIKey) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.api_keys (tenant_id, principal_id, name, public_id, secret_hash, scopes, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text`,
		tenantID, k.PrincipalID, k.Name, k.PublicID, k.SecretHash, k.Scopes, k.ExpiresAt, postgres.NullString(k.CreatedBy)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create api key: %w", err)
	}
	return id, nil
}

func (r *machineRepository) FindAPIKeyByPublicID(ctx context.Context, tx pgx.Tx, tenantID, publicID string) (*model.APIKey, error) {
	rows, err := tx.Query(ctx, `SELECT `+keyColumns+` FROM aos.api_keys WHERE tenant_id = $1 AND public_id = $2`, tenantID, publicID)
	if err != nil {
		return nil, fmt.Errorf("find api key: %w", err)
	}
	k, err := pgx.CollectOneRow(rows, scanKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find api key: %w", err)
	}
	return &k, nil
}

func (r *machineRepository) ListAPIKeys(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.APIKey, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+keyColumns+` FROM aos.api_keys
		WHERE tenant_id = $1 AND ($2 = '' OR principal_id = $2::uuid) ORDER BY created_at`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanKey)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	return out, nil
}

func (r *machineRepository) RevokeAPIKey(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) (string, error) {
	if !postgres.IsUUID(id) {
		return "", nil
	}
	var principalID string
	err := tx.QueryRow(ctx, `
		UPDATE aos.api_keys SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL RETURNING principal_id::text`,
		tenantID, id, at).Scan(&principalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("revoke api key: %w", err)
	}
	return principalID, nil
}

func (r *machineRepository) RevokeAPIKeysOf(ctx context.Context, tx pgx.Tx, tenantID, principalID string, at time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE aos.api_keys SET revoked_at = $3 WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL`, tenantID, principalID, at)
	if err != nil {
		return 0, fmt.Errorf("revoke api keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *machineRepository) TouchAPIKey(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.api_keys SET last_used_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("touch api key: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Delegations
// ---------------------------------------------------------------------

const delegationColumns = `id::text, agent_principal_id::text, user_principal_id::text, scopes, resource_id::text, expires_at, revoked_at, created_at`

func scanDelegation(row pgx.CollectableRow) (model.Delegation, error) {
	var d model.Delegation
	err := row.Scan(&d.ID, &d.AgentID, &d.UserID, &d.Scopes, &d.ResourceID, &d.ExpiresAt, &d.RevokedAt, &d.CreatedAt)
	return d, err
}

func (r *machineRepository) CreateDelegation(ctx context.Context, tx pgx.Tx, tenantID string, d model.Delegation) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.delegations (tenant_id, agent_principal_id, user_principal_id, scopes, resource_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
		tenantID, d.AgentID, d.UserID, d.Scopes, d.ResourceID, d.ExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create delegation: %w", err)
	}
	return id, nil
}

func (r *machineRepository) LiveDelegations(ctx context.Context, tx pgx.Tx, tenantID, agentID, userID, resourceID string, now time.Time) ([]model.Delegation, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+delegationColumns+` FROM aos.delegations d
		WHERE d.tenant_id = $1 AND d.agent_principal_id = $2 AND d.user_principal_id = $3
		  AND d.revoked_at IS NULL AND d.expires_at > $5
		  AND d.resource_id IN (SELECT ancestor_id FROM aos.resource_ancestors a WHERE a.tenant_id = $1 AND a.resource_id = $4)
		ORDER BY d.created_at`, tenantID, agentID, userID, resourceID, now)
	if err != nil {
		return nil, fmt.Errorf("live delegations: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanDelegation)
	if err != nil {
		return nil, fmt.Errorf("live delegations: %w", err)
	}
	return out, nil
}

func (r *machineRepository) ListDelegations(ctx context.Context, tx pgx.Tx, tenantID, userID, agentID string) ([]model.Delegation, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+delegationColumns+` FROM aos.delegations
		WHERE tenant_id = $1 AND ($2 = '' OR user_principal_id = $2::uuid) AND ($3 = '' OR agent_principal_id = $3::uuid)
		ORDER BY created_at`, tenantID, userID, agentID)
	if err != nil {
		return nil, fmt.Errorf("list delegations: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanDelegation)
	if err != nil {
		return nil, fmt.Errorf("list delegations: %w", err)
	}
	return out, nil
}

func (r *machineRepository) RevokeDelegation(ctx context.Context, tx pgx.Tx, tenantID, id, userID string, at time.Time) (bool, error) {
	if !postgres.IsUUID(id) {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `
		UPDATE aos.delegations SET revoked_at = $4
		WHERE tenant_id = $1 AND id = $2 AND ($3 = '' OR user_principal_id = $3::uuid) AND revoked_at IS NULL`, tenantID, id, userID, at)
	if err != nil {
		return false, fmt.Errorf("revoke delegation: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *machineRepository) RevokeDelegationsOf(ctx context.Context, tx pgx.Tx, tenantID, agentID string, at time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE aos.delegations SET revoked_at = $3 WHERE tenant_id = $1 AND agent_principal_id = $2 AND revoked_at IS NULL`, tenantID, agentID, at)
	if err != nil {
		return 0, fmt.Errorf("revoke delegations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------

const approvalColumns = `id::text, agent_principal_id::text, user_principal_id::text, permission, resource_id::text, action_digest, details, status, expires_at, decided_at, used_at, created_at`

func scanApproval(row pgx.CollectableRow) (model.Approval, error) {
	var a model.Approval
	var details []byte
	if err := row.Scan(&a.ID, &a.AgentID, &a.UserID, &a.Permission, &a.ResourceID, &a.Digest, &details, &a.Status, &a.ExpiresAt, &a.DecidedAt, &a.UsedAt, &a.CreatedAt); err != nil {
		return a, err
	}
	return a, json.Unmarshal(details, &a.Details)
}

func (r *machineRepository) CreateApproval(ctx context.Context, tx pgx.Tx, tenantID string, a model.Approval) (string, error) {
	if a.Details == nil {
		a.Details = map[string]any{}
	}
	details, err := json.Marshal(a.Details)
	if err != nil {
		return "", fmt.Errorf("create approval: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.approvals (tenant_id, agent_principal_id, user_principal_id, permission, resource_id, action_digest, details, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text`,
		tenantID, a.AgentID, a.UserID, a.Permission, a.ResourceID, a.Digest, details, a.ExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create approval: %w", err)
	}
	return id, nil
}

func (r *machineRepository) FindPendingApproval(ctx context.Context, tx pgx.Tx, tenantID, agentID string, digest []byte, now time.Time) (*model.Approval, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+approvalColumns+` FROM aos.approvals
		WHERE tenant_id = $1 AND agent_principal_id = $2 AND action_digest = $3 AND status IN ('pending', 'approved') AND expires_at > $4
		ORDER BY created_at DESC LIMIT 1`, tenantID, agentID, digest, now)
	if err != nil {
		return nil, fmt.Errorf("find approval: %w", err)
	}
	a, err := pgx.CollectOneRow(rows, scanApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find approval: %w", err)
	}
	return &a, nil
}

func (r *machineRepository) LockApproval(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Approval, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+approvalColumns+` FROM aos.approvals WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("lock approval: %w", err)
	}
	a, err := pgx.CollectOneRow(rows, scanApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock approval: %w", err)
	}
	return &a, nil
}

func (r *machineRepository) ListApprovals(ctx context.Context, tx pgx.Tx, tenantID, userID string, now time.Time) ([]model.Approval, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+approvalColumns+` FROM aos.approvals
		WHERE tenant_id = $1 AND user_principal_id = $2 AND status = 'pending' AND expires_at > $3 ORDER BY created_at`, tenantID, userID, now)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanApproval)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	return out, nil
}

func (r *machineRepository) SetApprovalStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.approvals SET status = $3, decided_at = $4 WHERE tenant_id = $1 AND id = $2`, tenantID, id, status, at); err != nil {
		return fmt.Errorf("set approval status: %w", err)
	}
	return nil
}

func (r *machineRepository) MarkApprovalUsed(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.approvals SET status = 'used', used_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("mark approval used: %w", err)
	}
	return nil
}

func (r *machineRepository) RevokeTokenFamiliesOfPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID, reason string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.token_families SET revoked_at = $3, revoked_reason = $4
		WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL`, tenantID, principalID, at, reason); err != nil {
		return fmt.Errorf("revoke token families: %w", err)
	}
	return nil
}

func (r *machineRepository) DeleteGrantsOf(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM aos.grants WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID)
	if err != nil {
		return 0, fmt.Errorf("delete grants: %w", err)
	}
	return tag.RowsAffected(), nil
}
