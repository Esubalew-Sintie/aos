// Package auth is the SQL for accounts, credentials, tokens and sessions.
package auth

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

type authRepository struct {
	log logger.Logger
}

func NewAuthRepository(log logger.Logger) storage.AuthRepository {
	return &authRepository{log: log}
}

func (r *authRepository) FindUserByEmail(ctx context.Context, tx pgx.Tx, tenantID, email string) (*model.UserAuth, error) {
	var u model.UserAuth
	err := tx.QueryRow(ctx, `
		SELECT u.principal_id::text, p.kind, p.status, u.email_verified_at IS NOT NULL,
		       COALESCE((SELECT pw.hash FROM aos.passwords pw
		                 WHERE pw.tenant_id = u.tenant_id AND pw.principal_id = u.principal_id
		                   AND pw.status = 'active'), '')
		FROM aos.users u
		JOIN aos.principals p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
		WHERE u.tenant_id = $1 AND u.email = $2`,
		tenantID, email).Scan(&u.PrincipalID, &u.Kind, &u.Status, &u.EmailVerified, &u.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return &u, nil
}

func (r *authRepository) GetUser(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (*model.User, error) {
	var u model.User
	err := tx.QueryRow(ctx, `
		SELECT u.principal_id::text, COALESCE(u.email::text, ''), COALESCE(u.name, ''), p.status,
		       u.email_verified_at IS NOT NULL, u.assurance_level, u.created_at
		FROM aos.users u
		JOIN aos.principals p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
		WHERE u.tenant_id = $1 AND u.principal_id = $2`,
		tenantID, principalID).Scan(&u.ID, &u.Email, &u.Name, &u.Status, &u.EmailVerified, &u.AssuranceLevel, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

func (r *authRepository) CreateUser(ctx context.Context, tx pgx.Tx, tenantID, email, name string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.principals (tenant_id, kind, display_name)
		VALUES ($1, 'user', NULLIF($2, '')) RETURNING id::text`, tenantID, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create principal: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.users (principal_id, tenant_id, email, name)
		VALUES ($1, $2, $3, NULLIF($4, ''))`, id, tenantID, email, name); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

func (r *authRepository) MarkEmailVerified(ctx context.Context, tx pgx.Tx, tenantID, principalID string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.users
		SET email_verified_at = COALESCE(email_verified_at, $3),
		    assurance_level = GREATEST(assurance_level, 1),
		    updated_at = $3
		WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID, at); err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}
	return nil
}

func (r *authRepository) CreateToken(ctx context.Context, tx pgx.Tx, tenantID string, t model.NewToken) (string, error) {
	payload := t.Payload
	if payload == nil {
		payload = map[string]string{}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.tokens (tenant_id, purpose, principal_id, target, token_hash, expires_at, payload, max_attempts)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, GREATEST($8, 1)) RETURNING id::text`,
		tenantID, t.Purpose, postgres.NullString(t.PrincipalID), t.Target, t.Hash, t.ExpiresAt, encoded, t.MaxAttempts).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}
	return id, nil
}

func (r *authRepository) LockToken(ctx context.Context, tx pgx.Tx, tenantID, purpose string, hash []byte) (*model.Token, error) {
	var t model.Token
	var payload []byte
	err := tx.QueryRow(ctx, `
		SELECT id::text, COALESCE(principal_id::text, ''), expires_at, used_at, payload
		FROM aos.tokens
		WHERE tenant_id = $1 AND purpose = $2 AND token_hash = $3
		FOR UPDATE`, tenantID, purpose, hash).Scan(&t.ID, &t.PrincipalID, &t.ExpiresAt, &t.UsedAt, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock token: %w", err)
	}
	if err := json.Unmarshal(payload, &t.Payload); err != nil {
		return nil, fmt.Errorf("lock token: read payload: %w", err)
	}
	return &t, nil
}

func (r *authRepository) MarkTokenUsed(ctx context.Context, tx pgx.Tx, tenantID, tokenID string, at time.Time) error {
	if _, err := tx.Exec(ctx,
		`UPDATE aos.tokens SET used_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, tokenID, at); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}
	return nil
}

func (r *authRepository) VoidTokens(ctx context.Context, tx pgx.Tx, tenantID, principalID, purpose string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.tokens SET used_at = $4
		WHERE tenant_id = $1 AND principal_id = $2 AND purpose = $3 AND used_at IS NULL`,
		tenantID, principalID, purpose, at); err != nil {
		return fmt.Errorf("void tokens: %w", err)
	}
	return nil
}

func (r *authRepository) AddPendingPassword(ctx context.Context, tx pgx.Tx, tenantID, principalID, hash, tokenID string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.passwords (tenant_id, principal_id, hash, status, token_id)
		VALUES ($1, $2, $3, 'pending', $4)`, tenantID, principalID, hash, tokenID); err != nil {
		return fmt.Errorf("add pending password: %w", err)
	}
	return nil
}

func (r *authRepository) ActivatePendingPassword(ctx context.Context, tx pgx.Tx, tenantID, principalID, tokenID string) error {
	// Every other password of this account goes first: an older active
	// one, and any pending one from another sign-up request.
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.passwords
		WHERE tenant_id = $1 AND principal_id = $2 AND token_id IS DISTINCT FROM $3`,
		tenantID, principalID, tokenID); err != nil {
		return fmt.Errorf("activate password: discard others: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE aos.passwords SET status = 'active', token_id = NULL
		WHERE tenant_id = $1 AND principal_id = $2 AND token_id = $3`,
		tenantID, principalID, tokenID)
	if err != nil {
		return fmt.Errorf("activate password: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("activate password: no pending password for this token")
	}
	return nil
}

func (r *authRepository) SetPassword(ctx context.Context, tx pgx.Tx, tenantID, principalID, hash string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM aos.passwords WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.passwords (tenant_id, principal_id, hash, status)
		VALUES ($1, $2, $3, 'active')`, tenantID, principalID, hash); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	return nil
}

func (r *authRepository) CreateSession(ctx context.Context, tx pgx.Tx, tenantID string, s model.NewSession) (string, error) {
	methods, err := json.Marshal(s.AuthMethods)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.sessions (
			tenant_id, principal_id, id_hash, kind, assurance_level, auth_methods, second_factor_at, device_id, ip, user_agent,
			created_at, last_seen_at, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, COALESCE(NULLIF($4, ''), 'browser'), $5, $6, $7, NULLIF($8, '')::uuid, NULLIF($9, '')::inet, NULLIF($10, ''), $11, $11, $12, $13)
		RETURNING id::text`,
		tenantID, s.PrincipalID, s.IDHash, s.Kind, s.AssuranceLevel, methods, s.SecondFactorAt, s.DeviceID, s.IP, s.UserAgent,
		s.Now, s.IdleExpiresAt, s.AbsoluteExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

func (r *authRepository) FindSession(ctx context.Context, tx pgx.Tx, tenantID string, idHash []byte) (*model.Session, error) {
	var s model.Session
	var methods []byte
	err := tx.QueryRow(ctx, `
		SELECT `+sessionColumns+`
		FROM aos.sessions s
		JOIN aos.principals p ON p.tenant_id = s.tenant_id AND p.id = s.principal_id
		LEFT JOIN aos.resources r ON r.tenant_id = s.tenant_id AND r.id = s.active_resource_id AND r.deleted_at IS NULL
		WHERE s.tenant_id = $1 AND s.id_hash = $2 AND s.revoked_at IS NULL`,
		tenantID, idHash).Scan(sessionDest(&s, &methods)...)
	return finishSession(&s, methods, err)
}

const sessionColumns = `s.id::text, s.principal_id::text, p.status, s.assurance_level,
		       s.last_seen_at, s.idle_expires_at, s.absolute_expires_at,
		       COALESCE(s.active_resource_id::text, ''), COALESCE(r.external_id, ''),
		       s.kind, s.auth_methods, s.second_factor_at, COALESCE(s.device_id::text, '')`

func sessionDest(s *model.Session, methods *[]byte) []any {
	return []any{&s.ID, &s.PrincipalID, &s.PrincipalStatus, &s.AssuranceLevel,
		&s.LastSeenAt, &s.IdleExpiresAt, &s.AbsoluteExpiresAt, &s.ActiveResourceID, &s.ActiveExternalID,
		&s.Kind, methods, &s.SecondFactorAt, &s.DeviceID}
}

func finishSession(s *model.Session, methods []byte, err error) (*model.Session, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}
	if err := json.Unmarshal(methods, &s.AuthMethods); err != nil {
		return nil, fmt.Errorf("find session: read methods: %w", err)
	}
	return s, nil
}

func (r *authRepository) TouchSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, lastSeen, idleExpires time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET last_seen_at = $3, idle_expires_at = LEAST($4, absolute_expires_at)
		WHERE tenant_id = $1 AND id = $2`, tenantID, sessionID, lastSeen, idleExpires); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (r *authRepository) RevokeSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID, reason string, at time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET revoked_at = $3, revoked_reason = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, tenantID, sessionID, at, reason)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *authRepository) RevokeAllSessions(ctx context.Context, tx pgx.Tx, tenantID, principalID, reason string, at time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET revoked_at = $3, revoked_reason = $4
		WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL`, tenantID, principalID, at, reason)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *authRepository) HitRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte, now time.Time, window time.Duration) (*model.RateLimit, error) {
	// One statement, so two requests at the same moment cannot both read
	// the old count. The counter starts again once its window has passed.
	var rl model.RateLimit
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.rate_limits AS r (tenant_id, bucket, key_hash, window_start, count)
		VALUES ($1, $2, $3, $4, 1)
		ON CONFLICT (tenant_id, bucket, key_hash) DO UPDATE SET
			count        = CASE WHEN r.window_start <= $5 THEN 1 ELSE r.count + 1 END,
			window_start = CASE WHEN r.window_start <= $5 THEN $4 ELSE r.window_start END,
			locked_until = CASE WHEN r.window_start <= $5 THEN NULL ELSE r.locked_until END
		RETURNING count, locked_until`,
		tenantID, bucket, keyHash, now, now.Add(-window)).Scan(&rl.Count, &rl.LockedUntil)
	if err != nil {
		return nil, fmt.Errorf("hit rate limit: %w", err)
	}
	return &rl, nil
}

func (r *authRepository) GetRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte) (*model.RateLimit, error) {
	var rl model.RateLimit
	err := tx.QueryRow(ctx, `
		SELECT count, locked_until FROM aos.rate_limits
		WHERE tenant_id = $1 AND bucket = $2 AND key_hash = $3`,
		tenantID, bucket, keyHash).Scan(&rl.Count, &rl.LockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return &rl, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get rate limit: %w", err)
	}
	return &rl, nil
}

func (r *authRepository) LockRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte, until time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.rate_limits SET locked_until = $4
		WHERE tenant_id = $1 AND bucket = $2 AND key_hash = $3`, tenantID, bucket, keyHash, until); err != nil {
		return fmt.Errorf("lock rate limit: %w", err)
	}
	return nil
}

func (r *authRepository) ResetRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte) error {
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.rate_limits
		WHERE tenant_id = $1 AND bucket = $2 AND key_hash = $3`, tenantID, bucket, keyHash); err != nil {
		return fmt.Errorf("reset rate limit: %w", err)
	}
	return nil
}

func (r *authRepository) GrantDefaultRole(ctx context.Context, tx pgx.Tx, tenantID, principalID, roleID, resourceID string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.grants (tenant_id, principal_id, role_id, resource_id, effect, source)
		SELECT $1, $2, $3, $4, 'allow', 'default_role'
		WHERE NOT EXISTS (
			SELECT 1 FROM aos.grants
			WHERE tenant_id = $1 AND principal_id = $2 AND role_id = $3 AND resource_id = $4)`,
		tenantID, principalID, roleID, resourceID); err != nil {
		return fmt.Errorf("grant default role: %w", err)
	}
	return nil
}

func (r *authRepository) ListSessions(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.SessionInfo, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, created_at, last_seen_at, absolute_expires_at,
		       COALESCE(host(ip), ''), COALESCE(user_agent, ''), auth_methods
		FROM aos.sessions
		WHERE tenant_id = $1 AND principal_id = $2 AND revoked_at IS NULL
		ORDER BY created_at DESC`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	sessions, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.SessionInfo, error) {
		var s model.SessionInfo
		var methods []byte
		if err := row.Scan(&s.ID, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.IP, &s.UserAgent, &methods); err != nil {
			return s, err
		}
		return s, json.Unmarshal(methods, &s.AuthMethods)
	})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

func (r *authRepository) FindSessionByID(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (*model.Session, error) {
	var s model.Session
	var methods []byte
	err := tx.QueryRow(ctx, `
		SELECT `+sessionColumns+`
		FROM aos.sessions s
		JOIN aos.principals p ON p.tenant_id = s.tenant_id AND p.id = s.principal_id
		LEFT JOIN aos.resources r ON r.tenant_id = s.tenant_id AND r.id = s.active_resource_id AND r.deleted_at IS NULL
		WHERE s.tenant_id = $1 AND s.id = $2 AND s.revoked_at IS NULL`,
		tenantID, sessionID).Scan(sessionDest(&s, &methods)...)
	return finishSession(&s, methods, err)
}

func (r *authRepository) UpdateEmail(ctx context.Context, tx pgx.Tx, tenantID, principalID, email string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.users SET email = $3, email_verified_at = $4, updated_at = $4
		WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID, email, at); err != nil {
		return fmt.Errorf("update email: %w", err)
	}
	return nil
}

func (r *authRepository) SetPrincipalStatus(ctx context.Context, tx pgx.Tx, tenantID, principalID, status, reason string, at time.Time) error {
	suspendedAt := any(nil)
	if status == "suspended" {
		suspendedAt = at
	}
	tag, err := tx.Exec(ctx, `
		UPDATE aos.principals SET status = $3, status_reason = NULLIF($4, ''), suspended_at = $5
		WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'`, tenantID, principalID, status, reason, suspendedAt)
	if err != nil {
		return fmt.Errorf("set principal status: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("set principal status: no such active principal")
	}
	return nil
}

func (r *authRepository) MarkPrincipalDeleted(ctx context.Context, tx pgx.Tx, tenantID, principalID string, at, purgeAfter time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.principals SET status = 'deleted', deleted_at = $3, purge_after = $4
		WHERE tenant_id = $1 AND id = $2`, tenantID, principalID, at, purgeAfter); err != nil {
		return fmt.Errorf("mark principal deleted: %w", err)
	}
	return nil
}

func (r *authRepository) ListUsers(ctx context.Context, tx pgx.Tx, tenantID string, afterCreated time.Time, afterID string, limit int) ([]model.User, error) {
	rows, err := tx.Query(ctx, `
		SELECT u.principal_id::text, COALESCE(u.email::text, ''), COALESCE(u.name, ''), p.status,
		       u.email_verified_at IS NOT NULL, u.assurance_level, u.created_at
		FROM aos.users u
		JOIN aos.principals p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
		WHERE u.tenant_id = $1 AND (u.created_at, u.principal_id::text) > ($2, $3)
		ORDER BY u.created_at, u.principal_id
		LIMIT $4`, tenantID, afterCreated, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.User, error) {
		var u model.User
		err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Status, &u.EmailVerified, &u.AssuranceLevel, &u.CreatedAt)
		return u, err
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (r *authRepository) RevokeOtherSessions(ctx context.Context, tx pgx.Tx, tenantID, principalID, keepSessionID, reason string, at time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET revoked_at = $3, revoked_reason = $4
		WHERE tenant_id = $1 AND principal_id = $2 AND id <> $5 AND revoked_at IS NULL`,
		tenantID, principalID, at, reason, keepSessionID)
	if err != nil {
		return 0, fmt.Errorf("revoke other sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (r *authRepository) SetActiveResource(ctx context.Context, tx pgx.Tx, tenantID, sessionID, resourceID string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET active_resource_id = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, sessionID, postgres.NullString(resourceID)); err != nil {
		return fmt.Errorf("set active resource: %w", err)
	}
	return nil
}

func (r *authRepository) ClearActiveResource(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET active_resource_id = NULL WHERE tenant_id = $1 AND active_resource_id = $2`,
		tenantID, resourceID); err != nil {
		return fmt.Errorf("clear active resource: %w", err)
	}
	return nil
}

func (r *authRepository) ClearActiveResourceFor(ctx context.Context, tx pgx.Tx, tenantID, principalID, resourceID string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET active_resource_id = NULL
		WHERE tenant_id = $1 AND principal_id = $2 AND active_resource_id = $3`, tenantID, principalID, resourceID); err != nil {
		return fmt.Errorf("clear active resource: %w", err)
	}
	return nil
}

func (r *authRepository) CountUsers(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM aos.users u
		JOIN aos.principals p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
		WHERE u.tenant_id = $1 AND p.status <> 'deleted'`, tenantID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------
// Principals and guests
// ---------------------------------------------------------------------

func (r *authRepository) GetPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (*model.PrincipalRow, error) {
	var p model.PrincipalRow
	err := tx.QueryRow(ctx, `
		SELECT id::text, kind, status, COALESCE(display_name, ''), created_at
		FROM aos.principals WHERE tenant_id = $1 AND id = $2`, tenantID, principalID).Scan(&p.ID, &p.Kind, &p.Status, &p.DisplayName, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get principal: %w", err)
	}
	return &p, nil
}

func (r *authRepository) CreateGuest(ctx context.Context, tx pgx.Tx, tenantID, name string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.principals (tenant_id, kind, display_name) VALUES ($1, 'guest', NULLIF($2, '')) RETURNING id::text`,
		tenantID, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create guest: %w", err)
	}
	return id, nil
}

func (r *authRepository) AttachAccount(ctx context.Context, tx pgx.Tx, tenantID, principalID, email, name string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO aos.users (principal_id, tenant_id, email, name) VALUES ($1, $2, $3, NULLIF($4, ''))`,
		principalID, tenantID, email, name); err != nil {
		return fmt.Errorf("attach account: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE aos.principals SET kind = 'user', display_name = COALESCE(NULLIF($3, ''), display_name)
		WHERE tenant_id = $1 AND id = $2`, tenantID, principalID, name); err != nil {
		return fmt.Errorf("attach account: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Guessable tokens
// ---------------------------------------------------------------------

func (r *authRepository) LockTokenByTarget(ctx context.Context, tx pgx.Tx, tenantID, purpose, target string) (*model.Token, error) {
	var t model.Token
	var payload []byte
	err := tx.QueryRow(ctx, `
		SELECT id::text, COALESCE(principal_id::text, ''), token_hash, attempts, max_attempts, expires_at, used_at, payload
		FROM aos.tokens
		WHERE tenant_id = $1 AND purpose = $2 AND target = $3 AND used_at IS NULL
		ORDER BY created_at DESC LIMIT 1
		FOR UPDATE`, tenantID, purpose, target).Scan(&t.ID, &t.PrincipalID, &t.Hash, &t.Attempts, &t.MaxAttempts, &t.ExpiresAt, &t.UsedAt, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock token: %w", err)
	}
	if err := json.Unmarshal(payload, &t.Payload); err != nil {
		return nil, fmt.Errorf("lock token: read payload: %w", err)
	}
	return &t, nil
}

func (r *authRepository) BumpTokenAttempts(ctx context.Context, tx pgx.Tx, tenantID, tokenID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `UPDATE aos.tokens SET attempts = attempts + 1 WHERE tenant_id = $1 AND id = $2 RETURNING attempts`,
		tenantID, tokenID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("bump token attempts: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------

func (r *authRepository) CreateChallenge(ctx context.Context, tx pgx.Tx, tenantID string, c model.NewChallenge) (string, error) {
	data := c.Data
	if data == nil {
		data = map[string]any{}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("create challenge: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.challenges (tenant_id, kind, principal_id, token_hash, data, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
		tenantID, c.Kind, postgres.NullString(c.PrincipalID), c.TokenHash, encoded, c.ExpiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create challenge: %w", err)
	}
	return id, nil
}

const challengeColumns = `id::text, kind, COALESCE(principal_id::text, ''), data, attempts, expires_at, consumed_at`

func scanChallenge(row pgx.Row) (*model.Challenge, error) {
	var c model.Challenge
	var data []byte
	err := row.Scan(&c.ID, &c.Kind, &c.PrincipalID, &data, &c.Attempts, &c.ExpiresAt, &c.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock challenge: %w", err)
	}
	if err := json.Unmarshal(data, &c.Data); err != nil {
		return nil, fmt.Errorf("lock challenge: read data: %w", err)
	}
	return &c, nil
}

func (r *authRepository) LockChallengeByToken(ctx context.Context, tx pgx.Tx, tenantID, kind string, tokenHash []byte) (*model.Challenge, error) {
	return scanChallenge(tx.QueryRow(ctx, `
		SELECT `+challengeColumns+` FROM aos.challenges
		WHERE tenant_id = $1 AND kind = $2 AND token_hash = $3 FOR UPDATE`, tenantID, kind, tokenHash))
}

func (r *authRepository) LockChallenge(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Challenge, error) {
	if !postgres.IsUUID(id) {
		return nil, nil
	}
	return scanChallenge(tx.QueryRow(ctx, `
		SELECT `+challengeColumns+` FROM aos.challenges WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id))
}

func (r *authRepository) BumpChallengeAttempts(ctx context.Context, tx pgx.Tx, tenantID, id string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `UPDATE aos.challenges SET attempts = attempts + 1 WHERE tenant_id = $1 AND id = $2 RETURNING attempts`,
		tenantID, id).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("bump challenge attempts: %w", err)
	}
	return n, nil
}

func (r *authRepository) ConsumeChallenge(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.challenges SET consumed_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Second factors
// ---------------------------------------------------------------------

func (r *authRepository) GetTOTP(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (*model.TOTPFactor, error) {
	var f model.TOTPFactor
	var step *int64
	err := tx.QueryRow(ctx, `
		SELECT id::text, secret_encrypted, data_key_id::text, confirmed_at IS NOT NULL, last_used_step
		FROM aos.totp_factors WHERE tenant_id = $1 AND principal_id = $2
		ORDER BY confirmed_at DESC NULLS LAST, created_at DESC LIMIT 1`, tenantID, principalID).Scan(
		&f.ID, &f.SecretEncrypted, &f.DataKeyID, &f.Confirmed, &step)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get totp: %w", err)
	}
	if step != nil {
		f.LastUsedStep = *step
	}
	return &f, nil
}

func (r *authRepository) CreateTOTP(ctx context.Context, tx pgx.Tx, tenantID, principalID string, secretEncrypted []byte, dataKeyID string) (string, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.totp_factors WHERE tenant_id = $1 AND principal_id = $2 AND confirmed_at IS NULL`,
		tenantID, principalID); err != nil {
		return "", fmt.Errorf("create totp: %w", err)
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.totp_factors (tenant_id, principal_id, secret_encrypted, data_key_id)
		VALUES ($1, $2, $3, $4) RETURNING id::text`, tenantID, principalID, secretEncrypted, dataKeyID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create totp: %w", err)
	}
	return id, nil
}

func (r *authRepository) ConfirmTOTP(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	// Confirming one factor retires any other for the same person.
	if _, err := tx.Exec(ctx, `
		DELETE FROM aos.totp_factors WHERE tenant_id = $1 AND id <> $2
		  AND principal_id = (SELECT principal_id FROM aos.totp_factors WHERE tenant_id = $1 AND id = $2)`, tenantID, id); err != nil {
		return fmt.Errorf("confirm totp: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE aos.totp_factors SET confirmed_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("confirm totp: %w", err)
	}
	return nil
}

func (r *authRepository) SetTOTPLastStep(ctx context.Context, tx pgx.Tx, tenantID, id string, step int64) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.totp_factors SET last_used_step = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, step); err != nil {
		return fmt.Errorf("set totp step: %w", err)
	}
	return nil
}

func (r *authRepository) DeleteTOTP(ctx context.Context, tx pgx.Tx, tenantID, principalID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.totp_factors WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID); err != nil {
		return fmt.Errorf("delete totp: %w", err)
	}
	return nil
}

func (r *authRepository) ReplaceRecoveryCodes(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hashes [][]byte) error {
	if _, err := tx.Exec(ctx, `DELETE FROM aos.recovery_codes WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO aos.recovery_codes (tenant_id, principal_id, code_hash) VALUES ($1, $2, $3)`,
			tenantID, principalID, h); err != nil {
			return fmt.Errorf("replace recovery codes: %w", err)
		}
	}
	return nil
}

func (r *authRepository) UseRecoveryCode(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hash []byte, at time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE aos.recovery_codes SET used_at = $4
		WHERE tenant_id = $1 AND principal_id = $2 AND code_hash = $3 AND used_at IS NULL`, tenantID, principalID, hash, at)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *authRepository) CountRecoveryCodes(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.recovery_codes WHERE tenant_id = $1 AND principal_id = $2 AND used_at IS NULL`,
		tenantID, principalID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}

func (r *authRepository) CountPasskeys(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.passkeys WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count passkeys: %w", err)
	}
	return n, nil
}

func (r *authRepository) SetSecondFactorAt(ctx context.Context, tx pgx.Tx, tenantID, sessionID, method string, at time.Time) error {
	entry, err := json.Marshal([]model.AuthMethod{{Method: method, At: at}})
	if err != nil {
		return fmt.Errorf("set second factor: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET second_factor_at = $3, auth_methods = auth_methods || $4::jsonb
		WHERE tenant_id = $1 AND id = $2`, tenantID, sessionID, at, entry); err != nil {
		return fmt.Errorf("set second factor: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------

func (r *authRepository) FindDevice(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hash []byte) (*model.Device, error) {
	var d model.Device
	err := tx.QueryRow(ctx, `
		SELECT id::text, COALESCE(label, ''), first_seen_at, last_seen_at
		FROM aos.devices WHERE tenant_id = $1 AND principal_id = $2 AND device_hash = $3`, tenantID, principalID, hash).Scan(
		&d.ID, &d.Label, &d.FirstSeenAt, &d.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find device: %w", err)
	}
	return &d, nil
}

func (r *authRepository) CreateDevice(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hash []byte, label string, at time.Time) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.devices (tenant_id, principal_id, device_hash, label, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5) RETURNING id::text`, tenantID, principalID, hash, label, at).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create device: %w", err)
	}
	return id, nil
}

func (r *authRepository) TouchDevice(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.devices SET last_seen_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("touch device: %w", err)
	}
	return nil
}

func (r *authRepository) CountDevices(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.devices WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count devices: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------
// Token sessions
// ---------------------------------------------------------------------

func (r *authRepository) CreateTokenFamily(ctx context.Context, tx pgx.Tx, tenantID, principalID, sessionID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.token_families (tenant_id, principal_id, session_id) VALUES ($1, $2, $3) RETURNING id::text`,
		tenantID, principalID, sessionID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create token family: %w", err)
	}
	return id, nil
}

func (r *authRepository) CreateRefreshToken(ctx context.Context, tx pgx.Tx, tenantID, familyID string, hash []byte, expires time.Time) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.refresh_tokens (tenant_id, family_id, token_hash, expires_at) VALUES ($1, $2, $3, $4) RETURNING id::text`,
		tenantID, familyID, hash, expires).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}
	return id, nil
}

func (r *authRepository) LockRefreshToken(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte) (*model.RefreshToken, error) {
	var t model.RefreshToken
	err := tx.QueryRow(ctx, `
		SELECT rt.id::text, rt.family_id::text, f.principal_id::text, COALESCE(f.session_id::text, ''), COALESCE(f.client_id::text, ''),
		       f.scopes, COALESCE(f.audience, ''), rt.expires_at, rt.used_at, f.revoked_at IS NOT NULL
		FROM aos.refresh_tokens rt
		JOIN aos.token_families f ON f.tenant_id = rt.tenant_id AND f.id = rt.family_id
		WHERE rt.tenant_id = $1 AND rt.token_hash = $2
		FOR UPDATE OF rt`, tenantID, hash).Scan(&t.ID, &t.FamilyID, &t.PrincipalID, &t.SessionID, &t.ClientID, &t.Scopes, &t.Audience, &t.ExpiresAt, &t.UsedAt, &t.FamilyRevoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock refresh token: %w", err)
	}
	return &t, nil
}

func (r *authRepository) MarkRefreshTokenUsed(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.refresh_tokens SET used_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}

func (r *authRepository) RevokeTokenFamily(ctx context.Context, tx pgx.Tx, tenantID, familyID, reason string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.token_families SET revoked_at = $3, revoked_reason = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, tenantID, familyID, at, reason); err != nil {
		return fmt.Errorf("revoke token family: %w", err)
	}
	return nil
}

func (r *authRepository) RevokeTokenFamiliesOf(ctx context.Context, tx pgx.Tx, tenantID, sessionID, reason string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.token_families SET revoked_at = $3, revoked_reason = $4
		WHERE tenant_id = $1 AND session_id = $2 AND revoked_at IS NULL`, tenantID, sessionID, at, reason); err != nil {
		return fmt.Errorf("revoke token families: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------

const passkeyColumns = `id::text, principal_id::text, credential_id, public_key, sign_count, transports, aaguid, backup_eligible, backed_up, COALESCE(name, ''), created_at, last_used_at`

func scanPasskey(row pgx.CollectableRow) (model.Passkey, error) {
	var p model.Passkey
	var aaguid *[16]byte
	err := row.Scan(&p.ID, &p.PrincipalID, &p.CredentialID, &p.PublicKey, &p.SignCount, &p.Transports, &aaguid, &p.BackupEligible, &p.BackedUp, &p.Name, &p.CreatedAt, &p.LastUsedAt)
	if aaguid != nil {
		p.AAGUID = aaguid[:]
	}
	return p, err
}

func (r *authRepository) ListPasskeys(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.Passkey, error) {
	rows, err := tx.Query(ctx, `SELECT `+passkeyColumns+` FROM aos.passkeys WHERE tenant_id = $1 AND principal_id = $2 ORDER BY created_at`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanPasskey)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	return out, nil
}

func (r *authRepository) CreatePasskey(ctx context.Context, tx pgx.Tx, tenantID string, p model.Passkey) (string, error) {
	var aaguid any
	if len(p.AAGUID) == 16 {
		var a [16]byte
		copy(a[:], p.AAGUID)
		aaguid = a
	}
	if p.Transports == nil {
		p.Transports = []string{}
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.passkeys (tenant_id, principal_id, credential_id, public_key, sign_count, transports, aaguid, backup_eligible, backed_up, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, '')) RETURNING id::text`,
		tenantID, p.PrincipalID, p.CredentialID, p.PublicKey, p.SignCount, p.Transports, aaguid, p.BackupEligible, p.BackedUp, p.Name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create passkey: %w", err)
	}
	return id, nil
}

func (r *authRepository) FindPasskey(ctx context.Context, tx pgx.Tx, tenantID string, credentialID []byte) (*model.Passkey, error) {
	rows, err := tx.Query(ctx, `SELECT `+passkeyColumns+` FROM aos.passkeys WHERE tenant_id = $1 AND credential_id = $2`, tenantID, credentialID)
	if err != nil {
		return nil, fmt.Errorf("find passkey: %w", err)
	}
	p, err := pgx.CollectOneRow(rows, scanPasskey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find passkey: %w", err)
	}
	return &p, nil
}

func (r *authRepository) UsePasskey(ctx context.Context, tx pgx.Tx, tenantID, id string, signCount int64, backedUp bool, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.passkeys SET sign_count = $3, backed_up = $4, last_used_at = $5 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, signCount, backedUp, at); err != nil {
		return fmt.Errorf("use passkey: %w", err)
	}
	return nil
}

func (r *authRepository) DeletePasskey(ctx context.Context, tx pgx.Tx, tenantID, principalID, id string) (bool, error) {
	if !postgres.IsUUID(id) {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `DELETE FROM aos.passkeys WHERE tenant_id = $1 AND principal_id = $2 AND id = $3`, tenantID, principalID, id)
	if err != nil {
		return false, fmt.Errorf("delete passkey: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ---------------------------------------------------------------------
// Social sign-in
// ---------------------------------------------------------------------

func (r *authRepository) UpsertOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID string, p model.OAuthProvider) (string, error) {
	if p.Scopes == nil {
		p.Scopes = []string{}
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO aos.oauth_providers (tenant_id, provider, client_id, client_secret_encrypted, data_key_id, scopes, enabled, issuer)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''))
		ON CONFLICT (tenant_id, provider) DO UPDATE SET
			client_id = EXCLUDED.client_id, client_secret_encrypted = EXCLUDED.client_secret_encrypted,
			data_key_id = EXCLUDED.data_key_id, scopes = EXCLUDED.scopes, enabled = EXCLUDED.enabled, issuer = EXCLUDED.issuer
		RETURNING id::text`, tenantID, p.Provider, p.ClientID, p.SecretEncrypted, p.DataKeyID, p.Scopes, p.Enabled, p.Issuer).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert oauth provider: %w", err)
	}
	return id, nil
}

const providerColumns = `id::text, provider, client_id, client_secret_encrypted, data_key_id::text, COALESCE(issuer, ''), scopes, enabled, created_at`

func scanProvider(row pgx.CollectableRow) (model.OAuthProvider, error) {
	var p model.OAuthProvider
	err := row.Scan(&p.ID, &p.Provider, &p.ClientID, &p.SecretEncrypted, &p.DataKeyID, &p.Issuer, &p.Scopes, &p.Enabled, &p.CreatedAt)
	return p, err
}

func (r *authRepository) GetOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID, provider string) (*model.OAuthProvider, error) {
	rows, err := tx.Query(ctx, `SELECT `+providerColumns+` FROM aos.oauth_providers WHERE tenant_id = $1 AND provider = $2`, tenantID, provider)
	if err != nil {
		return nil, fmt.Errorf("get oauth provider: %w", err)
	}
	p, err := pgx.CollectOneRow(rows, scanProvider)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get oauth provider: %w", err)
	}
	return &p, nil
}

func (r *authRepository) ListOAuthProviders(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.OAuthProvider, error) {
	rows, err := tx.Query(ctx, `SELECT `+providerColumns+` FROM aos.oauth_providers WHERE tenant_id = $1 ORDER BY provider`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list oauth providers: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanProvider)
	if err != nil {
		return nil, fmt.Errorf("list oauth providers: %w", err)
	}
	return out, nil
}

func (r *authRepository) DeleteOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID, provider string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM aos.oauth_providers WHERE tenant_id = $1 AND provider = $2`, tenantID, provider)
	if err != nil {
		return false, fmt.Errorf("delete oauth provider: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

const identityColumns = `id::text, principal_id::text, provider, subject, COALESCE(email::text, ''), email_verified, created_at, last_sign_in_at`

func scanIdentity(row pgx.CollectableRow) (model.ExternalIdentity, error) {
	var i model.ExternalIdentity
	err := row.Scan(&i.ID, &i.PrincipalID, &i.Provider, &i.Subject, &i.Email, &i.EmailVerified, &i.CreatedAt, &i.LastSignInAt)
	return i, err
}

func (r *authRepository) FindExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID, provider, subject string) (*model.ExternalIdentity, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+identityColumns+` FROM aos.external_identities
		WHERE tenant_id = $1 AND provider = $2 AND subject = $3 AND connection_id IS NULL AND directory_id IS NULL`, tenantID, provider, subject)
	if err != nil {
		return nil, fmt.Errorf("find external identity: %w", err)
	}
	i, err := pgx.CollectOneRow(rows, scanIdentity)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find external identity: %w", err)
	}
	return &i, nil
}

func (r *authRepository) CreateExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID string, i model.ExternalIdentity, profile map[string]any) (string, error) {
	if profile == nil {
		profile = map[string]any{}
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("create external identity: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO aos.external_identities (tenant_id, principal_id, provider, subject, email, email_verified, profile, last_sign_in_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, now()) RETURNING id::text`,
		tenantID, i.PrincipalID, i.Provider, i.Subject, i.Email, i.EmailVerified, encoded).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create external identity: %w", err)
	}
	return id, nil
}

func (r *authRepository) TouchExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE aos.external_identities SET last_sign_in_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at); err != nil {
		return fmt.Errorf("touch external identity: %w", err)
	}
	return nil
}

func (r *authRepository) ListExternalIdentities(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.ExternalIdentity, error) {
	rows, err := tx.Query(ctx, `SELECT `+identityColumns+` FROM aos.external_identities WHERE tenant_id = $1 AND principal_id = $2 ORDER BY created_at`, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("list external identities: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanIdentity)
	if err != nil {
		return nil, fmt.Errorf("list external identities: %w", err)
	}
	return out, nil
}

func (r *authRepository) DeleteExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID, principalID, provider string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM aos.external_identities WHERE tenant_id = $1 AND principal_id = $2 AND provider = $3 AND connection_id IS NULL`,
		tenantID, principalID, provider)
	if err != nil {
		return false, fmt.Errorf("delete external identity: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *authRepository) CapSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, absolute time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE aos.sessions SET absolute_expires_at = LEAST(absolute_expires_at, $3), idle_expires_at = LEAST(idle_expires_at, $3)
		WHERE tenant_id = $1 AND id = $2`, tenantID, sessionID, absolute); err != nil {
		return fmt.Errorf("cap session: %w", err)
	}
	return nil
}
