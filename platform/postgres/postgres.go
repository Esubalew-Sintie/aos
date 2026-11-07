// Package postgres is the only way the engine reaches the database.
//
// There is no method that hands out an unscoped connection for ordinary
// work. A caller must say which tenant it is working in (Tenant), or that
// it is the platform (Platform), or that it only needs to find a tenant
// (Resolver). Each one switches the database role and names the tenant
// inside the transaction, so row-level security applies to every query.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string) (*DB, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (s *DB) Close() { s.pool.Close() }

func (s *DB) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Tenant runs fn in a transaction that can see and change one tenant's
// rows and no others.
func (s *DB) Tenant(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := SetTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// Platform runs fn as the platform role. It can see every tenant as an
// account and the platform's own tables. It cannot read inside a tenant.
func (s *DB) Platform(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := SetPlatform(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

// Resolver runs fn as the engine's role with no tenant named. Every table
// looks empty. Only the functions that find a tenant from a key or a
// hostname return anything.
func (s *DB) Resolver(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`SELECT set_config('role', 'aos_app', true), set_config('aos.tenant_id', '', true)`); err != nil {
			return fmt.Errorf("postgres: enter resolver scope: %w", err)
		}
		return fn(tx)
	})
}

// Switching runs fn in a plain transaction. fn must call SetPlatform or
// SetTenant before its first query. It exists for the one job that
// crosses the line on purpose: creating a tenant (platform) and then
// filling it (tenant) atomically.
func (s *DB) Switching(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

// SetTenant points the transaction at one tenant.
func SetTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if !IsUUID(tenantID) {
		return fmt.Errorf("postgres: %q is not a tenant id", tenantID)
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('role', 'aos_app', true), set_config('aos.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("postgres: enter tenant scope: %w", err)
	}
	return nil
}

// SetPlatform points the transaction at the platform role.
func SetPlatform(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx,
		`SELECT set_config('role', 'aos_platform', true), set_config('aos.tenant_id', '', true)`); err != nil {
		return fmt.Errorf("postgres: enter platform scope: %w", err)
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID reports whether s has the form of an id.
func IsUUID(s string) bool { return uuidPattern.MatchString(s) }

// IsUniqueViolation reports whether err is a broken unique constraint.
func IsUniqueViolation(err error) bool { return pgCode(err) == "23505" }

// IsForeignKeyViolation reports whether err is a broken foreign key.
func IsForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

// IsCheckViolation reports whether err is a broken check constraint.
func IsCheckViolation(err error) bool { return pgCode(err) == "23514" }

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// NullString turns an empty string into a database null.
func NullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
