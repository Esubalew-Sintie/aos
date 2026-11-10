package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/schema"
)

// migrationLock is the advisory lock that stops two copies of the engine
// from migrating the same database at the same time.
const migrationLock = 4201607

// Migrate applies every migration that has not been applied yet, in
// order, each in its own transaction. It returns the names it applied.
// It is safe to run on every start.
func (s *DB) Migrate(ctx context.Context) ([]string, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return nil, fmt.Errorf("migrate: take lock: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock)

	done := map[int]bool{}
	var tableExists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('aos.schema_migrations') IS NOT NULL`).Scan(&tableExists); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if tableExists {
		rows, err := conn.Query(ctx, `SELECT version FROM aos.schema_migrations`)
		if err != nil {
			return nil, fmt.Errorf("migrate: read applied versions: %w", err)
		}
		versions, err := pgx.CollectRows(rows, pgx.RowTo[int])
		if err != nil {
			return nil, fmt.Errorf("migrate: read applied versions: %w", err)
		}
		for _, v := range versions {
			done[v] = true
		}
	}

	files, err := fs.Glob(schema.FS, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	sort.Strings(files)

	var applied []string
	for _, name := range files {
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return applied, fmt.Errorf("migrate: %s: name must look like 0001_name.sql", name)
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return applied, fmt.Errorf("migrate: %s: name must start with a number", name)
		}
		if done[version] {
			continue
		}
		sql, err := schema.FS.ReadFile(name)
		if err != nil {
			return applied, fmt.Errorf("migrate: %w", err)
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// A migration file holds many statements, which only the
			// simple protocol accepts in one call.
			if _, err := tx.Exec(ctx, string(sql), pgx.QueryExecModeSimpleProtocol); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO aos.schema_migrations (version, name) VALUES ($1, $2)`, version, name)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migrate: %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// Pending lists the migration files not applied yet.
func (s *DB) Pending(ctx context.Context) ([]string, error) {
	done := map[int]bool{}
	var tableExists bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('aos.schema_migrations') IS NOT NULL`).Scan(&tableExists); err != nil {
		return nil, err
	}
	if tableExists {
		rows, err := s.pool.Query(ctx, `SELECT version FROM aos.schema_migrations`)
		if err != nil {
			return nil, err
		}
		versions, err := pgx.CollectRows(rows, pgx.RowTo[int])
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			done[v] = true
		}
	}
	files, err := fs.Glob(schema.FS, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var pending []string
	for _, name := range files {
		prefix, _, _ := strings.Cut(name, "_")
		if v, err := strconv.Atoi(prefix); err == nil && !done[v] {
			pending = append(pending, name)
		}
	}
	return pending, nil
}

// HasRole reports whether the connected user can act as a database role.
func (s *DB) HasRole(ctx context.Context, role string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT pg_has_role(current_user, $1, 'MEMBER')`, role).Scan(&ok)
	return ok, err
}
