// Package testdb gives a test its own empty, migrated database.
//
// SAFETY. A test database is created, used and removed by the test
// itself. This package never touches a database it did not create:
//
//   - It runs only when AOS_TEST_DATABASE_URL is set. There is no default
//     address, so a bare "go test" connects to nothing and skips.
//   - It creates a new database with a random name starting "aos_test_"
//     and works only inside it.
//   - On cleanup it drops that one database, by the name it made.
//
// Point AOS_TEST_DATABASE_URL at a throwaway Postgres, never at a server
// that holds real data. "make test" starts one in Docker and removes it
// afterwards.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/platform/postgres"
)

const envVar = "AOS_TEST_DATABASE_URL"

// Open returns a migrated database that exists only for this test.
func Open(t testing.TB) *postgres.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := postgres.Open(ctx, URL(t))
	if err != nil {
		t.Fatalf("testdb: open: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("testdb: migrate: %v", err)
	}
	return db
}

// URL creates an empty database that exists only for this test and
// returns its address, for code that connects by itself.
func URL(t testing.TB) string {
	t.Helper()
	base := os.Getenv(envVar)
	if base == "" {
		t.Skip(envVar + " is not set. Run `make test`, which starts a throwaway Postgres for the tests.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := make([]byte, 8)
	rand.Read(suffix)
	// The name is built here from hex digits only, so it is safe to place
	// in the statements below.
	name := "aos_test_" + hex.EncodeToString(suffix)

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("testdb: connect to the test server: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("testdb: create %s: %v", name, err)
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("testdb: %s is not a URL: %v", envVar, err)
	}
	u.Path = "/" + name

	// Cleanups run last-added first, so this drop runs after anything the
	// test registers later, such as closing its own connections.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Only ever the database created above.
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("testdb: drop %s: %v", name, err)
		}
		admin.Close(ctx)
	})
	return u.String()
}
