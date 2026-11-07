package tests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This file is the PRD's M0 exit test: a two-tenant isolation suite.
// Two tenants live in one database. Nothing one of them does may see,
// change or even refer to anything of the other.

const permissionDenied = "42501" // Postgres: insufficient privilege, or a row-level security refusal

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func TestTenantsShareNothing(t *testing.T) {
	e := newEnv(t)
	a, b := e.tenant("alpha"), e.tenant("beta")

	// The same email address is a different account in each tenant.
	idA, sessionA := a.user("hana@example.com", "alpha-password")
	idB, sessionB := b.user("hana@example.com", "beta-password")
	if idA == idB {
		t.Fatal("two tenants share one account")
	}

	// One tenant's password does not work in the other.
	if r := b.signIn("hana@example.com", "alpha-password"); r.code() != "invalid_credentials" {
		t.Fatalf("tenant A's password works in tenant B: %d %s", r.Status, r.Raw)
	}
	// Nor does its session.
	if r := b.front("GET", "/v1/session", nil, sessionA); r.Status != 401 {
		t.Fatalf("tenant A's session works in tenant B: %d", r.Status)
	}
	if r := a.front("GET", "/v1/session", nil, sessionB); r.Status != 401 {
		t.Fatalf("tenant B's session works in tenant A: %d", r.Status)
	}
	// Nor does a confirmation link.
	a.front("POST", "/v1/sign-up", obj{"email": "second@example.com", "password": "some-password"}, "")
	e.deliver()
	link := e.mail.token("second@example.com")
	if r := b.front("POST", "/v1/verify-email", obj{"token": link}, ""); r.code() != "invalid_token" {
		t.Fatalf("tenant A's link works in tenant B: %d %s", r.Status, r.Raw)
	}
	if r := a.front("POST", "/v1/verify-email", obj{"token": link}, ""); r.Status != 200 {
		t.Fatalf("the link was damaged by the attempt in the other tenant: %d %s", r.Status, r.Raw)
	}

	// With tenant A's secret key, tenant B's user does not exist.
	r := a.back("POST", "/v1/can", obj{
		"principal_id": idB, "permission": "payment.read", "resource": obj{"type": "tenant", "id": "root"},
	})
	var decision struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	r.data(&decision)
	if decision.Allowed || decision.Reason != "unknown_principal" {
		t.Fatalf("tenant A can see tenant B's user: %s", r.Raw)
	}
	// And cannot be given a role there.
	r = a.back("POST", "/v1/grants", obj{
		"principal_id": idB, "role": "Owner", "resource": obj{"type": "tenant", "id": "root"},
	})
	if r.Status != 400 || r.Body.Error.Details["principal_id"] == "" {
		t.Fatalf("tenant A granted a role to tenant B's user: %d %s", r.Status, r.Raw)
	}

	// The queries below name no tenant at all. Row-level security alone
	// decides what each one sees.
	for name, tn := range map[string]*tenant{"alpha": a, "beta": b} {
		wantUsers := map[string]int{"alpha": 2, "beta": 1}[name]
		if n := tn.count(`SELECT count(*) FROM aos.users`); n != wantUsers {
			t.Fatalf("%s sees %d users, want %d", name, n, wantUsers)
		}
		if n := tn.count(`SELECT count(*) FROM aos.tenants`); n != 1 {
			t.Fatalf("%s sees %d tenants, want only itself", name, n)
		}
		if n := tn.count(`SELECT count(*) FROM aos.sessions WHERE tenant_id <> $1`, tn.ID); n != 0 {
			t.Fatalf("%s sees %d sessions of another tenant", name, n)
		}
		if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE tenant_id <> $1`, tn.ID); n != 0 {
			t.Fatalf("%s sees %d audit entries of another tenant", name, n)
		}
	}
}

func TestEngineCannotWriteIntoAnotherTenant(t *testing.T) {
	e := newEnv(t)
	a, b := e.tenant("alpha"), e.tenant("beta")
	idB, _ := b.user("hana@example.com", "some-password")
	ctx := context.Background()

	inA := func(fn func(tx pgx.Tx) error) error { return e.app.DB.Tenant(ctx, a.ID, fn) }

	// A new row for the other tenant is refused.
	err := inA(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO aos.principals (tenant_id, kind) VALUES ($1, 'user')`, b.ID)
		return err
	})
	if sqlState(err) != permissionDenied {
		t.Fatalf("writing a row into another tenant: got %v, want a row-level security refusal", err)
	}

	// An update or a delete finds nothing to touch.
	err = inA(func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE aos.principals SET status = 'suspended' WHERE id = $1`, idB)
		if err == nil && tag.RowsAffected() != 0 {
			t.Fatal("tenant A changed a row of tenant B")
		}
		tag, err = tx.Exec(ctx, `DELETE FROM aos.users`)
		if err == nil && tag.RowsAffected() != 0 {
			t.Fatal("tenant A deleted rows of tenant B")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := b.count(`SELECT count(*) FROM aos.users`); n != 1 {
		t.Fatalf("tenant B lost its user: %d", n)
	}

	// A row of tenant A cannot point at a row of tenant B, even with the
	// right id in hand: the foreign key includes the tenant.
	err = inA(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO aos.grants (tenant_id, principal_id, role_id, resource_id)
			SELECT $1::uuid, $2::uuid, ro.id, re.id
			FROM aos.roles ro, aos.resources re WHERE ro.name = 'Owner' AND re.parent_id IS NULL`, a.ID, idB)
		return err
	})
	if sqlState(err) != "23503" {
		t.Fatalf("a grant in tenant A pointed at tenant B's user: got %v, want a foreign key refusal", err)
	}
}

// With no tenant named, every table looks empty.
func TestNoTenantNamedSeesNothing(t *testing.T) {
	e := newEnv(t)
	e.tenant("alpha").user("hana@example.com", "some-password")
	ctx := context.Background()

	err := e.app.DB.Resolver(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"tenants", "users", "principals", "sessions", "passwords", "tenant_keys", "audit_log"} {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.`+table).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Fatalf("with no tenant named, aos.%s shows %d rows", table, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// "Managing a tenant is not reading it": the platform's database role
// lists tenants as accounts and can read nothing inside them.
func TestPlatformRoleCannotReadInsideATenant(t *testing.T) {
	e := newEnv(t)
	e.tenant("alpha").user("hana@example.com", "some-password")
	e.tenant("beta")
	ctx := context.Background()

	err := e.app.DB.Platform(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM aos.tenants`).Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			t.Fatalf("the platform role sees %d tenants, want 2", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"users", "principals", "sessions", "passwords", "grants", "audit_log", "tenant_keys"} {
		err := e.app.DB.Platform(ctx, func(tx pgx.Tx) error {
			var n int
			return tx.QueryRow(ctx, `SELECT count(*) FROM aos.`+table).Scan(&n)
		})
		if sqlState(err) != permissionDenied {
			t.Fatalf("the platform role read aos.%s: got %v, want permission denied", table, err)
		}
	}
}

// Each key opens its own door and no other.
// unknownSecretKey has the shape of a secret key but belongs to nobody.
// It is built in pieces so that secret scanners do not mistake it for a
// real key of another service.
var unknownSecretKey = "sk_" + "test_" + strings.Repeat("0", 24) + ".nope"

func TestKeysOpenOnlyTheirOwnDoor(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("alpha")
	other := e.tenant("beta")
	can := obj{"principal_id": "00000000-0000-0000-0000-000000000000", "permission": "a.b", "resource": obj{"type": "tenant", "id": "root"}}
	signIn := obj{"email": "nobody@example.com", "password": "x"}

	publicID, _, _ := cut(tn.SK, ".")
	_, otherSecret, _ := cut(other.SK, ".")
	refused := map[string]result{
		"no key on the backend door":            e.call("POST", "/v1/can", can),
		"no key on the frontend door":           e.call("POST", "/v1/sign-in", signIn),
		"publishable key on the backend door":   e.call("POST", "/v1/can", can, "Authorization", "Bearer "+tn.PK),
		"secret key on the frontend door":       e.call("POST", "/v1/sign-in", signIn, "X-AOS-Publishable-Key", tn.SK),
		"unknown key":                           e.call("POST", "/v1/can", can, "Authorization", "Bearer "+unknownSecretKey),
		"right key id, wrong secret":            e.call("POST", "/v1/can", can, "Authorization", "Bearer "+publicID+".wrong"),
		"right key id, another tenant's secret": e.call("POST", "/v1/can", can, "Authorization", "Bearer "+publicID+"."+otherSecret),
		"secret key with its secret cut off":    e.call("POST", "/v1/can", can, "Authorization", "Bearer "+publicID),
	}
	for name, r := range refused {
		if r.Status != 401 || r.code() != "invalid_key" {
			t.Errorf("%s: got %d %s, want 401 invalid_key", name, r.Status, r.Raw)
		}
	}
	if r := tn.back("POST", "/v1/can", can); r.Status != 200 {
		t.Fatalf("the real secret key was refused: %d %s", r.Status, r.Raw)
	}

	// A suspended tenant is refused at both doors.
	err := e.app.DB.Platform(context.Background(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.tenants SET status = 'suspended' WHERE id = $1`, tn.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := tn.back("POST", "/v1/can", can); r.Status != 403 || r.code() != "tenant_unavailable" {
		t.Fatalf("a suspended tenant's backend door: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/sign-in", signIn, ""); r.Status != 403 || r.code() != "tenant_unavailable" {
		t.Fatalf("a suspended tenant's frontend door: %d %s", r.Status, r.Raw)
	}
	// The other tenant is not affected.
	if r := other.back("POST", "/v1/can", can); r.Status != 200 {
		t.Fatalf("suspending one tenant affected another: %d", r.Status)
	}
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}

// Running the migrations again changes nothing.
func TestMigrationsAreAppliedOnce(t *testing.T) {
	e := newEnv(t)
	applied, err := e.app.DB.Migrate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("a second run applied %v", applied)
	}
}
