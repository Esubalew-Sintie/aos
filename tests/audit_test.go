package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant/model"
)

func (e *env) metaForTest() model.RequestMeta {
	return model.RequestMeta{RequestID: "test"}
}

// verifyAudit recomputes the tenant's whole hash chain.
func (tn *tenant) verifyAudit() (int64, error) {
	var n int64
	err := tn.e.app.DB.Tenant(context.Background(), tn.ID, func(tx pgx.Tx) (err error) {
		n, err = tn.e.app.Storage.AuditRepo.Verify(context.Background(), tx, tn.ID)
		return err
	})
	return n, err
}

// asOwner runs a statement as the owner of the tables: the role a
// database administrator has, and the engine never uses for its work.
func (e *env) asOwner(statements ...string) {
	e.t.Helper()
	ctx := context.Background()
	err := e.app.DB.Switching(ctx, func(tx pgx.Tx) error {
		for _, s := range statements {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatalf("as owner: %v", err)
	}
}

// busyTenant returns a tenant with some history in its audit log.
func busyTenant(t *testing.T) (*env, *tenant) {
	e := newEnv(t)
	tn := e.tenant("acme")
	_, session := tn.user("hana@example.com", "right-password")
	tn.signIn("hana@example.com", "wrong-password")
	tn.signIn("hana@example.com", "right-password")
	tn.front("POST", "/v1/sign-out", nil, session)
	return e, tn
}

func TestAuditLogRecordsWhatHappenedAndVerifies(t *testing.T) {
	_, tn := busyTenant(t)

	n, err := tn.verifyAudit()
	if err != nil {
		t.Fatalf("an untouched log does not verify: %v", err)
	}
	if n < 6 {
		t.Fatalf("want at least 6 entries, got %d", n)
	}
	for _, action := range []string{
		"tenant.created", "user.created", "user.email_verified",
		"signin.succeeded", "signin.failed", "session.revoked",
	} {
		if c := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action = $1`, action); c == 0 {
			t.Errorf("no audit entry for %s", action)
		}
	}

	// The log holds ids, never addresses. Personal details sit apart.
	if c := tn.count(`SELECT count(*) FROM aos.audit_log WHERE data::text ILIKE '%example.com%' OR target_id ILIKE '%@%'`); c != 0 {
		t.Fatalf("%d audit entries hold an email address", c)
	}
	if c := tn.count(`SELECT count(*) FROM aos.audit_log_personal WHERE ip IS NOT NULL`); c == 0 {
		t.Fatal("no client address was recorded beside the log")
	}

	// Personal details can be erased without breaking the chain.
	tn.sql(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `DELETE FROM aos.audit_log_personal`)
		return err
	})
	if _, err := tn.verifyAudit(); err != nil {
		t.Fatalf("erasing personal details broke the chain: %v", err)
	}
}

// The engine's own database role can add to the log and nothing else.
func TestEngineCannotRewriteHistory(t *testing.T) {
	e, tn := busyTenant(t)
	ctx := context.Background()
	for name, statement := range map[string]string{
		"update": `UPDATE aos.audit_log SET action = 'something.else'`,
		"delete": `DELETE FROM aos.audit_log`,
	} {
		err := e.app.DB.Tenant(ctx, tn.ID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement)
			return err
		})
		if sqlState(err) != permissionDenied {
			t.Errorf("%s of the audit log: got %v, want permission denied", name, err)
		}
	}
	if _, err := tn.verifyAudit(); err != nil {
		t.Fatalf("the log no longer verifies: %v", err)
	}
}

// Someone with the owner's rights on the database can still change the
// table. The hash chain is what catches them.
func TestTamperingWithTheAuditLogIsDetected(t *testing.T) {
	cases := []struct {
		name   string
		tamper []string
		want   string
	}{
		{
			name: "an entry is changed",
			tamper: []string{
				`ALTER TABLE aos.audit_log DISABLE TRIGGER audit_log_no_update`,
				`UPDATE aos.audit_log SET reason_code = 'edited' WHERE seq = 3`,
				`ALTER TABLE aos.audit_log ENABLE TRIGGER audit_log_no_update`,
			},
			want: "entry 3: its contents were changed",
		},
		{
			name:   "an entry in the middle is removed",
			tamper: []string{`DELETE FROM aos.audit_log WHERE seq = 3`},
			want:   "an entry is missing",
		},
		{
			name:   "the last entries are cut off",
			tamper: []string{`DELETE FROM aos.audit_log WHERE seq > 3`},
			want:   "the end was cut off",
		},
		{
			name: "an entry is swapped for another",
			tamper: []string{
				`ALTER TABLE aos.audit_log DISABLE TRIGGER audit_log_no_update`,
				`UPDATE aos.audit_log SET hash = (SELECT hash FROM aos.audit_log WHERE seq = 2) WHERE seq = 3`,
				`ALTER TABLE aos.audit_log ENABLE TRIGGER audit_log_no_update`,
			},
			want: "entry 3",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, tn := busyTenant(t)
			if _, err := tn.verifyAudit(); err != nil {
				t.Fatalf("setup: %v", err)
			}
			e.asOwner(c.tamper...)
			_, err := tn.verifyAudit()
			if err == nil {
				t.Fatal("the tampering was not detected")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// Even the owner of the tables cannot change an entry without first
// switching the guard off, which is itself a visible act.
func TestAuditEntriesCannotBeUpdatedWhileTheGuardIsOn(t *testing.T) {
	e, _ := busyTenant(t)
	ctx := context.Background()
	err := e.app.DB.Switching(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE aos.audit_log SET reason_code = 'edited' WHERE seq = 1`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("got %v, want the append-only refusal", err)
	}
}
