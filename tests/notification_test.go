package tests

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/platform/secret"
)

// Rule: secrets leave AOS once. The raw token exists only in the email.
// In the database the message is encrypted while it waits, and wiped
// once it is sent. The token itself is stored only as a hash.
func TestTokensAreNeverStoredInClear(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.front("POST", "/v1/sign-up", obj{"email": "hana@example.com", "password": "some-password"}, "")

	ctx := context.Background()
	var waiting []byte
	var status string
	tn.sql(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT body_encrypted, status FROM aos.messages`).Scan(&waiting, &status)
	})
	if status != "pending" || len(waiting) == 0 {
		t.Fatalf("the message should be waiting with a body: status %q, %d bytes", status, len(waiting))
	}

	if sent := e.deliver(); sent != 1 {
		t.Fatalf("want 1 message sent, got %d", sent)
	}
	token := e.mail.token("hana@example.com")
	if token == "" {
		t.Fatal("the email carries no token")
	}

	// While it waited, the stored body held neither the token nor the link.
	if bytes.Contains(waiting, []byte(token)) || bytes.Contains(waiting, []byte("app.test")) {
		t.Fatal("the waiting message was stored in clear")
	}
	// Once sent, the body is gone.
	if n := tn.count(`SELECT count(*) FROM aos.messages WHERE status = 'sent' AND body_encrypted IS NULL AND sent_at IS NOT NULL`); n != 1 {
		t.Fatal("the sent message kept its body")
	}
	// The token table holds the hash, and nothing that equals the token.
	if n := tn.count(`SELECT count(*) FROM aos.tokens WHERE token_hash = $1`, secret.Hash(token)); n != 1 {
		t.Fatal("the token's hash is not what is stored")
	}
	if n := tn.count(`SELECT count(*) FROM aos.tokens WHERE token_hash = $1 OR target = $2`, []byte(token), token); n != 0 {
		t.Fatal("the raw token is stored")
	}
	// The same holds for the session: only a hash of its id is stored.
	r := tn.front("POST", "/v1/verify-email", obj{"token": token}, "")
	var out authData
	r.data(&out)
	if n := tn.count(`SELECT count(*) FROM aos.sessions WHERE id_hash = $1`, secret.Hash(out.SessionToken)); n != 1 {
		t.Fatal("the session id's hash is not what is stored")
	}
	if n := tn.count(`SELECT count(*) FROM aos.sessions WHERE id_hash = $1`, []byte(out.SessionToken)); n != 0 {
		t.Fatal("the raw session id is stored")
	}
	// And for the password.
	if n := tn.count(`SELECT count(*) FROM aos.passwords WHERE hash LIKE '$argon2id$%' AND hash NOT LIKE '%some-password%'`); n != 1 {
		t.Fatal("the password is not stored as an Argon2id hash")
	}
}

// When the mail server is down the action still succeeds, the message
// waits, and it goes out once the server is back.
func TestFailedDeliveryIsTriedAgain(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")

	e.mail.fail = true
	if r := tn.front("POST", "/v1/sign-up", obj{"email": "hana@example.com", "password": "some-password"}, ""); r.Status != 202 {
		t.Fatalf("sign up should succeed while mail is down: %d %s", r.Status, r.Raw)
	}
	if sent := e.deliver(); sent != 0 {
		t.Fatalf("a message was reported sent while mail was down: %d", sent)
	}
	if n := tn.count(`SELECT count(*) FROM aos.messages
	                  WHERE status = 'pending' AND attempts = 1 AND next_attempt_at IS NOT NULL AND body_encrypted IS NOT NULL`); n != 1 {
		t.Fatal("the failed message should wait for another attempt, with its body kept")
	}
	// It is not tried again before its time.
	e.mail.fail = false
	if sent := e.deliver(); sent != 0 {
		t.Fatalf("the message was retried before its next attempt time: %d", sent)
	}

	// Once that time has come, it is sent.
	tn.sql(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.messages SET next_attempt_at = now() - interval '1 second'`)
		return err
	})
	if sent := e.deliver(); sent != 1 {
		t.Fatalf("want the message sent on the retry, got %d", sent)
	}
	if e.mail.token("hana@example.com") == "" {
		t.Fatal("the retried email carries no token")
	}
}

// Events are written with the change, for delivery later.
func TestEventsAreWrittenWithTheChange(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.user("hana@example.com", "some-password")

	for _, eventType := range []string{"user.created", "user.email_verified", "session.created"} {
		if n := tn.count(`SELECT count(*) FROM aos.events WHERE type = $1`, eventType); n != 1 {
			t.Errorf("want 1 %s event, got %d", eventType, n)
		}
	}
	// A request that changes nothing writes no event.
	before := tn.count(`SELECT count(*) FROM aos.events`)
	tn.signIn("hana@example.com", "wrong-password")
	if after := tn.count(`SELECT count(*) FROM aos.events`); after != before {
		t.Fatalf("a failed sign-in wrote %d events", after-before)
	}
}
