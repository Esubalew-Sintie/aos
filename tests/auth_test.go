package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/platform/jwt"
)

// The whole happy path, through HTTP: sign up, confirm the link, read the
// session, get a signed token and verify it with the published keys,
// then sign out.
func TestSignUpVerifySignInSignOut(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")

	r := tn.front("POST", "/v1/sign-up", obj{"email": " Hana@Example.com ", "password": "correct horse", "name": "Hana"}, "")
	if r.Status != 202 {
		t.Fatalf("sign up: %d %s", r.Status, r.Raw)
	}
	if len(r.Header.Values("Set-Cookie")) != 0 {
		t.Fatal("sign up must not start a session before the address is confirmed")
	}
	if got := tn.signIn("hana@example.com", "correct horse").code(); got != "invalid_credentials" {
		t.Fatalf("sign in before confirming: got %q, want invalid_credentials", got)
	}

	e.deliver()
	emails := e.mail.to("hana@example.com")
	if len(emails) != 1 {
		t.Fatalf("want 1 email, got %d", len(emails))
	}
	if !strings.Contains(emails[0].Body, "https://app.test/auth/verify-email?token=") {
		t.Fatalf("the email has no link to the application:\n%s", emails[0].Body)
	}

	r = tn.front("POST", "/v1/verify-email", obj{"token": e.mail.token("hana@example.com")}, "")
	if r.Status != 200 {
		t.Fatalf("verify: %d %s", r.Status, r.Raw)
	}
	var signedIn authData
	r.data(&signedIn)
	if signedIn.User.Email != "hana@example.com" || !signedIn.User.EmailVerified {
		t.Fatalf("unexpected user: %+v", signedIn.User)
	}
	session := signedIn.SessionToken
	if session == "" {
		t.Fatal("a development tenant should receive the session token in the body")
	}

	// The cookie is host-locked and unreadable by page scripts.
	c := sessionCookie(r)
	if c == nil {
		t.Fatal("no session cookie was set")
	}
	if c.Value != session || !c.HttpOnly || !c.Secure ||
		c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("session cookie is not host-locked and protected: %+v", c)
	}

	// Who am I?
	r = tn.front("GET", "/v1/session", nil, session)
	if r.Status != 200 {
		t.Fatalf("session: %d %s", r.Status, r.Raw)
	}

	// The 60-second token verifies with the keys the tenant publishes.
	r = tn.front("POST", "/v1/session/token", nil, session)
	if r.Status != 200 {
		t.Fatalf("token: %d %s", r.Status, r.Raw)
	}
	var tok struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	r.data(&tok)
	keys := tn.publicKeys()
	claims, err := jwt.Verify(tok.Token, e.clock.Now(), keys)
	if err != nil {
		t.Fatalf("the signed token does not verify: %v", err)
	}
	if claims["sub"] != signedIn.User.ID || claims["tid"] != tn.ID || claims["sid"] != signedIn.Session.ID {
		t.Fatalf("unexpected claims: %v", claims)
	}
	if life := claims["exp"].(float64) - claims["iat"].(float64); life != 60 {
		t.Fatalf("token lifetime: got %v seconds, want 60", life)
	}
	// One second past its life, it is refused.
	if _, err := jwt.Verify(tok.Token, e.clock.Now().Add(61*time.Second), keys); err == nil {
		t.Fatal("an expired token verified")
	}

	// The password now works, and gives a second, separate session.
	r = tn.signIn("hana@example.com", "correct horse")
	if r.Status != 200 {
		t.Fatalf("sign in: %d %s", r.Status, r.Raw)
	}
	var second authData
	r.data(&second)
	if second.SessionToken == session {
		t.Fatal("two sign-ins shared one session")
	}

	// Signing out ends that session at once, and only that one.
	if r = tn.front("POST", "/v1/sign-out", nil, session); r.Status != 200 {
		t.Fatalf("sign out: %d %s", r.Status, r.Raw)
	}
	if r = tn.front("GET", "/v1/session", nil, session); r.Status != 401 {
		t.Fatalf("a signed-out session still works: %d", r.Status)
	}
	if r = tn.front("POST", "/v1/session/token", nil, session); r.Status != 401 {
		t.Fatalf("a signed-out session still gets tokens: %d", r.Status)
	}
	if r = tn.front("GET", "/v1/session", nil, second.SessionToken); r.Status != 200 {
		t.Fatalf("signing out one session ended another: %d", r.Status)
	}
}

// publicKeys fetches the tenant's published keys, as an application's
// backend would.
func (tn *tenant) publicKeys() func(kid string) ed25519.PublicKey {
	tn.e.t.Helper()
	r := tn.front("GET", "/v1/jwks.json", nil, "")
	if r.Status != 200 {
		tn.e.t.Fatalf("jwks: %d %s", r.Status, r.Raw)
	}
	var set struct {
		Keys []jwt.JWK `json:"keys"`
	}
	if err := json.Unmarshal(r.Raw, &set); err != nil || len(set.Keys) == 0 {
		tn.e.t.Fatalf("jwks is not a key set: %v %s", err, r.Raw)
	}
	byID := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			tn.e.t.Fatal(err)
		}
		byID[k.Kid] = pub
	}
	return func(kid string) ed25519.PublicKey { return byID[kid] }
}

// Rule: no account discovery. Signing up with an address that already
// has an account must look exactly like signing up with a new one.
func TestSignUpGivesTheSameAnswerForAnExistingAccount(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.user("hana@example.com", "first-password")

	fresh := tn.front("POST", "/v1/sign-up", obj{"email": "new@example.com", "password": "some-password"}, "")
	again := tn.front("POST", "/v1/sign-up", obj{"email": "hana@example.com", "password": "second-password"}, "")
	if fresh.Status != 202 || again.Status != 202 || !bytes.Equal(fresh.Raw, again.Raw) {
		t.Fatalf("the two answers differ:\n new:      %d %s\n existing: %d %s", fresh.Status, fresh.Raw, again.Status, again.Raw)
	}

	e.deliver()
	emails := e.mail.to("hana@example.com")
	if len(emails) != 2 {
		t.Fatalf("want 2 emails to the owner (confirmation, then notice), got %d", len(emails))
	}
	notice := emails[1]
	if !strings.Contains(notice.Body, "already have an account") || tokenInLink.MatchString(notice.Body) {
		t.Fatalf("the notice must say an account exists and carry no link:\n%s", notice.Body)
	}

	if n := tn.count(`SELECT count(*) FROM aos.users WHERE email = 'hana@example.com'`); n != 1 {
		t.Fatalf("want 1 account, got %d", n)
	}
	// The second sign-up changed nothing about the real account.
	if r := tn.signIn("hana@example.com", "second-password"); r.code() != "invalid_credentials" {
		t.Fatalf("the second sign-up's password works: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn("hana@example.com", "first-password"); r.Status != 200 {
		t.Fatalf("the owner's password stopped working: %d %s", r.Status, r.Raw)
	}
}

// user-flow REG-3: a stranger signs up first with someone else's address.
// The password of whoever confirms the link wins. The stranger, who
// cannot read the mailbox, gains nothing.
func TestUnconfirmedSignUpCannotPlantAPassword(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	const victim = "victim@example.com"

	tn.front("POST", "/v1/sign-up", obj{"email": victim, "password": "strangers-password"}, "")
	tn.front("POST", "/v1/sign-up", obj{"email": victim, "password": "owners-password"}, "")
	e.deliver()
	tokens := e.mail.tokens(victim)
	if len(tokens) != 2 {
		t.Fatalf("want 2 confirmation emails, got %d", len(tokens))
	}
	strangersLink, ownersLink := tokens[0], tokens[1]

	// The owner confirms the link from their own request.
	if r := tn.front("POST", "/v1/verify-email", obj{"token": ownersLink}, ""); r.Status != 200 {
		t.Fatalf("verify: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn(victim, "owners-password"); r.Status != 200 {
		t.Fatalf("the owner's password does not work: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn(victim, "strangers-password"); r.code() != "invalid_credentials" {
		t.Fatalf("the stranger's password works: %d %s", r.Status, r.Raw)
	}
	// The other link is dead.
	if r := tn.front("POST", "/v1/verify-email", obj{"token": strangersLink}, ""); r.code() != "invalid_token" {
		t.Fatalf("the stranger's link still works: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.passwords`); n != 1 {
		t.Fatalf("want exactly 1 stored password, got %d", n)
	}
}

func TestConfirmationLinkWorksOnceAndExpires(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")

	tn.front("POST", "/v1/sign-up", obj{"email": "a@example.com", "password": "some-password"}, "")
	e.deliver()
	link := e.mail.token("a@example.com")
	if r := tn.front("POST", "/v1/verify-email", obj{"token": link}, ""); r.Status != 200 {
		t.Fatalf("first use: %d %s", r.Status, r.Raw)
	}
	used := tn.front("POST", "/v1/verify-email", obj{"token": link}, "")
	if used.code() != "invalid_token" {
		t.Fatalf("second use: %d %s", used.Status, used.Raw)
	}

	tn.front("POST", "/v1/sign-up", obj{"email": "b@example.com", "password": "some-password"}, "")
	e.deliver()
	e.clock.advance(constant.EmailVerificationTTL + time.Minute)
	expired := tn.front("POST", "/v1/verify-email", obj{"token": e.mail.token("b@example.com")}, "")
	unknown := tn.front("POST", "/v1/verify-email", obj{"token": "no-such-token"}, "")

	// Used, expired and unknown all read the same.
	if !bytes.Equal(used.Raw, expired.Raw) || !bytes.Equal(used.Raw, unknown.Raw) {
		t.Fatalf("the answers differ:\n used:    %s\n expired: %s\n unknown: %s", used.Raw, expired.Raw, unknown.Raw)
	}
}

func TestSignInNeverRevealsWhetherAnAccountExists(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.user("hana@example.com", "right-password")

	wrong := tn.signIn("hana@example.com", "wrong-password")
	unknown := tn.signIn("nobody@example.com", "wrong-password")
	malformed := tn.signIn("not-an-email", "x")
	for name, r := range map[string]result{"wrong password": wrong, "unknown email": unknown, "malformed email": malformed} {
		if r.Status != 401 || r.code() != "invalid_credentials" {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if !bytes.Equal(wrong.Raw, unknown.Raw) || !bytes.Equal(wrong.Raw, malformed.Raw) {
		t.Fatalf("the answers differ:\n wrong:     %s\n unknown:   %s\n malformed: %s", wrong.Raw, unknown.Raw, malformed.Raw)
	}
}

// user-flow SIGN-10: after 10 failures the account is locked for 15
// minutes, the owner is told once, and a locked account answers exactly
// as a wrong password does.
func TestLockoutAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.user("hana@example.com", "right-password")

	fail := func(email string) {
		t.Helper()
		for i := 0; i < constant.LockoutLockAfter; i++ {
			if r := tn.signIn(email, "wrong-password"); r.code() != "invalid_credentials" {
				t.Fatalf("attempt %d: %d %s", i+1, r.Status, r.Raw)
			}
			// Wait out the short delays, so every attempt is counted.
			e.clock.advance(10 * time.Second)
		}
	}
	fail("hana@example.com")

	locked := tn.signIn("hana@example.com", "right-password")
	wrong := tn.signIn("nobody-else@example.com", "wrong-password")
	if locked.Status != 401 || !bytes.Equal(locked.Raw, wrong.Raw) {
		t.Fatalf("a locked account must answer as a wrong password does:\n locked: %d %s\n wrong:  %d %s",
			locked.Status, locked.Raw, wrong.Status, wrong.Raw)
	}

	e.deliver()
	notices := 0
	for _, m := range e.mail.to("hana@example.com") {
		if strings.Contains(m.Subject, "temporarily locked") {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("the owner should be told once about the lock, got %d", notices)
	}

	// An address with no account locks the same way, and nobody is emailed.
	e.clock.advance(2 * time.Minute)
	fail("nobody@example.com")
	e.deliver()
	if n := len(e.mail.to("nobody@example.com")); n != 0 {
		t.Fatalf("an email was sent to an address with no account: %d", n)
	}

	// After the lock ends, the right password works again.
	e.clock.advance(constant.LockoutDuration + time.Minute)
	if r := tn.signIn("hana@example.com", "right-password"); r.Status != 200 {
		t.Fatalf("after the lock: %d %s", r.Status, r.Raw)
	}
}

func TestDelayGrowsAfterFiveFailures(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.user("hana@example.com", "right-password")

	// Five failures cost nothing. The sixth starts a one-second pause.
	for i := 0; i < constant.LockoutDelayAfter+1; i++ {
		tn.signIn("hana@example.com", "wrong-password")
	}
	if r := tn.signIn("hana@example.com", "right-password"); r.Status != 401 {
		t.Fatalf("during the pause the right password should be refused: %d", r.Status)
	}
	e.clock.advance(2 * time.Second)
	if r := tn.signIn("hana@example.com", "right-password"); r.Status != 200 {
		t.Fatalf("after the pause: %d %s", r.Status, r.Raw)
	}
}

func TestPasswordReset(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	_, oldSession := tn.user("hana@example.com", "old-password")

	known := tn.front("POST", "/v1/password/forgot", obj{"email": "hana@example.com"}, "")
	unknown := tn.front("POST", "/v1/password/forgot", obj{"email": "nobody@example.com"}, "")
	if known.Status != 202 || !bytes.Equal(known.Raw, unknown.Raw) {
		t.Fatalf("the two answers differ:\n known:   %d %s\n unknown: %d %s", known.Status, known.Raw, unknown.Status, unknown.Raw)
	}
	e.deliver()
	if n := len(e.mail.to("nobody@example.com")); n != 0 {
		t.Fatalf("an email went to an address with no account: %d", n)
	}
	resetEmail := e.mail.to("hana@example.com")[1]
	if !strings.Contains(resetEmail.Body, "https://app.test/auth/reset-password?token=") {
		t.Fatalf("the reset email has no link:\n%s", resetEmail.Body)
	}
	link := e.mail.token("hana@example.com")

	// A weak password is refused, and the link is not used up by that.
	weak := tn.front("POST", "/v1/password/reset", obj{"token": link, "password": "short"}, "")
	if weak.Status != 400 || weak.Body.Error.Details["password"] == "" {
		t.Fatalf("weak password: %d %s", weak.Status, weak.Raw)
	}

	r := tn.front("POST", "/v1/password/reset", obj{"token": link, "password": "new-password"}, "")
	if r.Status != 200 {
		t.Fatalf("reset: %d %s", r.Status, r.Raw)
	}
	// A reset signs nobody in.
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == constant.SessionCookie && c.Value != "" {
			t.Fatal("a reset must not start a session")
		}
	}
	// It ends every session that existed.
	if r := tn.front("GET", "/v1/session", nil, oldSession); r.Status != 401 {
		t.Fatalf("an old session survived the reset: %d", r.Status)
	}
	if r := tn.signIn("hana@example.com", "old-password"); r.code() != "invalid_credentials" {
		t.Fatalf("the old password still works: %d", r.Status)
	}
	if r := tn.signIn("hana@example.com", "new-password"); r.Status != 200 {
		t.Fatalf("the new password does not work: %d %s", r.Status, r.Raw)
	}
	// The link works once.
	if r := tn.front("POST", "/v1/password/reset", obj{"token": link, "password": "another-password"}, ""); r.code() != "invalid_token" {
		t.Fatalf("the link worked twice: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	if !e.mail.has("hana@example.com", "password was changed") {
		t.Fatal("the owner was not told the password changed")
	}

	// A newer link cancels an older one, and a link expires.
	e.clock.advance(2 * time.Hour)
	tn.front("POST", "/v1/password/forgot", obj{"email": "hana@example.com"}, "")
	tn.front("POST", "/v1/password/forgot", obj{"email": "hana@example.com"}, "")
	e.deliver()
	links := e.mail.tokens("hana@example.com")
	older, newer := links[len(links)-2], links[len(links)-1]
	if r := tn.front("POST", "/v1/password/reset", obj{"token": older, "password": "third-password"}, ""); r.code() != "invalid_token" {
		t.Fatalf("an older link still works: %d", r.Status)
	}
	e.clock.advance(constant.PasswordResetTTL + time.Minute)
	if r := tn.front("POST", "/v1/password/reset", obj{"token": newer, "password": "third-password"}, ""); r.code() != "invalid_token" {
		t.Fatalf("an expired link still works: %d", r.Status)
	}
}

// One address can be sent only a few emails an hour. Over the cap the
// answer is unchanged and nothing is sent.
func TestEmailsToOneAddressAreCapped(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	tn.user("hana@example.com", "some-password") // the confirmation email is the first

	for i := 0; i < constant.EmailLimitPerHour+3; i++ {
		if r := tn.front("POST", "/v1/password/forgot", obj{"email": "hana@example.com"}, ""); r.Status != 202 {
			t.Fatalf("request %d: %d %s", i+1, r.Status, r.Raw)
		}
	}
	e.deliver()
	if n := len(e.mail.to("hana@example.com")); n != constant.EmailLimitPerHour {
		t.Fatalf("want %d emails in the hour, got %d", constant.EmailLimitPerHour, n)
	}
}

func TestSessionTimeouts(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	_, session := tn.user("hana@example.com", "some-password")
	alive := func(s string) bool { return tn.front("GET", "/v1/session", nil, s).Status == 200 }

	// Use keeps a session alive past the idle timeout.
	e.clock.advance(6 * 24 * time.Hour)
	if !alive(session) {
		t.Fatal("the session ended before its idle timeout")
	}
	e.clock.advance(6 * 24 * time.Hour)
	if !alive(session) {
		t.Fatal("using the session did not move its idle timeout forward")
	}
	// Left unused for longer than the idle timeout, it ends.
	e.clock.advance(8 * 24 * time.Hour)
	if alive(session) {
		t.Fatal("the session outlived its idle timeout")
	}

	// However much it is used, it ends at the absolute timeout.
	r := tn.signIn("hana@example.com", "some-password")
	var fresh authData
	r.data(&fresh)
	for day := 6; day < 30; day += 6 {
		e.clock.advance(6 * 24 * time.Hour)
		if !alive(fresh.SessionToken) {
			t.Fatalf("the session ended on day %d, before its absolute timeout", day)
		}
	}
	e.clock.advance(6 * 24 * time.Hour)
	if alive(fresh.SessionToken) {
		t.Fatal("the session outlived its absolute timeout")
	}
}

func TestSuspendedAccount(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	id, session := tn.user("hana@example.com", "right-password")

	tn.sql(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.principals SET status = 'suspended' WHERE id = $1`, id)
		return err
	})

	// The session stops on the very next request.
	if r := tn.front("GET", "/v1/session", nil, session); r.Status != 401 {
		t.Fatalf("a suspended user's session still works: %d", r.Status)
	}
	// "Suspended" is said only to someone who knows the password.
	if r := tn.signIn("hana@example.com", "right-password"); r.Status != 403 || r.code() != "account_suspended" {
		t.Fatalf("right password: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn("hana@example.com", "wrong-password"); r.code() != "invalid_credentials" {
		t.Fatalf("wrong password: %d %s", r.Status, r.Raw)
	}
	// No reset link is sent to a suspended account.
	before := len(e.mail.to("hana@example.com"))
	tn.front("POST", "/v1/password/forgot", obj{"email": "hana@example.com"}, "")
	e.deliver()
	if after := len(e.mail.to("hana@example.com")); after != before {
		t.Fatal("a reset link was sent to a suspended account")
	}
}

// In production the session id never appears in a response body, and the
// development header is ignored. Only the cookie carries it.
func TestProductionTenantKeepsTheSessionOutOfReachOfScripts(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme", func(r *request.CreateTenantRequest) { r.Environment = constant.EnvProduction })
	if !strings.HasPrefix(tn.PK, "pk_live_") || !strings.HasPrefix(tn.SK, "sk_live_") {
		t.Fatalf("production keys should be marked live: %s", tn.PK)
	}

	tn.front("POST", "/v1/sign-up", obj{"email": "hana@example.com", "password": "some-password"}, "")
	e.deliver()
	r := tn.front("POST", "/v1/verify-email", obj{"token": e.mail.token("hana@example.com")}, "")
	if r.Status != 200 {
		t.Fatalf("verify: %d %s", r.Status, r.Raw)
	}
	var out authData
	r.data(&out)
	if out.SessionToken != "" || bytes.Contains(r.Raw, []byte("session_token")) {
		t.Fatalf("a production answer carries the session token: %s", r.Raw)
	}
	c := sessionCookie(r)
	if c == nil || c.Value == "" {
		t.Fatal("no session cookie was set")
	}
	session := c.Value

	if r := tn.front("GET", "/v1/session", nil, session); r.Status != 401 {
		t.Fatalf("production accepted the session in a header: %d", r.Status)
	}
	if r := tn.front("GET", "/v1/session", nil, "", "Cookie", constant.SessionCookie+"="+session); r.Status != 200 {
		t.Fatalf("the cookie was not accepted: %d %s", r.Status, r.Raw)
	}
}

func TestSignUpPolicy(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	setPolicy := func(policy string, domains []string) {
		t.Helper()
		err := e.app.DB.Platform(context.Background(), func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(),
				`UPDATE aos.tenants SET signup_policy = $2, signup_domains = $3 WHERE id = $1`, tn.ID, policy, domains)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	signUp := func(email string) result {
		return tn.front("POST", "/v1/sign-up", obj{"email": email, "password": "some-password"}, "")
	}

	setPolicy(constant.SignupInviteOnly, []string{})
	if r := signUp("a@example.com"); r.Status != 403 || r.code() != "signup_closed" {
		t.Fatalf("invitation only: %d %s", r.Status, r.Raw)
	}

	setPolicy(constant.SignupDomains, []string{"example.com"})
	if r := signUp("a@elsewhere.org"); r.code() != "signup_closed" {
		t.Fatalf("a domain off the list was accepted: %d %s", r.Status, r.Raw)
	}
	if r := signUp("a@example.com"); r.Status != 202 {
		t.Fatalf("a domain on the list was refused: %d %s", r.Status, r.Raw)
	}
}

func TestRequestsFromOneAddressAreLimited(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")

	for i := 0; i < constant.AddressLimitPerMinute; i++ {
		if r := tn.signIn("nobody@example.com", "x"); r.Status == 429 {
			t.Fatalf("limited too early, at request %d", i+1)
		}
	}
	if r := tn.signIn("nobody@example.com", "x"); r.Status != 429 || r.code() != "rate_limited" {
		t.Fatalf("over the limit: %d %s", r.Status, r.Raw)
	}
	e.clock.advance(constant.AddressLimitWindow + time.Second)
	if r := tn.signIn("nobody@example.com", "x"); r.Status == 429 {
		t.Fatal("still limited after the window passed")
	}
}

// Browsers: only a listed web address may call the frontend routes, and
// a secret key is refused from any browser.
func TestBrowserOrigins(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	body := obj{"email": "nobody@example.com", "password": "x"}

	listed := tn.front("POST", "/v1/sign-in", body, "", "Origin", "https://app.test")
	if listed.Header.Get("Access-Control-Allow-Origin") != "https://app.test" ||
		listed.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("a listed origin was not allowed: %v", listed.Header)
	}

	other := tn.front("POST", "/v1/sign-in", body, "", "Origin", "https://evil.test")
	if other.Status != 403 || other.code() != "origin_not_allowed" || other.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("an unlisted origin was not refused: %d %s", other.Status, other.Raw)
	}

	preflight := e.call("OPTIONS", "/v1/sign-in", nil, "Origin", "https://app.test", "Access-Control-Request-Method", "POST")
	if preflight.Status != 204 || !strings.Contains(preflight.Header.Get("Access-Control-Allow-Headers"), constant.HeaderPublishableKey) {
		t.Fatalf("preflight: %d %v", preflight.Status, preflight.Header)
	}

	fromBrowser := tn.back("POST", "/v1/can", obj{}, "Origin", "https://app.test")
	if fromBrowser.Status != 403 || fromBrowser.code() != "origin_not_allowed" {
		t.Fatalf("a secret key was accepted from a browser: %d %s", fromBrowser.Status, fromBrowser.Raw)
	}
}

func TestBadRequestsAreRefused(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")

	weak := tn.front("POST", "/v1/sign-up", obj{"email": "not-an-email", "password": "short"}, "")
	if weak.Status != 400 || weak.code() != "invalid_input" ||
		weak.Body.Error.Details["email"] == "" || weak.Body.Error.Details["password"] == "" {
		t.Fatalf("validation: %d %s", weak.Status, weak.Raw)
	}
	unknownField := tn.front("POST", "/v1/sign-up", obj{"email": "a@example.com", "password": "some-password", "admin": true}, "")
	if unknownField.Status != 400 || unknownField.code() != "bad_request" {
		t.Fatalf("unknown field: %d %s", unknownField.Status, unknownField.Raw)
	}
	tooLarge := tn.front("POST", "/v1/sign-up", obj{"email": "a@example.com", "password": strings.Repeat("x", constant.MaxBodyBytes)}, "")
	if tooLarge.Status != 400 {
		t.Fatalf("oversized body: %d", tooLarge.Status)
	}
	if r := e.call("GET", "/healthz", nil); r.Status != 200 {
		t.Fatalf("healthz: %d", r.Status)
	}
	if r := e.call("GET", "/readyz", nil); r.Status != 200 {
		t.Fatalf("readyz: %d", r.Status)
	}
}
