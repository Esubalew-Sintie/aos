package tests

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
)

type sessionInfo struct {
	ID      string `json:"id"`
	Current bool   `json:"current"`
}

func TestDeviceListAndSignOutEverywhere(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	_, first := tn.user("hana@example.com", "some-password")
	var second, third authData
	tn.signIn("hana@example.com", "some-password").data(&second)
	tn.signIn("hana@example.com", "some-password").data(&third)

	// The device list shows every live session and marks this one.
	var list []sessionInfo
	tn.front("GET", "/v1/sessions", nil, second.SessionToken).data(&list)
	if len(list) != 3 {
		t.Fatalf("want 3 sessions, got %d", len(list))
	}
	current := 0
	for _, s := range list {
		if s.Current {
			current++
			if s.ID != second.Session.ID {
				t.Fatal("the wrong session is marked as current")
			}
		}
	}
	if current != 1 {
		t.Fatalf("want exactly 1 current session, got %d", current)
	}

	// A person can end one of their own sessions from another device.
	if r := tn.front("DELETE", "/v1/sessions/"+third.Session.ID, nil, second.SessionToken); r.Status != 200 {
		t.Fatalf("revoke: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, third.SessionToken); r.Status != 401 {
		t.Fatal("the revoked session still works")
	}
	// But not someone else's: it reads as not found.
	_, other := tn.user("sara@example.com", "some-password")
	if r := tn.front("DELETE", "/v1/sessions/"+second.Session.ID, nil, other); r.Status != 404 {
		t.Fatalf("revoking another person's session: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, second.SessionToken); r.Status != 200 {
		t.Fatal("another person's attempt ended the session")
	}

	// Sign out everywhere ends every session, this one included.
	if r := tn.front("POST", "/v1/sign-out-all", nil, second.SessionToken); r.Status != 200 {
		t.Fatalf("sign out everywhere: %d %s", r.Status, r.Raw)
	}
	for name, s := range map[string]string{"first": first, "second": second.SessionToken} {
		if r := tn.front("GET", "/v1/session", nil, s); r.Status != 401 {
			t.Fatalf("the %s session survived sign-out everywhere", name)
		}
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	_, session := tn.user("hana@example.com", "old-password")
	var other authData
	tn.signIn("hana@example.com", "old-password").data(&other)

	wrong := tn.front("POST", "/v1/password/change", obj{"current_password": "not-it", "new_password": "new-password"}, session)
	if wrong.Status != 401 || wrong.code() != "invalid_credentials" {
		t.Fatalf("wrong current password: %d %s", wrong.Status, wrong.Raw)
	}
	leaked := tn.front("POST", "/v1/password/change", obj{"current_password": "old-password", "new_password": "password123"}, session)
	if leaked.Status != 400 || leaked.Body.Error.Details["new_password"] == "" {
		t.Fatalf("a leaked password was accepted: %d %s", leaked.Status, leaked.Raw)
	}
	if r := tn.front("POST", "/v1/password/change", obj{"current_password": "old-password", "new_password": "new-password"}, session); r.Status != 200 {
		t.Fatalf("change: %d %s", r.Status, r.Raw)
	}
	// This session stays. The other one is gone.
	if r := tn.front("GET", "/v1/session", nil, session); r.Status != 200 {
		t.Fatal("changing the password ended the session that changed it")
	}
	if r := tn.front("GET", "/v1/session", nil, other.SessionToken); r.Status != 401 {
		t.Fatal("changing the password left another session alive")
	}
	if r := tn.signIn("hana@example.com", "old-password"); r.code() != "invalid_credentials" {
		t.Fatal("the old password still works")
	}
	if r := tn.signIn("hana@example.com", "new-password"); r.Status != 200 {
		t.Fatalf("the new password does not work: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	if !e.mail.has("hana@example.com", "password was changed") {
		t.Fatal("the owner was not told")
	}
}

func TestChangeEmail(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	_, session := tn.user("hana@example.com", "some-password")
	tn.user("taken@example.com", "some-password")

	// Nothing changes until the new address confirms.
	r := tn.front("POST", "/v1/email/change", obj{"new_email": "new@example.com", "password": "some-password"}, session)
	if r.Status != 202 {
		t.Fatalf("change email: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	if link := e.mail.token("new@example.com"); link == "" {
		t.Fatal("no confirmation link went to the new address")
	}
	notices := e.mail.to("hana@example.com")
	if !strings.Contains(notices[len(notices)-1].Body, "new@example.com") {
		t.Fatal("the old address was not told")
	}
	var who authData
	tn.front("GET", "/v1/session", nil, session).data(&who)
	if who.User.Email != "hana@example.com" {
		t.Fatal("the address changed before the link was confirmed")
	}

	// An address that belongs to someone else: same answer, no link,
	// and its owner is told.
	before := len(e.mail.to("taken@example.com"))
	r2 := tn.front("POST", "/v1/email/change", obj{"new_email": "taken@example.com", "password": "some-password"}, session)
	if r2.Status != 202 || !bytes.Equal(r.Raw, r2.Raw) {
		t.Fatalf("a taken address answered differently: %d %s", r2.Status, r2.Raw)
	}
	e.deliver()
	taken := e.mail.to("taken@example.com")
	if len(taken) != before+1 || tokenInLink.MatchString(taken[len(taken)-1].Body) {
		t.Fatal("a taken address received a confirmation link, or no notice")
	}

	// Confirming the link moves the account and ends every session.
	link := e.mail.token("new@example.com")
	if r := tn.front("POST", "/v1/email/confirm", obj{"token": link}, ""); r.Status != 200 {
		t.Fatalf("confirm: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, session); r.Status != 401 {
		t.Fatal("the session survived the change of address")
	}
	if r := tn.signIn("new@example.com", "some-password"); r.Status != 200 {
		t.Fatalf("sign in with the new address: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn("hana@example.com", "some-password"); r.code() != "invalid_credentials" {
		t.Fatal("the old address still signs in")
	}
	if r := tn.front("POST", "/v1/email/confirm", obj{"token": link}, ""); r.code() != "invalid_token" {
		t.Fatal("the link worked twice")
	}
}

func TestDeleteAccountAndExport(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	id, session := tn.user("hana@example.com", "some-password")
	tn.signIn("hana@example.com", "wrong-password")

	// The export holds the account, its sessions and its history.
	r := tn.front("POST", "/v1/me/export", obj{"password": "some-password"}, session)
	if r.Status != 200 {
		t.Fatalf("export: %d %s", r.Status, r.Raw)
	}
	var export struct {
		User     struct{ Email string }    `json:"user"`
		Sessions []sessionInfo             `json:"sessions"`
		Audit    []struct{ Action string } `json:"audit"`
	}
	r.data(&export)
	if export.User.Email != "hana@example.com" || len(export.Sessions) != 1 {
		t.Fatalf("unexpected export: %s", r.Raw)
	}
	actions := map[string]bool{}
	for _, a := range export.Audit {
		actions[a.Action] = true
	}
	if !actions["user.created"] || !actions["signin.failed"] {
		t.Fatalf("the export lacks the person's history: %v", actions)
	}
	if r := tn.front("POST", "/v1/me/export", obj{"password": "wrong"}, session); r.Status != 401 {
		t.Fatal("an export was given without the right password")
	}

	// Deleting needs the password, then stops the account at once.
	if r := tn.front("DELETE", "/v1/me", obj{"password": "wrong"}, session); r.Status != 401 {
		t.Fatal("the account was deleted without the right password")
	}
	if r := tn.front("DELETE", "/v1/me", obj{"password": "some-password"}, session); r.Status != 200 {
		t.Fatalf("delete: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, session); r.Status != 401 {
		t.Fatal("the session survived the deletion")
	}
	if r := tn.signIn("hana@example.com", "some-password"); r.Status != 403 {
		t.Fatalf("a deleted account signed in: %d", r.Status)
	}
	if n := tn.count(`SELECT count(*) FROM aos.principals WHERE id = $1 AND status = 'deleted' AND purge_after > now()`, id); n != 1 {
		t.Fatal("the account is not marked for erasure after the grace period")
	}
	// The address stays taken during the grace period.
	if n := tn.count(`SELECT count(*) FROM aos.users WHERE email = 'hana@example.com'`); n != 1 {
		t.Fatal("the user row vanished at once")
	}
}

func TestAdminCreatesAUserWithASetupLink(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	w := obj{"email": "new@example.com", "name": "New Person", "role": "Owner", "resource": obj{"type": "tenant", "id": "root"}}

	r := tn.back("POST", "/v1/users", w)
	if r.Status != 201 {
		t.Fatalf("create: %d %s", r.Status, r.Raw)
	}
	var created struct {
		ID            string `json:"id"`
		EmailVerified bool   `json:"email_verified"`
	}
	r.data(&created)
	if created.EmailVerified {
		t.Fatal("an admin-created address counts as verified before the link is used")
	}
	// The admin learns that an address is taken.
	if r := tn.back("POST", "/v1/users", obj{"email": "new@example.com"}); r.Status != 409 {
		t.Fatalf("a second account with the same address: %d %s", r.Status, r.Raw)
	}
	// The answer carries no token, and no password exists yet.
	if tokenInLink.Match(r.Raw) || tn.count(`SELECT count(*) FROM aos.passwords`) != 0 {
		t.Fatal("a secret leaked into the answer, or a password was set")
	}
	if r := tn.signIn("new@example.com", "anything-at-all"); r.code() != "invalid_credentials" {
		t.Fatal("an account with no password signed in")
	}

	// The person uses the link and chooses a password.
	e.deliver()
	link := e.mail.token("new@example.com")
	if r := tn.front("POST", "/v1/account/setup", obj{"token": link, "password": "chosen-password"}, ""); r.Status != 200 {
		t.Fatalf("setup: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/account/setup", obj{"token": link, "password": "another-one"}, ""); r.code() != "invalid_token" {
		t.Fatal("the setup link worked twice")
	}
	if r := tn.signIn("new@example.com", "chosen-password"); r.Status != 200 {
		t.Fatalf("sign in after setup: %d %s", r.Status, r.Raw)
	}
	// The role given at creation is in force.
	allowed, _ := (&world{e: e, tn: tn}).can(created.ID, "anything.at_all", "tenant", "root")
	if !allowed {
		t.Fatal("the role given at creation is not in force")
	}
	// A setup link expires.
	tn.back("POST", "/v1/users", obj{"email": "late@example.com"})
	e.deliver()
	e.clock.advance(constant.AccountSetupTTL + time.Minute)
	if r := tn.front("POST", "/v1/account/setup", obj{"token": e.mail.token("late@example.com"), "password": "chosen-password"}, ""); r.code() != "invalid_token" {
		t.Fatal("an expired setup link worked")
	}
}

func TestAdminManagesUsers(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	ids := map[string]string{}
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		id, _ := tn.user(name+"@example.com", "some-password")
		ids[name] = id
	}

	// Paging walks every user once.
	seen := []string{}
	cursor := ""
	for i := 0; i < 10; i++ {
		var page struct {
			Users      []struct{ Email string } `json:"users"`
			NextCursor string                   `json:"next_cursor"`
		}
		tn.back("GET", "/v1/users?limit=2&cursor="+cursor, nil).data(&page)
		for _, u := range page.Users {
			seen = append(seen, u.Email)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if strings.Join(seen, ",") != "a@example.com,b@example.com,c@example.com,d@example.com,e@example.com" {
		t.Fatalf("paging gave %v", seen)
	}
	if r := tn.back("GET", "/v1/users?cursor=garbage", nil); r.Status != 400 {
		t.Fatalf("a bad cursor: %d", r.Status)
	}

	// Suspension signs the person out at once; reinstatement does not sign them back in.
	var s authData
	tn.signIn("a@example.com", "some-password").data(&s)
	if r := tn.back("POST", "/v1/users/"+ids["a"]+"/suspend", obj{"reason": "fraud review"}); r.Status != 200 {
		t.Fatalf("suspend: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, s.SessionToken); r.Status != 401 {
		t.Fatal("a suspended user's session still works")
	}
	if r := tn.back("POST", "/v1/users/"+ids["a"]+"/suspend", obj{}); r.Status != 400 {
		t.Fatal("a suspension without a reason was accepted")
	}
	var got struct{ Status string }
	tn.back("GET", "/v1/users/"+ids["a"], nil).data(&got)
	if got.Status != "suspended" {
		t.Fatalf("status after suspension: %q", got.Status)
	}
	if r := tn.back("POST", "/v1/users/"+ids["a"]+"/reinstate", nil); r.Status != 200 {
		t.Fatalf("reinstate: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, s.SessionToken); r.Status != 401 {
		t.Fatal("reinstatement brought a session back")
	}
	if r := tn.signIn("a@example.com", "some-password"); r.Status != 200 {
		t.Fatal("a reinstated user cannot sign in")
	}

	// Deletion by an admin.
	if r := tn.back("DELETE", "/v1/users/"+ids["b"], nil); r.Status != 200 {
		t.Fatalf("delete: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("DELETE", "/v1/users/"+ids["b"], nil); r.Status != 404 {
		t.Fatalf("deleting twice: %d", r.Status)
	}
	if r := tn.back("GET", "/v1/users/00000000-0000-0000-0000-000000000000", nil); r.Status != 404 {
		t.Fatalf("an unknown user: %d", r.Status)
	}
	// Another tenant's user does not exist here.
	other := e.tenant("beta")
	otherID, _ := other.user("x@example.com", "some-password")
	if r := tn.back("GET", "/v1/users/"+otherID, nil); r.Status != 404 {
		t.Fatalf("another tenant's user was found: %d", r.Status)
	}
	_ = context.Background()
	_ = pgx.ErrNoRows
}

func TestLeakedPasswordsAreRefused(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	for _, pw := range []string{"password", "Password", "12345678", "qwertyuiop", "iloveyou"} {
		r := tn.front("POST", "/v1/sign-up", obj{"email": "a@example.com", "password": pw}, "")
		if r.Status != 400 || r.Body.Error.Details["password"] == "" {
			t.Errorf("%q was accepted: %d %s", pw, r.Status, r.Raw)
		}
	}
	if r := tn.front("POST", "/v1/sign-up", obj{"email": "a@example.com", "password": "correct horse battery"}, ""); r.Status != 202 {
		t.Fatalf("a good password was refused: %d %s", r.Status, r.Raw)
	}
}
