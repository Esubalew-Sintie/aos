package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/flash-softeware/aos/internal/constant"
)

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	SessionToken string `json:"session_token"`
	Session      struct {
		ID string `json:"id"`
	} `json:"session"`
}

func TestTokenSessionsForMobileApps(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	tn.user("hana@example.com", "some-password")

	r := tn.front("POST", "/v1/sign-in", obj{"email": "hana@example.com", "password": "some-password", "session_kind": "token"}, "")
	if r.Status != 200 {
		t.Fatalf("token sign-in: %d %s", r.Status, r.Raw)
	}
	var pair tokenPair
	r.data(&pair)
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.ExpiresIn != 600 || pair.SessionToken != "" {
		t.Fatalf("pair: %+v", pair)
	}
	if sessionCookie(r) != nil {
		t.Fatal("a token session set a cookie")
	}
	if !strings.Contains(claims(t, pair.AccessToken), `"typ":"access"`) || !strings.Contains(claims(t, pair.AccessToken), `"sid":"`+pair.Session.ID+`"`) {
		t.Fatalf("access token claims: %s", claims(t, pair.AccessToken))
	}
	// The access token opens the frontend routes as a bearer token.
	bearer := func(token string) []string { return []string{"Authorization", "Bearer " + token} }
	if r := tn.front("GET", "/v1/session", nil, "", bearer(pair.AccessToken)...); r.Status != 200 {
		t.Fatalf("session with the access token: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, "", bearer(pair.AccessToken[:len(pair.AccessToken)-2]+"xx")...); r.Status != 401 {
		t.Fatalf("a tampered access token was accepted: %d", r.Status)
	}
	// It expires; the refresh token brings a new pair.
	e.clock.advance(11 * time.Minute)
	if r := tn.front("GET", "/v1/session", nil, "", bearer(pair.AccessToken)...); r.Status != 401 {
		t.Fatalf("an expired access token was accepted: %d", r.Status)
	}
	r = tn.front("POST", "/v1/token/refresh", obj{"refresh_token": pair.RefreshToken}, "")
	if r.Status != 200 {
		t.Fatalf("refresh: %d %s", r.Status, r.Raw)
	}
	var second tokenPair
	r.data(&second)
	if second.AccessToken == pair.AccessToken || second.RefreshToken == pair.RefreshToken || second.Session.ID != pair.Session.ID {
		t.Fatalf("second pair: %+v", second)
	}
	if r := tn.front("GET", "/v1/session", nil, "", bearer(second.AccessToken)...); r.Status != 200 {
		t.Fatalf("session with the new access token: %d %s", r.Status, r.Raw)
	}
	// Reuse of the spent refresh token ends the whole family and the session.
	r = tn.front("POST", "/v1/token/refresh", obj{"refresh_token": pair.RefreshToken}, "")
	if r.code() != "token_reused" {
		t.Fatalf("reuse: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/token/refresh", obj{"refresh_token": second.RefreshToken}, ""); r.Status != 401 {
		t.Fatalf("the family survived reuse: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, "", bearer(second.AccessToken)...); r.Status != 401 {
		t.Fatalf("the session survived reuse: %d", r.Status)
	}
	e.deliver()
	if !e.mail.has("hana@example.com", "used twice") {
		t.Fatal("the person was not told")
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action = 'token.reuse_detected'`); n != 1 {
		t.Fatalf("audit of the reuse: %d", n)
	}
	// Sign-out with a bearer token ends the family too.
	tn.front("POST", "/v1/sign-in", obj{"email": "hana@example.com", "password": "some-password", "session_kind": "token"}, "").data(&pair)
	if r := tn.front("POST", "/v1/sign-out", nil, "", bearer(pair.AccessToken)...); r.Status != 200 {
		t.Fatalf("sign out: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/token/refresh", obj{"refresh_token": pair.RefreshToken}, ""); r.Status != 401 {
		t.Fatalf("refresh after sign-out: %d %s", r.Status, r.Raw)
	}
	// The second factor applies to token sessions as well.
	_, plain := tn.signInSession("hana@example.com", "some-password")
	app, _ := enrollTOTP(t, tn, plain)
	var pending pendingData
	tn.front("POST", "/v1/sign-in", obj{"email": "hana@example.com", "password": "some-password", "session_kind": "token"}, "").data(&pending)
	if !pending.SecondFactorRequired {
		t.Fatal("a token sign-in skipped the second factor")
	}
	r = tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, "")
	pair = tokenPair{}
	r.data(&pair)
	if pair.AccessToken == "" || pair.RefreshToken == "" || sessionCookie(r) != nil {
		t.Fatalf("token pair after the second factor: %s", r.Raw)
	}
	// Sessions of kind token are listed like any other.
	if n := tn.count(`SELECT count(*) FROM aos.sessions WHERE kind = $1`, constant.SessionToken); n != 3 {
		t.Fatalf("token sessions: %d", n)
	}
}
