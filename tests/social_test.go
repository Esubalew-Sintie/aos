package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/flash-software-technology/aos/platform/oidc"
)

type socialStart struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// socialSignIn runs the whole round trip for one person at the provider.
func socialSignIn(t *testing.T, tn *tenant, fp *oidc.FakeProvider, session string, claims map[string]any) result {
	t.Helper()
	// Each round trip is a minute apart, as it would be for a person.
	tn.e.clock.advance(time.Minute)
	r := tn.front("POST", "/v1/oauth/oidc/start", obj{"redirect_uri": "https://app.test/auth/callback"}, session)
	if r.Status != 200 {
		t.Fatalf("start: %d %s", r.Status, r.Raw)
	}
	var start socialStart
	r.data(&start)
	code, state, err := fp.Authorize(start.AuthorizationURL, claims)
	if err != nil {
		t.Fatal(err)
	}
	if state != start.State {
		t.Fatalf("state: %q vs %q", state, start.State)
	}
	return tn.front("POST", "/v1/oauth/oidc/finish", obj{"state": state, "code": code}, "")
}

func TestSocialSignInThroughOpenIDConnect(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	fp, err := oidc.NewFakeProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()

	// The backend sets the provider up. The secret is never shown again.
	r := tn.back("PUT", "/v1/oauth-providers", obj{"provider": "oidc", "client_id": fp.ClientID, "client_secret": fp.Secret, "issuer": fp.Server.URL})
	if r.Status != 200 || strings.Contains(string(r.Raw), fp.Secret) {
		t.Fatalf("put provider: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.oauth_providers WHERE client_secret_encrypted = $1`, []byte(fp.Secret)); n != 0 {
		t.Fatal("the client secret is stored in clear")
	}
	if r := tn.back("PUT", "/v1/oauth-providers", obj{"provider": "oidc", "client_id": "x", "client_secret": "y", "issuer": "https://127.0.0.1:1"}); r.Status != 400 {
		t.Fatalf("unreachable issuer: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("PUT", "/v1/oauth-providers", obj{"provider": "facebook", "client_id": "x", "client_secret": "y"}); r.Status != 400 {
		t.Fatalf("unknown preset: %d", r.Status)
	}
	// The provider may only send the browser back to the application.
	if r := tn.front("POST", "/v1/oauth/oidc/start", obj{"redirect_uri": "https://evil.test/cb"}, ""); r.Status != 400 {
		t.Fatalf("foreign redirect: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/oauth/google/start", obj{"redirect_uri": "https://app.test/cb"}, ""); r.code() != "provider_not_found" {
		t.Fatalf("provider not set up: %d %s", r.Status, r.Raw)
	}

	// A new person: the account is made, with the address verified
	// because the provider vouched for it.
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-new", "email": "New@Example.com", "email_verified": true, "name": "Newcomer"})
	if r.Status != 200 {
		t.Fatalf("first social sign-in: %d %s", r.Status, r.Raw)
	}
	var signedIn authData
	r.data(&signedIn)
	if signedIn.User.Email != "new@example.com" || !signedIn.User.EmailVerified || signedIn.SessionToken == "" {
		t.Fatalf("signed in: %+v", signedIn.User)
	}
	newID := signedIn.User.ID
	// The same provider account again: the same user.
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-new", "email": "changed@example.com", "email_verified": true})
	r.data(&signedIn)
	if signedIn.User.ID != newID {
		t.Fatal("a second sign-in made a second user")
	}
	// A state works once.
	start := tn.front("POST", "/v1/oauth/oidc/start", obj{"redirect_uri": "https://app.test/cb"}, "")
	var st socialStart
	start.data(&st)
	code, _, _ := fp.Authorize(st.AuthorizationURL, map[string]any{"sub": "u-new"})
	tn.front("POST", "/v1/oauth/oidc/finish", obj{"state": st.State, "code": code}, "")
	if r := tn.front("POST", "/v1/oauth/oidc/finish", obj{"state": st.State, "code": code}, ""); r.code() != "social_failed" {
		t.Fatalf("reused state: %d %s", r.Status, r.Raw)
	}

	// An existing, verified account with the same address is linked.
	hanaID, _ := tn.user("hana@example.com", "some-password")
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-hana", "email": "hana@example.com", "email_verified": true})
	r.data(&signedIn)
	if r.Status != 200 || signedIn.User.ID != hanaID {
		t.Fatalf("link by address: %d %s", r.Status, r.Raw)
	}
	var identities []struct {
		Provider string `json:"provider"`
		Subject  string `json:"subject"`
	}
	tn.front("GET", "/v1/me/identities", nil, signedIn.SessionToken).data(&identities)
	if len(identities) != 1 || identities[0].Subject != "u-hana" {
		t.Fatalf("identities: %+v", identities)
	}
	// Hana has a password, so she may unlink. Newcomer has nothing else.
	if r := tn.front("DELETE", "/v1/me/identities/oidc", nil, signedIn.SessionToken); r.Status != 200 {
		t.Fatalf("unlink: %d %s", r.Status, r.Raw)
	}
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-new", "email": "new@example.com", "email_verified": true})
	r.data(&signedIn)
	if r := tn.front("DELETE", "/v1/me/identities/oidc", nil, signedIn.SessionToken); r.code() != "last_way_in" {
		t.Fatalf("unlink the last way in: %d %s", r.Status, r.Raw)
	}

	// The provider does not vouch for the address of an existing account:
	// nothing is linked, nothing is made.
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-impostor", "email": "hana@example.com", "email_verified": false})
	if r.code() != "account_exists_unverified" {
		t.Fatalf("unverified address: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.external_identities WHERE subject = 'u-impostor'`); n != 0 {
		t.Fatal("an unverified address was linked")
	}

	// Someone signed up with an address but never confirmed it. The
	// provider's word wins and their pending password is dropped.
	tn.front("POST", "/v1/sign-up", obj{"email": "pending@example.com", "password": "squatter-password"}, "")
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-pending", "email": "pending@example.com", "email_verified": true})
	if r.Status != 200 {
		t.Fatalf("over an unconfirmed sign-up: %d %s", r.Status, r.Raw)
	}
	e.deliver()
	if r := tn.front("POST", "/v1/verify-email", obj{"token": e.mail.token("pending@example.com")}, ""); r.Status == 200 {
		t.Fatal("the squatter's link still worked")
	}
	if r := tn.signIn("pending@example.com", "squatter-password"); r.Status == 200 {
		t.Fatal("the squatter's password works")
	}

	// Linking from the profile: Sara, signed in, connects the provider.
	_, sara := tn.user("sara@example.com", "some-password")
	saraID := userID(t, tn, "sara@example.com")
	r = socialSignIn(t, tn, fp, sara, map[string]any{"sub": "u-sara", "email": "other@example.com", "email_verified": true})
	if r.Status != 200 || strings.Contains(string(r.Raw), "session_token") {
		t.Fatalf("link from profile: %d %s", r.Status, r.Raw)
	}
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-sara", "email": "other@example.com", "email_verified": true})
	r.data(&signedIn)
	if signedIn.User.ID != saraID {
		t.Fatal("the linked provider account did not sign Sara in")
	}
	// A provider account linked to one person cannot be linked to another.
	r = socialSignIn(t, tn, fp, signedIn.SessionToken, map[string]any{"sub": "u-new", "email": "new@example.com", "email_verified": true})
	if r.code() != "identity_taken" {
		t.Fatalf("link someone else's identity: %d %s", r.Status, r.Raw)
	}

	// The second factor applies to social sign-in too.
	app, _ := enrollTOTP(t, tn, signedIn.SessionToken)
	r = socialSignIn(t, tn, fp, "", map[string]any{"sub": "u-sara"})
	var pending pendingData
	r.data(&pending)
	if !pending.SecondFactorRequired {
		t.Fatalf("social sign-in skipped the second factor: %s", r.Raw)
	}
	if r := tn.front("POST", "/v1/second-factor", obj{"pending_token": pending.PendingToken, "method": "totp", "code": app.code()}, ""); r.Status != 200 {
		t.Fatalf("second factor after social: %d %s", r.Status, r.Raw)
	}

	// Turning the provider off stops it.
	tn.back("DELETE", "/v1/oauth-providers/oidc", nil)
	if r := tn.front("POST", "/v1/oauth/oidc/start", obj{"redirect_uri": "https://app.test/cb"}, ""); r.code() != "provider_not_found" {
		t.Fatalf("removed provider: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action IN ('identity.linked', 'identity.unlinked')`); n < 4 {
		t.Fatalf("audit entries: %d", n)
	}
}
