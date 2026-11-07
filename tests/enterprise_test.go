package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flash-softeware/aos/platform/oidc"
)

type ssoStart struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// ssoRoundTrip sends the browser to the company's provider and back.
func ssoRoundTrip(t *testing.T, tn *tenant, fp *oidc.FakeProvider, startPath string, body obj, claims map[string]any) result {
	t.Helper()
	tn.e.clock.advance(time.Minute)
	r := tn.front("POST", startPath, body, "")
	if r.Status != 200 {
		t.Fatalf("start %s: %d %s", startPath, r.Status, r.Raw)
	}
	var st ssoStart
	r.data(&st)
	code, state, err := fp.Authorize(st.AuthorizationURL, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tn.front("POST", "/v1/sso/finish", obj{"state": state, "code": code}, "")
}

func TestEnterpriseSignInAndDirectorySync(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	tn.back("PUT", "/v1/roles", obj{"name": "Engineer", "permissions": []string{"code.*"}})
	tn.back("PUT", "/v1/roles", obj{"name": "Viewer", "permissions": []string{"code.read"}})
	org := createOrg(t, tn, hana, "Bank")
	fp, err := oidc.NewFakeProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()

	// The organization admin makes a connection and a setup link.
	_, outsider := tn.user("x@example.com", "some-password")
	if r := tn.front("POST", "/v1/sso/connections", obj{"organization_id": org.ID}, outsider); r.Status != 403 {
		t.Fatalf("outsider makes a connection: %d %s", r.Status, r.Raw)
	}
	r := tn.front("POST", "/v1/sso/connections", obj{"organization_id": org.ID, "name": "Bank Okta"}, hana)
	if r.Status != 201 {
		t.Fatalf("create connection: %d %s", r.Status, r.Raw)
	}
	var link struct {
		Token string `json:"token"`
		Link  string `json:"link"`
	}
	r.data(&link)
	setup := "/v1/sso/setup/" + link.Token
	var view struct {
		RedirectURI string `json:"redirect_uri"`
		Status      string `json:"status"`
	}
	tn.front("GET", setup, nil, "").data(&view)
	if view.RedirectURI != "https://app.test/auth/sso/callback" || view.Status != "draft" || !strings.Contains(link.Link, "/auth/sso/setup?token=") {
		t.Fatalf("setup view: %+v %s", view, link.Link)
	}
	if r := tn.front("GET", "/v1/sso/setup/wrong", nil, ""); r.code() != "setup_link_invalid" {
		t.Fatalf("wrong link: %d %s", r.Status, r.Raw)
	}

	// The IT admin pastes the provider's values, maps groups, verifies the domain.
	if r := tn.front("PUT", setup+"/settings", obj{"issuer": fp.Server.URL, "client_id": fp.ClientID, "client_secret": fp.Secret}, ""); r.Status != 200 {
		t.Fatalf("settings: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.sso_connections WHERE oidc_client_secret_encrypted = $1`, []byte(fp.Secret)); n != 0 {
		t.Fatal("the provider secret is stored in clear")
	}
	if r := tn.front("PUT", setup+"/mappings", obj{"mappings": []obj{{"group": "eng", "role": "Engineer"}}, "default_role": "Viewer"}, ""); r.Status != 200 {
		t.Fatalf("mappings: %d %s", r.Status, r.Raw)
	}
	r = tn.front("POST", setup+"/domains", obj{"domain": "Bank.Example"}, "")
	var domain struct {
		ID          string `json:"id"`
		Verified    bool   `json:"verified"`
		RecordName  string `json:"record_name"`
		RecordValue string `json:"record_value"`
	}
	r.data(&domain)
	if domain.RecordName != "_aos-verify.bank.example" || !strings.HasPrefix(domain.RecordValue, "aos-verify=") {
		t.Fatalf("domain: %+v", domain)
	}
	tn.front("POST", setup+"/domains/"+domain.ID+"/verify", nil, "").data(&domain)
	if domain.Verified {
		t.Fatal("verified without the DNS record")
	}
	e.dns.set(domain.RecordName, "unrelated", domain.RecordValue)
	tn.front("POST", setup+"/domains/"+domain.ID+"/verify", nil, "").data(&domain)
	if !domain.Verified {
		t.Fatal("not verified with the DNS record")
	}
	// No activation before a successful test.
	if r := tn.front("POST", setup+"/activate", nil, ""); r.code() != "connection_incomplete" {
		t.Fatalf("activate before test: %d %s", r.Status, r.Raw)
	}
	r = ssoRoundTrip(t, tn, fp, setup+"/test", obj{"redirect_uri": "https://app.test/auth/sso/callback"},
		map[string]any{"sub": "okta-dana", "email": "dana@bank.example", "name": "Dana", "groups": []string{"eng"}})
	var test struct {
		TestResult map[string]any `json:"test_result"`
	}
	r.data(&test)
	if r.Status != 200 || test.TestResult["email"] != "dana@bank.example" || sessionCookie(r) != nil {
		t.Fatalf("test sign-in: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.users WHERE email = 'dana@bank.example'`); n != 0 {
		t.Fatal("a test sign-in made an account")
	}
	if r := tn.front("POST", setup+"/activate", nil, ""); r.Status != 200 {
		t.Fatalf("activate: %d %s", r.Status, r.Raw)
	}

	// Dana signs in with her company account. The account is made, the
	// group becomes a role, and she works in the bank's organization.
	start := obj{"email": "dana@bank.example", "redirect_uri": "https://app.test/auth/sso/callback"}
	r = ssoRoundTrip(t, tn, fp, "/v1/sso/start", start, map[string]any{"sub": "okta-dana", "email": "dana@bank.example", "name": "Dana", "groups": []string{"eng"}})
	if r.Status != 200 {
		t.Fatalf("enterprise sign-in: %d %s", r.Status, r.Raw)
	}
	var dana struct {
		User struct {
			ID            string `json:"id"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"user"`
		SessionToken string `json:"session_token"`
		Session      struct {
			ActiveOrganizationID string `json:"active_organization_id"`
		} `json:"session"`
	}
	r.data(&dana)
	if !dana.User.EmailVerified || dana.Session.ActiveOrganizationID != org.ID || dana.SessionToken == "" {
		t.Fatalf("dana: %s", r.Raw)
	}
	if ok, _ := can(t, tn, dana.User.ID, "code.write", "organization", org.Slug); !ok {
		t.Fatal("the mapped group gave no role")
	}
	if r := tn.front("POST", "/v1/sso/start", obj{"email": "dana@elsewhere.test", "redirect_uri": "https://app.test/cb"}, ""); r.code() != "no_enterprise_connection" {
		t.Fatalf("unbound domain: %d %s", r.Status, r.Raw)
	}
	// Leaving the group at the company takes the role away at next sign-in;
	// the default role stays.
	r = ssoRoundTrip(t, tn, fp, "/v1/sso/start", start, map[string]any{"sub": "okta-dana", "email": "dana@bank.example", "groups": []string{}})
	if r.Status != 200 {
		t.Fatalf("second sign-in: %d %s", r.Status, r.Raw)
	}
	if ok, _ := can(t, tn, dana.User.ID, "code.write", "organization", org.Slug); ok {
		t.Fatal("the old group role survived")
	}
	if ok, _ := can(t, tn, dana.User.ID, "code.read", "organization", org.Slug); !ok {
		t.Fatal("the default role is missing")
	}

	// An existing account in the verified domain is linked, not duplicated.
	eveID, _ := tn.user("eve@bank.example", "eve-password")
	r = ssoRoundTrip(t, tn, fp, "/v1/sso/start", obj{"email": "eve@bank.example", "redirect_uri": "https://app.test/cb"}, map[string]any{"sub": "okta-eve", "email": "eve@bank.example"})
	var eve authData
	r.data(&eve)
	if r.Status != 200 || eve.User.ID != eveID {
		t.Fatalf("link eve: %d %s", r.Status, r.Raw)
	}

	// Requiring enterprise sign-in: passwords stop for the domain, except
	// the break-glass owner.
	if r := tn.front("PATCH", "/v1/organizations/"+org.ID+"/policies", obj{"enforce_sso": true}, outsider); r.Status != 403 {
		t.Fatalf("outsider sets policies: %d", r.Status)
	}
	if r := tn.front("PATCH", "/v1/organizations/"+org.ID+"/policies", obj{"enforce_sso": true}, hana); r.Status != 200 {
		t.Fatalf("enforce sso: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn("eve@bank.example", "eve-password"); r.code() != "sso_required" {
		t.Fatalf("password under enforced sso: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("PATCH", "/v1/organizations/"+org.ID+"/policies", obj{"break_glass_principal_id": eveID}, hana); r.Status != 200 {
		t.Fatalf("break glass: %d %s", r.Status, r.Raw)
	}
	if r := tn.signIn("eve@bank.example", "eve-password"); r.Status != 200 {
		t.Fatalf("break-glass sign-in: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.audit_log WHERE action = 'signin.break_glass'`); n != 1 {
		t.Fatalf("break-glass audit: %d", n)
	}

	// Directory sync: a token for the identity provider.
	r = tn.front("POST", setup+"/directory", obj{"default_role": "Viewer"}, "")
	var dir struct {
		Token   string `json:"token"`
		SCIMURL string `json:"scim_url"`
	}
	r.data(&dir)
	if dir.Token == "" || dir.SCIMURL != "https://aos.test/scim/v2" {
		t.Fatalf("directory: %d %s", r.Status, r.Raw)
	}
	scim := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		r := e.call(method, path, body, "Authorization", "Bearer "+dir.Token)
		var out map[string]any
		_ = json.Unmarshal(r.Raw, &out)
		return r.Status, out
	}
	if r := e.call("GET", "/scim/v2/Users", nil, "Authorization", "Bearer wrong"); r.Status != 401 {
		t.Fatalf("wrong sync token: %d", r.Status)
	}
	status, sam := scim("POST", "/scim/v2/Users", obj{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "sam@bank.example", "externalId": "okta-sam", "name": obj{"givenName": "Sam", "familyName": "Lee"}, "active": true})
	if status != 201 || sam["id"] == nil {
		t.Fatalf("scim create: %d %v", status, sam)
	}
	samID := sam["id"].(string)
	if status, _ := scim("POST", "/scim/v2/Users", obj{"userName": "sam@bank.example", "externalId": "okta-sam"}); status != 409 {
		t.Fatalf("duplicate: %d", status)
	}
	if ok, _ := can(t, tn, samID, "code.read", "organization", org.Slug); !ok {
		t.Fatal("a synced user has no default role")
	}
	status, found := scim("GET", "/scim/v2/Users?filter="+strings.ReplaceAll(`userName eq "sam@bank.example"`, " ", "%20"), nil)
	if status != 200 || found["totalResults"].(float64) != 1 {
		t.Fatalf("filter: %d %v", status, found)
	}
	// Groups follow the directory.
	status, group := scim("POST", "/scim/v2/Groups", obj{"displayName": "Auditors", "externalId": "g1", "members": []obj{{"value": samID}}})
	if status != 201 || len(group["members"].([]any)) != 1 {
		t.Fatalf("scim group: %d %v", status, group)
	}
	status, group = scim("PATCH", "/scim/v2/Groups/"+group["id"].(string), obj{"Operations": []obj{{"op": "remove", "path": `members[value eq "` + samID + `"]`}}})
	if status != 200 || len(group["members"].([]any)) != 0 {
		t.Fatalf("scim group patch: %d %v", status, group)
	}
	// Deactivation removes access in this organization at once; the account stays.
	status, _ = scim("PATCH", "/scim/v2/Users/"+samID, obj{"Operations": []obj{{"op": "replace", "value": obj{"active": false}}}})
	if status != 200 {
		t.Fatalf("deactivate: %d", status)
	}
	if ok, _ := can(t, tn, samID, "code.read", "organization", org.Slug); ok {
		t.Fatal("a deactivated user kept access")
	}
	if n := tn.count(`SELECT count(*) FROM aos.users WHERE principal_id = $1`, samID); n != 1 {
		t.Fatal("the account was deleted")
	}
	if status, _ := scim("PATCH", "/scim/v2/Users/"+samID, obj{"Operations": []obj{{"op": "replace", "path": "active", "value": true}}}); status != 200 {
		t.Fatalf("reactivate: %d", status)
	}
	if ok, _ := can(t, tn, samID, "code.read", "organization", org.Slug); !ok {
		t.Fatal("reactivation gave no access")
	}
	if status, _ := scim("DELETE", "/scim/v2/Users/"+samID, nil); status != 204 {
		t.Fatalf("scim delete: %d", status)
	}
	if status, _ := scim("GET", "/scim/v2/Users/"+samID, nil); status != 404 {
		t.Fatalf("deleted user: %d", status)
	}
}

func TestOrganizationPolicies(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	org := createOrg(t, tn, hana, "Bank")

	// A second factor required: switching in needs one.
	if r := tn.front("PATCH", "/v1/organizations/"+org.ID+"/policies", obj{"mfa_required": true, "session_max_seconds": 3600}, hana); r.Status != 200 {
		t.Fatalf("policies: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("POST", "/v1/organizations/"+org.ID+"/switch", nil, hana); r.code() != "second_factor_required" {
		t.Fatalf("switch without a factor: %d %s", r.Status, r.Raw)
	}
	app, _ := enrollTOTP(t, tn, hana)
	_ = app
	if r := tn.front("POST", "/v1/organizations/"+org.ID+"/switch", nil, hana); r.Status != 200 {
		t.Fatalf("switch with a factor: %d %s", r.Status, r.Raw)
	}
	var s struct {
		Session struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"session"`
	}
	tn.front("GET", "/v1/session", nil, hana).data(&s)
	if s.Session.ExpiresAt.After(e.clock.Now().Add(61 * time.Minute)) {
		t.Fatalf("the session length was not capped: %v", s.Session.ExpiresAt)
	}
	// An address allow-list applies to every request in the organization.
	if r := tn.back("PATCH", "/v1/admin/organizations/"+org.ID+"/policies", obj{"ip_allowlist": []string{"10.0.0.0/8"}}); r.Status != 200 {
		t.Fatalf("allow-list: %d %s", r.Status, r.Raw)
	}
	if r := tn.front("GET", "/v1/session", nil, hana); r.code() != "address_not_allowed" {
		t.Fatalf("request from outside the allow-list: %d %s", r.Status, r.Raw)
	}
	tn.back("PATCH", "/v1/admin/organizations/"+org.ID+"/policies", obj{"ip_allowlist": []string{"127.0.0.1"}})
	if r := tn.front("GET", "/v1/session", nil, hana); r.Status != 200 {
		t.Fatalf("request from an allowed address: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("PATCH", "/v1/admin/organizations/"+org.ID+"/policies", obj{"enforce_sso": true}); r.Status != 400 {
		t.Fatalf("enforce sso without a connection: %d", r.Status)
	}
	if r := tn.back("PATCH", "/v1/admin/organizations/"+org.ID+"/policies", obj{"ip_allowlist": []string{"not-an-address"}}); r.Status != 400 {
		t.Fatalf("bad allow-list: %d", r.Status)
	}
}

func TestGrantConditions(t *testing.T) {
	w := newWorld(t)
	tn := w.tn
	w.ok(tn.back("PUT", "/v1/roles", obj{"name": "Small refunds", "permissions": []string{"payment.refund"}}))
	if r := tn.back("POST", "/v1/grants", obj{"principal_id": w.daniel, "role": "Small refunds", "resource": obj{"type": "branch", "id": "branch-1"}, "condition": "request.amount <="}); r.Status != 400 {
		t.Fatalf("a broken condition was accepted: %d %s", r.Status, r.Raw)
	}
	w.grant(w.daniel, "Small refunds", "branch", "branch-1", "allow", obj{"condition": `request.amount <= 1000 && request.currency == "ETB"`})
	ask := func(ctx obj) (bool, string) {
		t.Helper()
		body := obj{"principal_id": w.daniel, "permission": "payment.refund", "resource": obj{"type": "branch", "id": "branch-1"}}
		if ctx != nil {
			body["context"] = ctx
		}
		var out struct {
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason"`
		}
		tn.back("POST", "/v1/can", body).data(&out)
		return out.Allowed, out.Reason
	}
	if ok, reason := ask(obj{"request": obj{"amount": 500, "currency": "ETB"}}); !ok {
		t.Fatalf("within the condition: %s", reason)
	}
	if ok, reason := ask(obj{"request": obj{"amount": 5000, "currency": "ETB"}}); ok || reason != "condition_not_met" {
		t.Fatalf("beyond the condition: %v %s", ok, reason)
	}
	if ok, reason := ask(nil); ok || reason != "condition_not_supported" {
		t.Fatalf("no context: %v %s", ok, reason)
	}
	// A conditional deny applies when it holds.
	w.ok(tn.back("PUT", "/v1/roles", obj{"name": "Readers", "permissions": []string{"payment.read"}}))
	w.grant(w.sara, "Readers", "branch", "branch-1", "deny", obj{"condition": `request.hour >= 22`})
	read := func(hour int) bool {
		var out struct {
			Allowed bool `json:"allowed"`
		}
		tn.back("POST", "/v1/can", obj{"principal_id": w.sara, "permission": "payment.read", "resource": obj{"type": "branch", "id": "branch-1"}, "context": obj{"request": obj{"hour": hour}}}).data(&out)
		return out.Allowed
	}
	if !read(10) || read(23) {
		t.Fatalf("conditional deny: day %v night %v", read(10), read(23))
	}
}

func TestAuditExportPerOrganization(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")
	a := createOrg(t, tn, hana, "Alpha")
	b := createOrg(t, tn, hana, "Beta")

	var mu sync.Mutex
	var received []map[string]any
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Entries []map[string]any `json:"entries"`
		}
		_ = json.Unmarshal(body, &payload)
		if r.Header.Get("X-AOS-Signature") == "" {
			http.Error(w, "unsigned", 400)
			return
		}
		mu.Lock()
		received = append(received, payload.Entries...)
		mu.Unlock()
	}))
	defer sink.Close()
	r := tn.back("POST", "/v1/webhooks", obj{"kind": "audit_export", "url": sink.URL, "organization_id": a.ID})
	if r.Status != 201 {
		t.Fatalf("audit endpoint: %d %s", r.Status, r.Raw)
	}
	if r := tn.back("POST", "/v1/webhooks", obj{"kind": "audit_export", "url": sink.URL}); r.Status != 400 {
		t.Fatalf("audit endpoint without an organization: %d", r.Status)
	}
	tn.front("POST", "/v1/organizations/"+a.ID+"/invitations", obj{"email": "x@example.com", "role": "Owner"}, hana)
	tn.front("POST", "/v1/organizations/"+b.ID+"/invitations", obj{"email": "y@example.com", "role": "Owner"}, hana)

	n, err := e.app.Module.Notification.ExportAudit(t.Context())
	if err != nil || n == 0 {
		t.Fatalf("export: %d %v", n, err)
	}
	mu.Lock()
	for _, entry := range received {
		if entry["organization_id"] != a.ID {
			t.Fatalf("another organization's entry was exported: %v", entry)
		}
	}
	first := len(received)
	mu.Unlock()
	// Nothing new: nothing sent. A new entry: only that one.
	if n, _ := e.app.Module.Notification.ExportAudit(t.Context()); n != 0 {
		t.Fatalf("re-export: %d", n)
	}
	tn.front("POST", "/v1/organizations/"+a.ID+"/invitations", obj{"email": "z@example.com", "role": "Owner"}, hana)
	if n, _ := e.app.Module.Notification.ExportAudit(t.Context()); n != 1 {
		t.Fatalf("incremental export: %d", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != first+1 {
		t.Fatalf("received: %d then %d", first, len(received))
	}
}
