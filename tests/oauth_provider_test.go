package tests

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/flash-software-technology/aos/platform/jwt"
	"github.com/flash-software-technology/aos/platform/oidc"
)

type clientData struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// postForm posts a form to a public route and decodes the JSON answer.
func (tn *tenant) postForm(path string, values url.Values, basicUser, basicSecret string) (int, map[string]any) {
	tn.e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, tn.e.srv.URL+path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicSecret)
	}
	resp, body := tn.e.raw(req)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

// authorize plays the third-party application sending the browser to the
// authorization endpoint, and returns the redirect it got.
func (tn *tenant) authorize(q url.Values) (int, *url.URL, []byte) {
	tn.e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, tn.e.srv.URL+"/t/shop/oauth/authorize?"+q.Encode(), nil)
	resp, body := tn.e.raw(req)
	loc, _ := resp.Location()
	return resp.StatusCode, loc, body
}

// publicKeys reads the tenant's keys from the public door.
func (tn *tenant) providerKeys(t *testing.T) func(kid string) ed25519.PublicKey {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, tn.e.srv.URL+"/t/shop/oauth/jwks.json", nil)
	_, body := tn.e.raw(req)
	var set struct {
		Keys []jwt.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
		t.Fatalf("jwks: %s", body)
	}
	return func(kid string) ed25519.PublicKey {
		for _, k := range set.Keys {
			if k.Kid == kid {
				key, _ := k.PublicKey()
				return key
			}
		}
		return nil
	}
}

func TestTenantIsAnOpenIDProvider(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	hanaID, hana := tn.user("hana@example.com", "some-password")
	tn.back("PUT", "/v1/permissions", obj{"name": "orders.read"})

	// Discovery.
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/t/shop/.well-known/openid-configuration", nil)
	resp, body := e.raw(req)
	var disc map[string]any
	_ = json.Unmarshal(body, &disc)
	if resp.StatusCode != 200 || disc["issuer"] != "https://aos.test/t/shop" || disc["token_endpoint"] != "https://aos.test/t/shop/oauth/token" {
		t.Fatalf("discovery: %d %s", resp.StatusCode, body)
	}
	req, _ = http.NewRequest(http.MethodGet, e.srv.URL+"/t/nope/.well-known/openid-configuration", nil)
	if resp, _ := e.raw(req); resp.StatusCode != 404 {
		t.Fatalf("unknown tenant: %d", resp.StatusCode)
	}

	// A public client (a single-page app) and a confidential one.
	r := tn.back("PUT", "/v1/oauth-clients", obj{"client_id": "spa", "name": "Partner SPA", "kind": "public",
		"redirect_uris": []string{"https://partner.test/callback"}, "allowed_scopes": []string{"orders.read"}})
	if r.Status != 200 {
		t.Fatalf("put public client: %d %s", r.Status, r.Raw)
	}
	var spa, conf clientData
	r.data(&spa)
	r = tn.back("PUT", "/v1/oauth-clients", obj{"client_id": "backend", "name": "Partner backend", "redirect_uris": []string{"https://partner.test/cb"},
		"grant_types": []string{"authorization_code", "refresh_token"}})
	r.data(&conf)
	if conf.ClientSecret == "" {
		t.Fatal("no secret for the confidential client")
	}
	if n := tn.count(`SELECT count(*) FROM aos.oauth_clients WHERE secret_hash = $1`, []byte(conf.ClientSecret)); n != 0 {
		t.Fatal("the client secret is stored in clear")
	}
	var clients []clientData
	tn.back("GET", "/v1/oauth-clients", nil).data(&clients)
	if len(clients) != 2 || clients[1].ClientSecret != "" {
		t.Fatalf("clients: %+v", clients)
	}

	// The authorization request. A wrong redirect is refused outright,
	// never redirected; a wrong scope is sent back to the client.
	verifier, _ := oidc.NewVerifier()
	base := url.Values{"response_type": {"code"}, "client_id": {"spa"}, "redirect_uri": {"https://partner.test/callback"},
		"scope": {"openid email orders.read"}, "state": {"xyz"}, "nonce": {"n1"}, "code_challenge": {oidc.Challenge(verifier)}, "code_challenge_method": {"S256"}}
	bad := url.Values{}
	for k, v := range base {
		bad[k] = v
	}
	bad.Set("redirect_uri", "https://evil.test/cb")
	if status, loc, body := tn.authorize(bad); status != 400 || loc != nil || !strings.Contains(string(body), "redirect_uri") {
		t.Fatalf("wrong redirect: %d %v %s", status, loc, body)
	}
	bad.Set("redirect_uri", "https://partner.test/callback")
	bad.Set("scope", "openid payments.refund")
	if status, loc, _ := tn.authorize(bad); status != 302 || loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("state") != "xyz" {
		t.Fatalf("wrong scope: %d %v", status, loc)
	}
	noPKCE := url.Values{}
	for k, v := range base {
		noPKCE[k] = v
	}
	noPKCE.Del("code_challenge")
	if status, loc, _ := tn.authorize(noPKCE); status != 302 || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("public client without PKCE: %d %v", status, loc)
	}
	status, loc, _ := tn.authorize(base)
	if status != 302 || !strings.HasPrefix(loc.String(), "https://app.test/auth/authorize?request_id=") {
		t.Fatalf("authorize: %d %v", status, loc)
	}
	requestID := loc.Query().Get("request_id")

	// The person sees who asks for what, and consents.
	var view struct {
		ClientName   string   `json:"client_name"`
		Scopes       []string `json:"scopes"`
		ConsentGiven bool     `json:"consent_given"`
	}
	r = tn.front("GET", "/v1/oauth/requests/"+requestID, nil, hana)
	if r.Status != 200 {
		t.Fatalf("request view: %d %s", r.Status, r.Raw)
	}
	r.data(&view)
	if view.ClientName != "Partner SPA" || view.ConsentGiven || strings.Join(view.Scopes, " ") != "openid email orders.read" {
		t.Fatalf("view: %+v", view)
	}
	if r := tn.front("GET", "/v1/oauth/requests/"+requestID, nil, ""); r.Status != 401 {
		t.Fatalf("view without a session: %d", r.Status)
	}
	r = tn.front("POST", "/v1/oauth/consent", obj{"request_id": requestID, "approve": true}, hana)
	if r.Status != 200 {
		t.Fatalf("consent: %d %s", r.Status, r.Raw)
	}
	var consent struct {
		RedirectTo string `json:"redirect_to"`
	}
	r.data(&consent)
	back, _ := url.Parse(consent.RedirectTo)
	code := back.Query().Get("code")
	if !strings.HasPrefix(consent.RedirectTo, "https://partner.test/callback?") || code == "" || back.Query().Get("state") != "xyz" || back.Query().Get("iss") != "https://aos.test/t/shop" {
		t.Fatalf("redirect back: %s", consent.RedirectTo)
	}
	if r := tn.front("POST", "/v1/oauth/consent", obj{"request_id": requestID, "approve": true}, hana); r.Status != 404 {
		t.Fatalf("consent twice: %d", r.Status)
	}

	// The code becomes tokens, with PKCE. Wrong verifier, then right.
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"}, "code": {code}, "redirect_uri": {"https://partner.test/callback"}, "code_verifier": {"wrong-verifier-wrong-verifier-wrong-verifier"}}
	if status, body := tn.postForm("/t/shop/oauth/token", form, "", ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", status, body)
	}
	form.Set("code_verifier", verifier)
	status, tokens := tn.postForm("/t/shop/oauth/token", form, "", "")
	if status != 200 {
		t.Fatalf("token: %d %v", status, tokens)
	}
	access, _ := tokens["access_token"].(string)
	idToken, _ := tokens["id_token"].(string)
	refresh, _ := tokens["refresh_token"].(string)
	if access == "" || idToken == "" || refresh == "" || tokens["scope"] != "openid email orders.read" {
		t.Fatalf("tokens: %v", tokens)
	}
	// A code works once.
	if status, body := tn.postForm("/t/shop/oauth/token", form, "", ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("code reuse: %d %v", status, body)
	}
	// The identity token checks out against the published keys.
	keys := tn.providerKeys(t)
	claims, err := jwt.Verify(idToken, time.Now(), keys)
	if err != nil {
		t.Fatalf("id token: %v", err)
	}
	if claims["iss"] != "https://aos.test/t/shop" || claims["aud"] != "spa" || claims["sub"] != hanaID || claims["nonce"] != "n1" || claims["email"] != "hana@example.com" {
		t.Fatalf("id token claims: %v", claims)
	}
	ac, err := jwt.Verify(access, time.Now(), keys)
	if err != nil || ac["typ"] != "oauth" || ac["aud"] != "spa" || ac["client_id"] != "spa" {
		t.Fatalf("access token: %v %v", err, ac)
	}
	// Userinfo and introspection.
	req, _ = http.NewRequest(http.MethodGet, e.srv.URL+"/t/shop/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, body = e.raw(req)
	var info map[string]any
	_ = json.Unmarshal(body, &info)
	if resp.StatusCode != 200 || info["sub"] != hanaID || info["email"] != "hana@example.com" {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, body)
	}
	status, intro := tn.postForm("/t/shop/oauth/introspect", url.Values{"token": {access}}, "backend", conf.ClientSecret)
	if status != 200 || intro["active"] != true || intro["sub"] != hanaID || intro["scope"] != "openid email orders.read" {
		t.Fatalf("introspect: %d %v", status, intro)
	}
	if status, body := tn.postForm("/t/shop/oauth/introspect", url.Values{"token": {access}}, "backend", "wrong"); status != 401 || body["error"] != "invalid_client" {
		t.Fatalf("introspect with a wrong secret: %d %v", status, body)
	}
	// Refresh rotates; reuse ends the family.
	status, second := tn.postForm("/t/shop/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {refresh}}, "", "")
	if status != 200 || second["refresh_token"] == refresh || second["access_token"] == access {
		t.Fatalf("refresh: %d %v", status, second)
	}
	if status, body := tn.postForm("/t/shop/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {refresh}}, "", ""); status != 400 || !strings.Contains(body["error_description"].(string), "twice") {
		t.Fatalf("refresh reuse: %d %v", status, body)
	}
	if status, _ := tn.postForm("/t/shop/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {second["refresh_token"].(string)}}, "", ""); status != 400 {
		t.Fatal("the family survived reuse")
	}

	// Consent is remembered, listed, and can be withdrawn.
	status, loc, _ = tn.authorize(base)
	tn.front("GET", "/v1/oauth/requests/"+loc.Query().Get("request_id"), nil, hana).data(&view)
	if !view.ConsentGiven {
		t.Fatal("consent was not remembered")
	}
	tn.front("POST", "/v1/oauth/consent", obj{"request_id": loc.Query().Get("request_id"), "approve": true}, hana).data(&consent)
	back, _ = url.Parse(consent.RedirectTo)
	form.Set("code", back.Query().Get("code"))
	_, tokens = tn.postForm("/t/shop/oauth/token", form, "", "")
	var consents []struct {
		ClientID   string `json:"client_id"`
		ClientName string `json:"client_name"`
	}
	tn.front("GET", "/v1/me/consents", nil, hana).data(&consents)
	if len(consents) != 1 || consents[0].ClientName != "Partner SPA" {
		t.Fatalf("consents: %+v", consents)
	}
	if r := tn.front("DELETE", "/v1/me/consents/"+consents[0].ClientID, nil, hana); r.Status != 200 {
		t.Fatalf("withdraw consent: %d %s", r.Status, r.Raw)
	}
	if status, _ := tn.postForm("/t/shop/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {tokens["refresh_token"].(string)}}, "", ""); status != 400 {
		t.Fatal("tokens survived the withdrawn consent")
	}
	// Declining sends the browser back with an error.
	_, loc, _ = tn.authorize(base)
	tn.front("POST", "/v1/oauth/consent", obj{"request_id": loc.Query().Get("request_id"), "approve": false}, hana).data(&consent)
	if !strings.Contains(consent.RedirectTo, "error=access_denied") {
		t.Fatalf("decline: %s", consent.RedirectTo)
	}

	// Revocation endpoint, and a disabled client.
	if status, _ := tn.postForm("/t/shop/oauth/revoke", url.Values{"token": {"whatever"}}, "backend", conf.ClientSecret); status != 200 {
		t.Fatalf("revoke: %d", status)
	}
	tn.back("DELETE", "/v1/oauth-clients/"+spa.ID, nil)
	if status, _, _ := tn.authorize(base); status != 400 {
		t.Fatalf("disabled client: %d", status)
	}
}

func TestMachinesGetTokensWithoutABrowser(t *testing.T) {
	w := newWorld(t)
	tn := w.tn
	var svc machineData
	tn.back("POST", "/v1/service-accounts", obj{"name": "Reporter"}).data(&svc)
	w.grant(svc.ID, "Cashier", "organization", "merchant-a", "allow")
	var conf clientData
	tn.back("PUT", "/v1/oauth-clients", obj{"client_id": "reporter", "name": "Reporter job", "service_principal_id": svc.ID,
		"allowed_scopes": []string{"payment.read"}, "grant_types": []string{"client_credentials"}}).data(&conf)

	// Client credentials: the service's own permissions, narrowed by the scopes.
	status, tokens := tn.postForm("/t/paygate/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"payment.read"}}, "reporter", conf.ClientSecret)
	if status != 200 || tokens["refresh_token"] != nil {
		t.Fatalf("client credentials: %d %v", status, tokens)
	}
	req, _ := http.NewRequest(http.MethodGet, w.e.srv.URL+"/t/paygate/oauth/jwks.json", nil)
	_, body := w.e.raw(req)
	var set struct {
		Keys []jwt.JWK `json:"keys"`
	}
	_ = json.Unmarshal(body, &set)
	claims, err := jwt.Verify(tokens["access_token"].(string), time.Now(), func(kid string) ed25519.PublicKey {
		k, _ := set.Keys[0].PublicKey()
		return k
	})
	if err != nil || claims["sub"] != svc.ID || claims["scope"] != "payment.read" {
		t.Fatalf("machine token: %v %v", err, claims)
	}
	if status, body := tn.postForm("/t/paygate/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"payment.refund"}}, "reporter", conf.ClientSecret); status != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("scope beyond the client: %d %v", status, body)
	}
	if status, body := tn.postForm("/t/paygate/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "reporter", "wrong"); status != 401 || body["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", status, body)
	}

	// The device flow: a code shown on the screen, approved on a phone.
	var tv clientData
	tn.back("PUT", "/v1/oauth-clients", obj{"client_id": "tv", "name": "Shop TV", "kind": "public", "grant_types": []string{"urn:ietf:params:oauth:grant-type:device_code"}}).data(&tv)
	status, dev := tn.postForm("/t/paygate/oauth/device", url.Values{"client_id": {"tv"}, "scope": {"openid"}}, "", "")
	if status != 200 || dev["user_code"] == nil || dev["verification_uri"] != "https://app.test/auth/device" {
		t.Fatalf("device: %d %v", status, dev)
	}
	poll := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"tv"}, "device_code": {dev["device_code"].(string)}}
	if status, body := tn.postForm("/t/paygate/oauth/token", poll, "", ""); status != 400 || body["error"] != "authorization_pending" {
		t.Fatalf("poll before approval: %d %v", status, body)
	}
	if status, body := tn.postForm("/t/paygate/oauth/token", poll, "", ""); body["error"] != "slow_down" {
		t.Fatalf("poll too soon: %d %v", status, body)
	}
	_, hana := tn.signInSession("hana@example.com", "some-password")
	r := tn.front("POST", "/v1/oauth/device/approve", obj{"user_code": strings.ToLower(dev["user_code"].(string)), "approve": true}, hana)
	if r.Status != 200 {
		t.Fatalf("approve device: %d %s", r.Status, r.Raw)
	}
	w.e.clock.advance(6 * time.Second)
	status, tokens = tn.postForm("/t/paygate/oauth/token", poll, "", "")
	if status != 200 || tokens["id_token"] == nil {
		t.Fatalf("poll after approval: %d %v", status, tokens)
	}
	claims, _ = jwt.Verify(tokens["id_token"].(string), time.Now(), func(string) ed25519.PublicKey { k, _ := set.Keys[0].PublicKey(); return k })
	if claims["sub"] != w.hana {
		t.Fatalf("device token subject: %v", claims)
	}
	w.e.clock.advance(6 * time.Second)
	if status, body := tn.postForm("/t/paygate/oauth/token", poll, "", ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("device code reuse: %d %v", status, body)
	}

	// Token exchange: an agent turns a delegation into a token that acts for Sara.
	var agent machineData
	tn.back("POST", "/v1/agents", obj{"name": "Refund helper", "owner_principal_id": w.sara}).data(&agent)
	var ac clientData
	tn.back("PUT", "/v1/oauth-clients", obj{"client_id": "helper", "name": "Helper", "service_principal_id": agent.ID,
		"allowed_scopes": []string{"payment.*"}, "grant_types": []string{"urn:ietf:params:oauth:grant-type:token-exchange"}}).data(&ac)
	_, sara := tn.signInSession("sara@example.com", "some-password")
	var delegation struct {
		ID string `json:"id"`
	}
	tn.front("POST", "/v1/me/delegations", obj{"agent_id": agent.ID, "scopes": []string{"payment.read"}, "resource": obj{"type": "organization", "id": "merchant-a"}, "hours": 2}, sara).data(&delegation)
	status, tokens = tn.postForm("/t/paygate/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "delegation_id": {delegation.ID}, "resource": {"https://api.paygate.test"}}, "helper", ac.ClientSecret)
	if status != 200 {
		t.Fatalf("exchange: %d %v", status, tokens)
	}
	claims, _ = jwt.Verify(tokens["access_token"].(string), time.Now(), func(string) ed25519.PublicKey { k, _ := set.Keys[0].PublicKey(); return k })
	act, _ := claims["act"].(map[string]any)
	if claims["sub"] != w.sara || act["sub"] != agent.ID || claims["aud"] != "https://api.paygate.test" || claims["scope"] != "payment.read" {
		t.Fatalf("exchanged token: %v", claims)
	}
	if status, body := tn.postForm("/t/paygate/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "delegation_id": {delegation.ID}, "scope": {"payment.refund"}}, "helper", ac.ClientSecret); status != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("exchange beyond the delegation: %d %v", status, body)
	}
	status, intro := tn.postForm("/t/paygate/oauth/introspect", url.Values{"token": {tokens["access_token"].(string)}}, "helper", ac.ClientSecret)
	if intro["active"] != true || intro["act"] == nil {
		t.Fatalf("introspect the exchanged token: %d %v", status, intro)
	}
}

func TestMCPClientsIdentifyWithAMetadataDocument(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("shop")
	_, hana := tn.user("hana@example.com", "some-password")

	// The MCP client publishes its metadata at its own address.
	var docServer *httptest.Server
	docServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id": docServer.URL + "/client", "client_name": "Coding assistant",
			"redirect_uris": []string{"http://127.0.0.1:9999/callback"}, "token_endpoint_auth_method": "none",
		})
	}))
	defer docServer.Close()
	clientID := docServer.URL + "/client"
	verifier, _ := oidc.NewVerifier()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:9999/callback"},
		"scope": {"openid"}, "state": {"s"}, "resource": {"https://mcp.shop.test"}, "code_challenge": {oidc.Challenge(verifier)}, "code_challenge_method": {"S256"}}
	status, loc, body := tn.authorize(q)
	if status != 302 || loc == nil {
		t.Fatalf("authorize with a metadata client: %d %s", status, body)
	}
	var view struct {
		ClientName string `json:"client_name"`
		Resource   string `json:"resource"`
	}
	tn.front("GET", "/v1/oauth/requests/"+loc.Query().Get("request_id"), nil, hana).data(&view)
	if view.ClientName != "Coding assistant" || view.Resource != "https://mcp.shop.test" {
		t.Fatalf("view: %+v", view)
	}
	var consent struct {
		RedirectTo string `json:"redirect_to"`
	}
	tn.front("POST", "/v1/oauth/consent", obj{"request_id": loc.Query().Get("request_id"), "approve": true}, hana).data(&consent)
	back, _ := url.Parse(consent.RedirectTo)
	status, tokens := tn.postForm("/t/shop/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {back.Query().Get("code")},
		"redirect_uri": {"http://127.0.0.1:9999/callback"}, "code_verifier": {verifier}}, "", "")
	if status != 200 {
		t.Fatalf("token: %d %v", status, tokens)
	}
	// The token is for that one MCP server and no other.
	claims, err := jwt.Verify(tokens["access_token"].(string), time.Now(), tn.providerKeys(t))
	if err != nil || claims["aud"] != "https://mcp.shop.test" {
		t.Fatalf("audience: %v %v", err, claims)
	}
	// A document that names another client id is refused.
	liar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "https://someone.else", "redirect_uris": []string{"http://127.0.0.1:9999/callback"}})
	}))
	defer liar.Close()
	q.Set("client_id", liar.URL+"/client")
	if status, _, _ := tn.authorize(q); status != 400 {
		t.Fatalf("lying document: %d", status)
	}
}
