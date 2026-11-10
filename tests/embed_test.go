package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aos "github.com/flash-software-technology/aos-go"

	"github.com/flash-software-technology/aos/embed"
	"github.com/flash-software-technology/aos/engine"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/mailer"
	"github.com/flash-software-technology/aos/platform/testdb"
)

// An application with the engine inside it: the browser signs up through
// the mounted routes, and the application's own routes check tokens and
// permissions in the same process.
func TestEmbeddedEngine(t *testing.T) {
	dbURL := testdb.URL(t)
	ctx := context.Background()
	inbox := mailer.NewInbox(logger.NewDiscard(), 50)
	cfg := embed.Config{
		DatabaseURL: dbURL, MasterKey: engine.NewMasterKey(), AppURL: "http://shop.test",
		Development: true, Sender: inbox, Logger: logger.NewDiscard(),
	}
	auth, err := embed.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Close)

	// The application, written against the same interface as the hosted SDK.
	var a aos.Auth = auth
	mux := http.NewServeMux()
	mux.Handle("/aos/", auth.Handler())
	mux.Handle("GET /api/invoices", a.Middleware(a.RequirePermission("invoice.read", aos.Root)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`["INV-1"]`)) }))))
	mux.Handle("POST /api/aos/can", a.CanHandler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	call := func(method, path string, body any, headers ...string) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	data := func(m map[string]any) map[string]any { d, _ := m["data"].(map[string]any); return d }

	// The browser calls from the application's own origin and may leave
	// the publishable key out: there is one application.
	origin := []string{"Origin", "http://shop.test"}
	if s, _ := call("POST", "/aos/v1/sign-up", map[string]string{"email": "eve@shop.test", "password": "correct horse battery staple 42"}, origin...); s != 202 {
		t.Fatalf("sign-up: %d", s)
	}
	if s, _ := call("POST", "/aos/v1/sign-up", map[string]string{"email": "x@shop.test", "password": "correct horse battery staple 42"}, "Origin", "http://evil.test"); s != 403 {
		t.Fatalf("another origin: %d", s)
	}
	var token string
	for i := 0; i < 50 && token == ""; i++ {
		for _, m := range inbox.List("eve@shop.test") {
			if strings.Contains(strings.Join(m.Links, " "), "http://shop.test/auth/verify-email") {
				token = m.Token
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if token == "" {
		t.Fatal("no confirmation email")
	}
	_, verified := call("POST", "/aos/v1/verify-email", map[string]string{"token": token}, origin...)
	session, _ := data(verified)["session_token"].(string)
	user, _ := data(verified)["user"].(map[string]any)
	userID, _ := user["id"].(string)
	_, tok := call("POST", "/aos/v1/session/token", nil, append(origin, "X-AOS-Session", session)...)
	jwt, _ := data(tok)["token"].(string)
	if jwt == "" || userID == "" {
		t.Fatalf("no session token: %v", verified)
	}

	// Tokens are checked against the engine in the same process.
	claims, err := a.VerifyToken(ctx, jwt)
	if err != nil || claims.UserID != userID {
		t.Fatalf("verify: %v %+v", err, claims)
	}
	bearer := []string{"Authorization", "Bearer " + jwt}
	if s, _ := call("GET", "/api/invoices", nil, bearer...); s != 403 {
		t.Fatalf("before the grant: %d", s)
	}
	if _, err := a.PutPermission(ctx, aos.Permission{Name: "invoice.read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutRole(ctx, aos.Role{Name: "Viewer", Permissions: []string{"invoice.read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGrant(ctx, aos.Grant{PrincipalID: userID, Role: "Viewer", Resource: aos.Resource{Type: "tenant", ID: "root"}}); err != nil {
		t.Fatal(err)
	}
	if s, _ := call("GET", "/api/invoices", nil, bearer...); s != 200 {
		t.Fatalf("after the grant: %d", s)
	}
	if s, out := call("POST", "/api/aos/can", map[string]any{"permissions": []string{"invoice.read", "invoice.refund"}}, bearer...); s != 200 ||
		out["results"].(map[string]any)["invoice.read"] != true || out["results"].(map[string]any)["invoice.refund"] != false {
		t.Fatalf("can: %d %v", s, out)
	}
	page, err := a.ListUsers(ctx, "", 10)
	if err != nil || len(page.Users) != 1 {
		t.Fatalf("users: %v %+v", err, page)
	}

	// The backend routes are not reachable from the network without the
	// secret key: only calls inside the process skip it.
	if s, _ := call("POST", "/aos/v1/can", map[string]any{"principal_id": userID, "permission": "invoice.read", "resource": map[string]string{"type": "tenant", "id": "root"}}); s != 401 {
		t.Fatalf("backend route from the network: %d", s)
	}

	// A restart finds the same application and its people.
	pk := auth.PublishableKey()
	auth.Close()
	again, err := embed.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.PublishableKey() != pk {
		t.Fatal("a restart made a new application")
	}
	if c, err := again.VerifyToken(ctx, jwt); err != nil || c.UserID != userID {
		t.Fatalf("token after restart: %v", err)
	}
}
