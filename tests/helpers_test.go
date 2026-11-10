// Package tests exercises the engine from the outside: through the same
// wiring and the same HTTP routes that run in production, against a real
// Postgres that exists only for the test.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/initiator"
	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/mailer"
	"github.com/flash-software-technology/aos/platform/secret"
	"github.com/flash-software-technology/aos/platform/testdb"
)

// env is one engine with its own database, a clock the test controls,
// and a mailbox that catches every email.
type env struct {
	// dns holds the TXT records the fake resolver answers.
	dns   *fakeDNS
	t     *testing.T
	app   *initiator.App
	mail  *mailbox
	clock *clock
	srv   *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith builds an engine whose emails go to sender instead of the
// test mailbox.
func newEnvWith(t *testing.T, sender mailer.Sender) *env {
	t.Helper()
	db := testdb.Open(t)
	master, err := secret.ParseMasterKey(secret.NewMasterKeyString())
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Now().UTC().Truncate(time.Second)}
	m := &mailbox{}
	if sender == nil {
		sender = m
	}
	dns := &fakeDNS{records: map[string][]string{}}
	app, err := initiator.NewApp(config.Config{Env: "development", PublicURL: "https://aos.test"}, db, master, initiator.ModuleOptions{
		Sender: sender,
		Now:    c.Now,
		// Real hashing costs would make the suite take minutes.
		PasswordParams: secret.PasswordParams{MemoryKiB: 64, Time: 1, Threads: 1},
		// Webhook tests point at a server on this machine.
		AllowPrivateWebhooks: true,
		DNS:                  dns.lookup,
	}, testLog{t})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Router)
	t.Cleanup(srv.Close)
	return &env{t: t, app: app, mail: m, clock: c, srv: srv, dns: dns}
}

// deliver sends every message that is waiting.
func (e *env) deliver() int {
	e.t.Helper()
	n, err := e.app.Module.Notification.DeliverDue(context.Background())
	if err != nil {
		e.t.Fatalf("deliver: %v", err)
	}
	return n
}

type pgxTx = pgx.Tx

// ---- a tenant and its two keys ----

type tenant struct {
	e  *env
	ID string
	PK string // publishable key: the frontend door
	SK string // secret key: the backend door
}

func (e *env) tenant(slug string, change ...func(*request.CreateTenantRequest)) *tenant {
	e.t.Helper()
	req := request.CreateTenantRequest{
		Slug: slug, Name: "App " + slug, Kind: constant.KindMulti, Environment: constant.EnvDevelopment,
		AppURL: "https://app.test", AllowedOrigins: []string{"https://app.test"},
	}
	for _, f := range change {
		f(&req)
	}
	created, err := e.app.Module.Tenant.Create(context.Background(), req)
	if err != nil {
		e.t.Fatalf("create tenant %s: %v", slug, err)
	}
	return &tenant{e: e, ID: created.TenantID, PK: created.PublishableKey, SK: created.SecretKey}
}

// sql runs fn inside this tenant's scope, as the engine would.
func (tn *tenant) sql(fn func(tx pgx.Tx) error) {
	tn.e.t.Helper()
	if err := tn.e.app.DB.Tenant(context.Background(), tn.ID, fn); err != nil {
		tn.e.t.Fatalf("sql in tenant: %v", err)
	}
}

// count returns the single number a query yields, inside this tenant's scope.
func (tn *tenant) count(query string, args ...any) int {
	tn.e.t.Helper()
	var n int
	tn.sql(func(tx pgx.Tx) error { return tx.QueryRow(context.Background(), query, args...).Scan(&n) })
	return n
}

// user signs a person up, confirms the emailed link, and returns their
// id and session token.
func (tn *tenant) user(email, password string) (id, session string) {
	tn.e.t.Helper()
	if r := tn.front("POST", "/v1/sign-up", obj{"email": email, "password": password}, ""); r.Status != 202 {
		tn.e.t.Fatalf("sign up %s: %d %s", email, r.Status, r.Raw)
	}
	tn.e.deliver()
	r := tn.front("POST", "/v1/verify-email", obj{"token": tn.e.mail.token(email)}, "")
	if r.Status != 200 {
		tn.e.t.Fatalf("verify %s: %d %s", email, r.Status, r.Raw)
	}
	var out authData
	r.data(&out)
	return out.User.ID, out.SessionToken
}

// signInSession signs in and returns the id and session token.
func (tn *tenant) signInSession(email, password string) (id, session string) {
	tn.e.t.Helper()
	r := tn.signIn(email, password)
	if r.Status != 200 {
		tn.e.t.Fatalf("sign in %s: %d %s", email, r.Status, r.Raw)
	}
	var out authData
	r.data(&out)
	return out.User.ID, out.SessionToken
}

// signIn returns the result of a sign-in attempt.
func (tn *tenant) signIn(email, password string) result {
	return tn.front("POST", "/v1/sign-in", obj{"email": email, "password": password}, "")
}

// ---- HTTP ----

type obj map[string]any

type result struct {
	t      *testing.T
	Status int
	Header http.Header
	Raw    []byte
	Body   struct {
		Status  int             `json:"status"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
		Error   *struct {
			Type    string            `json:"type"`
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
}

// code is the error code of the answer, or "" for a success.
func (r result) code() string {
	if r.Body.Error == nil {
		return ""
	}
	return r.Body.Error.Code
}

func (r result) data(dst any) {
	r.t.Helper()
	if err := json.Unmarshal(r.Body.Data, dst); err != nil {
		r.t.Fatalf("read data: %v (body %s)", err, r.Raw)
	}
}

type authData struct {
	User struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"user"`
	Session struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"session"`
	SessionToken string `json:"session_token"`
}

// front calls a frontend route with the publishable key. A session token,
// when given, travels in the development header.
func (tn *tenant) front(method, path string, body any, session string, headers ...string) result {
	h := []string{constant.HeaderPublishableKey, tn.PK}
	if session != "" {
		h = append(h, constant.HeaderSession, session)
	}
	return tn.e.call(method, path, body, append(h, headers...)...)
}

// back calls a backend route with the secret key.
func (tn *tenant) back(method, path string, body any, headers ...string) result {
	return tn.e.call(method, path, body, append([]string{"Authorization", "Bearer " + tn.SK}, headers...)...)
}

// raw sends a request as given, without following redirects, and
// returns the response with its body read.
func (e *env) raw(req *http.Request) (*http.Response, []byte) {
	e.t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// call makes one request. headers are alternating names and values.
func (e *env) call(method, path string, body any, headers ...string) result {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := result{t: e.t, Status: resp.StatusCode, Header: resp.Header, Raw: raw}
	_ = json.Unmarshal(raw, &r.Body)
	return r
}

// ---- a logger that shows the engine's errors in the test output ----

// testLog passes the engine's errors to the test log, so a failing test
// shows why the engine failed. Everything quieter is dropped.
type testLog struct{ t *testing.T }

func (l testLog) Debug(context.Context, string, ...any) {}
func (l testLog) Info(context.Context, string, ...any)  {}
func (l testLog) Warn(context.Context, string, ...any)  {}
func (l testLog) Error(_ context.Context, msg string, args ...any) {
	l.t.Logf("engine error: %s %v", msg, args)
}
func (l testLog) Debugf(string, ...any)             {}
func (l testLog) Infof(string, ...any)              {}
func (l testLog) Warnf(string, ...any)              {}
func (l testLog) Errorf(format string, args ...any) { l.t.Logf("engine error: "+format, args...) }
func (l testLog) Named(string) logger.Logger        { return l }

// ---- a clock the test moves ----

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// ---- a mailbox that catches every email ----

type mailbox struct {
	mu     sync.Mutex
	emails []mailer.Email
	// fail makes every send fail, as if the mail server were down.
	fail bool
}

func (m *mailbox) Send(_ context.Context, e mailer.Email) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("mail server is down")
	}
	m.emails = append(m.emails, e)
	return nil
}

// to returns the emails sent to one address, oldest first.
func (m *mailbox) to(address string) []mailer.Email {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []mailer.Email
	for _, e := range m.emails {
		if strings.EqualFold(e.To, address) {
			out = append(out, e)
		}
	}
	return out
}

// has reports whether any email to an address mentions the text in its
// subject or body. Emails sent in the same instant have no fixed order.
func (m *mailbox) has(address, text string) bool {
	for _, e := range m.to(address) {
		if strings.Contains(e.Subject, text) || strings.Contains(e.Body, text) {
			return true
		}
	}
	return false
}

// sessionCookie finds the session cookie among the ones an answer set.
func sessionCookie(r result) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == constant.SessionCookie {
			return c
		}
	}
	return nil
}

var tokenInLink = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

// tokens returns the token in each email sent to an address, oldest first.
func (m *mailbox) tokens(address string) []string {
	var out []string
	for _, e := range m.to(address) {
		if match := tokenInLink.FindStringSubmatch(e.Body); match != nil {
			out = append(out, match[1])
		}
	}
	return out
}

// token returns the token in the newest email to an address that has one.
func (m *mailbox) token(address string) string {
	all := m.tokens(address)
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

// fakeDNS answers TXT lookups from a map.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]string
}

func (d *fakeDNS) set(name string, values ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = values
}

func (d *fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.records[name], nil
}
