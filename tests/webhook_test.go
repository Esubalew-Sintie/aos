package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/module/notification"
)

// receiver is the application's webhook endpoint.
type receiver struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	calls   []call
	status  int
	answer  string
	secret  string
	hangFor time.Duration
}

type call struct {
	event, hook, signature string
	body                   []byte
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{t: t, status: 200, answer: `{"allow": true}`}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.calls = append(r.calls, call{
			event: req.Header.Get("X-AOS-Event"), hook: req.Header.Get("X-AOS-Hook"),
			signature: req.Header.Get("X-AOS-Signature"), body: body,
		})
		status, answer, hang := r.status, r.answer, r.hangFor
		r.mu.Unlock()
		if hang > 0 {
			time.Sleep(hang)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) set(status int, answer string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status, r.answer = status, answer
}

func (r *receiver) received() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]call(nil), r.calls...)
}

// verify checks a signature the way the application's backend would.
func (r *receiver) verify(c call) bool {
	parts := strings.Split(c.signature, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		return false
	}
	ts := strings.TrimPrefix(parts[0], "t=")
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		return false
	}
	return notification.Sign([]byte(r.secret), ts, c.body) == strings.TrimPrefix(parts[1], "v1=")
}

func (tn *tenant) registerWebhook(rc *receiver, kind string, types ...string) string {
	tn.e.t.Helper()
	r := tn.back("POST", "/v1/webhooks", obj{"kind": kind, "url": rc.srv.URL + "/hook", "event_types": types, "timeout_ms": 500})
	if r.Status != 201 {
		tn.e.t.Fatalf("register webhook: %d %s", r.Status, r.Raw)
	}
	var out struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	r.data(&out)
	if out.Secret == "" {
		tn.e.t.Fatal("no signing secret was returned")
	}
	rc.secret = out.Secret
	return out.ID
}

func (e *env) deliverWebhooks() int {
	e.t.Helper()
	n, err := e.app.Module.Notification.DeliverWebhooks(context.Background())
	if err != nil {
		e.t.Fatalf("deliver webhooks: %v", err)
	}
	return n
}

func TestEventsAreDeliveredSignedToWebhooks(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	rc := newReceiver(t)
	id := tn.registerWebhook(rc, "events", "user.*", "session.created")

	// The secret is shown once: the list does not repeat it.
	var list []struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	tn.back("GET", "/v1/webhooks", nil).data(&list)
	if len(list) != 1 || list[0].ID != id || list[0].Secret != "" {
		t.Fatalf("unexpected list: %s", list)
	}

	tn.user("hana@example.com", "some-password")
	tn.signIn("hana@example.com", "wrong-password") // no event
	if sent := e.deliverWebhooks(); sent != 3 {
		t.Fatalf("want 3 deliveries (user.created, user.email_verified, session.created), got %d", sent)
	}
	calls := rc.received()
	events := map[string]int{}
	for _, c := range calls {
		events[c.event]++
		if !rc.verify(c) {
			t.Fatalf("the signature of %s does not verify", c.event)
		}
		var body struct {
			Event string          `json:"event"`
			Data  json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(c.body, &body); err != nil || body.Event != c.event || len(body.Data) == 0 {
			t.Fatalf("unexpected body: %s", c.body)
		}
	}
	if events["user.created"] != 1 || events["user.email_verified"] != 1 || events["session.created"] != 1 {
		t.Fatalf("unexpected events: %v", events)
	}
	// Nothing is sent twice.
	if sent := e.deliverWebhooks(); sent != 0 {
		t.Fatalf("a delivery was repeated: %d", sent)
	}
	if n := tn.count(`SELECT count(*) FROM aos.webhook_endpoints WHERE last_success_at IS NOT NULL`); n != 1 {
		t.Fatal("the endpoint's last success was not recorded")
	}

	// Removing the endpoint stops deliveries.
	if r := tn.back("DELETE", "/v1/webhooks/"+id, nil); r.Status != 200 {
		t.Fatalf("delete: %d %s", r.Status, r.Raw)
	}
	tn.user("sara@example.com", "some-password")
	if sent := e.deliverWebhooks(); sent != 0 {
		t.Fatal("a removed endpoint still received deliveries")
	}
}

func TestFailedWebhookDeliveriesAreRetried(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	rc := newReceiver(t)
	tn.registerWebhook(rc, "events", "user.created")
	rc.set(500, "down")

	tn.front("POST", "/v1/sign-up", obj{"email": "hana@example.com", "password": "some-password"}, "")
	if sent := e.deliverWebhooks(); sent != 0 {
		t.Fatalf("a failed delivery was reported as sent: %d", sent)
	}
	if n := tn.count(`SELECT count(*) FROM aos.webhook_deliveries WHERE status = 'pending' AND attempts = 1 AND last_status_code = 500 AND next_attempt_at IS NOT NULL`); n != 1 {
		t.Fatal("the failed delivery should wait for another attempt")
	}
	if n := tn.count(`SELECT count(*) FROM aos.webhook_endpoints WHERE last_failure_at IS NOT NULL AND last_error LIKE '%500%'`); n != 1 {
		t.Fatal("the endpoint's failure was not recorded")
	}
	// Not before its time.
	rc.set(200, "ok")
	if sent := e.deliverWebhooks(); sent != 0 {
		t.Fatal("retried too early")
	}
	tn.sql(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE aos.webhook_deliveries SET next_attempt_at = now() - interval '1 second'`)
		return err
	})
	if sent := e.deliverWebhooks(); sent != 1 {
		t.Fatalf("want the retry delivered, got %d", sent)
	}
}

func TestBeforeHooksCanRefuseAndAreFailClosed(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	rc := newReceiver(t)
	tn.registerWebhook(rc, "before_hook", "user.before_create")
	signUp := func(email string) result {
		return tn.front("POST", "/v1/sign-up", obj{"email": email, "password": "some-password"}, "")
	}

	// Allowed: the hook saw the sign-up before it was written.
	if r := signUp("ok@example.com"); r.Status != 202 {
		t.Fatalf("allowed sign-up: %d %s", r.Status, r.Raw)
	}
	calls := rc.received()
	if len(calls) != 1 || calls[0].hook != "user.before_create" || !rc.verify(calls[0]) {
		t.Fatalf("the hook was not called correctly: %+v", calls)
	}
	if !strings.Contains(string(calls[0].body), "ok@example.com") {
		t.Fatalf("the hook did not receive the sign-up: %s", calls[0].body)
	}

	// Refused, with the application's own words.
	rc.set(200, `{"allow": false, "message": "disposable addresses are not accepted"}`)
	r := signUp("no@example.com")
	if r.Status != 403 || r.code() != "refused_by_hook" || !strings.Contains(r.Body.Error.Message, "disposable") {
		t.Fatalf("refused sign-up: %d %s", r.Status, r.Raw)
	}
	if n := tn.count(`SELECT count(*) FROM aos.users WHERE email = 'no@example.com'`); n != 0 {
		t.Fatal("a refused sign-up created an account")
	}

	// The hook is down, or slow: the action is refused, never allowed by default.
	rc.set(500, "boom")
	if r := signUp("down@example.com"); r.Status != 403 || r.code() != "hook_unavailable" {
		t.Fatalf("hook down: %d %s", r.Status, r.Raw)
	}
	rc.set(200, `{"allow": true}`)
	rc.mu.Lock()
	rc.hangFor = 2 * time.Second
	rc.mu.Unlock()
	start := time.Now()
	if r := signUp("slow@example.com"); r.Status != 403 || r.code() != "hook_unavailable" {
		t.Fatalf("hook slow: %d %s", r.Status, r.Raw)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal("the engine waited longer than the hook's time limit")
	}
	// A hook for another action is not asked.
	rc.mu.Lock()
	rc.hangFor = 0
	rc.calls = nil
	rc.mu.Unlock()
	tn.front("POST", "/v1/password/forgot", obj{"email": "ok@example.com"}, "")
	if len(rc.received()) != 0 {
		t.Fatal("a hook was asked about an action it did not subscribe to")
	}
}

func TestWebhookAddressesAreChecked(t *testing.T) {
	e := newEnv(t)
	tn := e.tenant("acme")
	for name, body := range map[string]obj{
		"no scheme":    {"url": "example.com/hook"},
		"ftp":          {"url": "ftp://example.com/hook"},
		"bad kind":     {"url": "https://example.com/hook", "kind": "sometimes"},
		"tiny timeout": {"url": "https://example.com/hook", "timeout_ms": 10},
	} {
		if r := tn.back("POST", "/v1/webhooks", body); r.Status != 400 {
			t.Errorf("%s: got %d %s, want 400", name, r.Status, r.Raw)
		}
	}
	if r := tn.back("DELETE", "/v1/webhooks/00000000-0000-0000-0000-000000000000", nil); r.Status != 404 {
		t.Fatalf("deleting an unknown endpoint: %d", r.Status)
	}
}
