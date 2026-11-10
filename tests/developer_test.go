package tests

import (
	"strings"
	"testing"

	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/mailer"
)

func TestDevelopmentInbox(t *testing.T) {
	inbox := mailer.NewInbox(logger.NewDiscard(), 50)
	e := newEnvWith(t, inbox)
	tn := e.tenant("shop")
	tn.front("POST", "/v1/sign-up", obj{"email": "me@example.com", "password": "a-long-test-password"}, "")
	e.deliver()

	r := e.call("GET", "/dev/mail?to=me@example.com", nil)
	if r.Status != 200 {
		t.Fatalf("dev mail: %d %s", r.Status, r.Raw)
	}
	var mails []struct {
		To    string   `json:"to"`
		Token string   `json:"token"`
		Links []string `json:"links"`
	}
	r.data(&mails)
	if len(mails) != 1 || mails[0].Token == "" || !strings.Contains(mails[0].Links[0], "/auth/verify-email?token=") {
		t.Fatalf("mails: %s", r.Raw)
	}
	// The token from the inbox signs the person in.
	if r := tn.front("POST", "/v1/verify-email", obj{"token": mails[0].Token}, ""); r.Status != 200 {
		t.Fatalf("verify with the inbox token: %d %s", r.Status, r.Raw)
	}
	// Only this machine may read it.
	if r := e.call("GET", "/dev/mail", nil, "X-Forwarded-For", "203.0.113.9"); r.Status != 200 {
		t.Fatalf("a forwarded header from an untrusted proxy must be ignored: %d", r.Status)
	}
	if r := e.call("DELETE", "/dev/mail", nil); r.Status != 200 {
		t.Fatalf("clear: %d", r.Status)
	}
	e.call("GET", "/dev/mail", nil).data(&mails)
	if len(mails) != 0 {
		t.Fatal("inbox not emptied")
	}
}

func TestNoDevelopmentInboxWithATestMailbox(t *testing.T) {
	e := newEnv(t)
	if r := e.call("GET", "/dev/mail", nil); r.Status != 404 && r.Status != 405 {
		t.Fatalf("dev routes exist without an inbox: %d", r.Status)
	}
}
