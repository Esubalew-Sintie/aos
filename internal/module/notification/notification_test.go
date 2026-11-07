package notification

import (
	"net/http"
	"testing"
)

func TestWants(t *testing.T) {
	for _, c := range []struct {
		types []string
		event string
		want  bool
	}{
		{[]string{"*"}, "user.created", true},
		{[]string{"user.created"}, "user.created", true},
		{[]string{"user.created"}, "user.deleted", false},
		{[]string{"user.*"}, "user.deleted", true},
		{[]string{"user.*"}, "session.created", false},
		{[]string{"user"}, "user.created", false},
		{nil, "user.created", false},
	} {
		if got := wants(c.types, c.event); got != c.want {
			t.Errorf("wants(%v, %q) = %v, want %v", c.types, c.event, got, c.want)
		}
	}
}

// In production, an endpoint may not point into the network the engine
// runs on. In development it may, so that a developer can test locally.
func TestCheckURLRefusesInternalAddresses(t *testing.T) {
	production := &notificationModule{client: &http.Client{}}
	development := &notificationModule{client: &http.Client{}, allowPrivate: true}

	for url, wantRefused := range map[string]bool{
		"https://127.0.0.1/hook":           true,
		"https://10.0.0.5/hook":            true,
		"https://192.168.1.9/hook":         true,
		"https://169.254.169.254/":         true, // a cloud metadata service
		"https://[::1]/hook":               true,
		"https://0.0.0.0/hook":             true,
		"http://203.0.113.9/hook":          true, // not https
		"https://user:pw@203.0.113.9/hook": false,
		"https://203.0.113.9/hook":         false,
		"not a url":                        true,
	} {
		err := production.checkURL(url)
		if (err != nil) != wantRefused {
			t.Errorf("production %s: refused=%v (%v), want %v", url, err != nil, err, wantRefused)
		}
	}
	if err := development.checkURL("http://127.0.0.1:8080/hook"); err != nil {
		t.Errorf("development should allow a local address: %v", err)
	}
}

func TestSignIsStable(t *testing.T) {
	a := Sign([]byte("secret"), "1700000000", []byte(`{"a":1}`))
	b := Sign([]byte("secret"), "1700000000", []byte(`{"a":1}`))
	c := Sign([]byte("secret"), "1700000001", []byte(`{"a":1}`))
	d := Sign([]byte("other"), "1700000000", []byte(`{"a":1}`))
	if a != b || a == c || a == d || len(a) != 64 {
		t.Fatalf("signatures: %s %s %s %s", a, b, c, d)
	}
}
