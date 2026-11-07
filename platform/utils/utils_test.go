package utils

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name      string
		remote    string
		forwarded []string
		trusted   []netip.Prefix
		want      string
	}{
		{"no proxies trusted: the header is ignored",
			"203.0.113.9:4000", []string{"1.2.3.4"}, nil, "203.0.113.9"},
		{"a stranger cannot claim to be a proxy",
			"203.0.113.9:4000", []string{"1.2.3.4"}, proxies, "203.0.113.9"},
		{"a trusted proxy is believed",
			"10.0.0.5:4000", []string{"198.51.100.7"}, proxies, "198.51.100.7"},
		{"the nearest address that is not a proxy wins; the client's own claim is ignored",
			"10.0.0.5:4000", []string{"1.2.3.4, 198.51.100.7, 10.0.0.9"}, proxies, "198.51.100.7"},
		{"several header lines are read as one list",
			"10.0.0.5:4000", []string{"1.2.3.4", "198.51.100.7"}, proxies, "198.51.100.7"},
		{"a broken entry stops the search",
			"10.0.0.5:4000", []string{"1.2.3.4, garbage"}, proxies, "10.0.0.5"},
		{"a trusted proxy with no header is the client",
			"10.0.0.5:4000", nil, proxies, "10.0.0.5"},
		{"IPv6",
			"[2001:db8::1]:4000", nil, nil, "2001:db8::1"},
		{"IPv4 written as IPv6",
			"[::ffff:203.0.113.9]:4000", nil, nil, "203.0.113.9"},
		{"an unreadable address",
			"nonsense", nil, nil, ""},
	}
	for _, c := range cases {
		r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
		for _, v := range c.forwarded {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := ClientIP(r, c.trusted); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRequestIDsDiffer(t *testing.T) {
	if a, b := NewRequestID(), NewRequestID(); a == b || len(a) != 24 {
		t.Fatalf("request ids: %q %q", a, b)
	}
}
