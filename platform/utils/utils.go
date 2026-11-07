// Package utils holds small helpers with no home of their own.
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the address a request came from.
//
// By default that is the address of the connection itself, and the
// X-Forwarded-For header is ignored: any client can write anything
// there. The header is believed only when the connection comes from a
// proxy the operator listed as trusted. Then the answer is the nearest
// address in the header that is not itself a trusted proxy.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	remote := parseAddr(r.RemoteAddr)
	if !remote.IsValid() {
		return ""
	}
	if !isTrusted(remote, trusted) {
		return remote.String()
	}

	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A broken entry. Nothing to the left of it can be believed.
			break
		}
		addr = addr.Unmap()
		if !isTrusted(addr, trusted) {
			return addr.String()
		}
	}
	return remote.String()
}

func parseAddr(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// NewRequestID returns a random id for one request.
func NewRequestID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
