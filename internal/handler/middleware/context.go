// Package middleware holds what runs around every handler.
package middleware

import (
	"context"

	"github.com/flash-software-technology/aos/internal/constant/model"
)

type contextKey int

const (
	tenantKey contextKey = iota
	metaKey
	keyKindKey
	directoryKey
	trustedTenantKey
)

// WithTrustedTenant marks a request made inside this process for a
// tenant's backend door (the engine package's in-process transport). It
// stands in for the secret key. A request from the network can never
// carry it: only code in the same process can set a context value.
func WithTrustedTenant(ctx context.Context, slug string) context.Context {
	return context.WithValue(ctx, trustedTenantKey, slug)
}

func trustedTenantFrom(ctx context.Context) (string, bool) {
	slug, ok := ctx.Value(trustedTenantKey).(string)
	return slug, ok && slug != ""
}

// Directory is what a sync token resolved to.
type Directory struct {
	TenantID       string
	DirectoryID    string
	OrganizationID string
}

func withDirectory(ctx context.Context, d Directory) context.Context {
	return context.WithValue(ctx, directoryKey, d)
}

// DirectoryFrom returns the directory behind a SCIM request.
func DirectoryFrom(ctx context.Context) Directory {
	d, _ := ctx.Value(directoryKey).(Directory)
	return d
}

func withKeyKind(ctx context.Context, kind string) context.Context {
	return context.WithValue(ctx, keyKindKey, kind)
}

// KeyKindFrom returns which door the request came through: "publishable"
// for the frontend routes, "secret" for the backend routes.
func KeyKindFrom(ctx context.Context) string {
	k, _ := ctx.Value(keyKindKey).(string)
	return k
}

func withTenant(ctx context.Context, t *model.Tenant) context.Context {
	return context.WithValue(ctx, tenantKey, t)
}

// TenantFrom returns the tenant the request belongs to. It is set by
// RequirePublishableKey or RequireSecretKey, and nil on any route that
// has neither.
func TenantFrom(ctx context.Context) *model.Tenant {
	t, _ := ctx.Value(tenantKey).(*model.Tenant)
	return t
}

func withMeta(ctx context.Context, m model.RequestMeta) context.Context {
	return context.WithValue(ctx, metaKey, m)
}

// MetaFrom returns where the request came from.
func MetaFrom(ctx context.Context) model.RequestMeta {
	m, _ := ctx.Value(metaKey).(model.RequestMeta)
	return m
}
