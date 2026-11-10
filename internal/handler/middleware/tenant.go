package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

// TenantMiddleware finds the tenant behind the key on a request. The API
// has two doors (user-flow SYS-2):
//
//   - the frontend routes, called from browsers with a publishable key;
//   - the backend routes, called from the application's server with a
//     secret key.
//
// A key of one kind is never accepted at the other door.
type TenantMiddleware struct {
	tenants module.Tenant
	log     logger.Logger
}

func NewTenantMiddleware(tenants module.Tenant, log logger.Logger) *TenantMiddleware {
	return &TenantMiddleware{tenants: tenants, log: log}
}

// RequirePublishableKey guards a frontend route.
func (m *TenantMiddleware) RequirePublishableKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, ok := m.resolve(w, r, r.Header.Get(constant.HeaderPublishableKey), constant.KeyKindPublishable)
		if !ok {
			return
		}

		// A browser states the page it is calling from. That address must
		// be on the tenant's list. A program that is not a browser sends
		// no Origin, and holds no cookies that could be abused.
		if origin := r.Header.Get("Origin"); origin != "" {
			allowed, err := m.tenants.IsAllowedOrigin(r.Context(), t.ID, origin)
			if err != nil {
				m.log.Error(r.Context(), "origin check failed", "error", err.Error(),
					"request_id", MetaFrom(r.Context()).RequestID)
				response.SendErrorResponse(w, errors.ErrUnexpected)
				return
			}
			if !allowed {
				response.SendErrorResponse(w, errors.ErrOriginNotAllowed)
				return
			}
			allowOrigin(w, origin)
		}

		next.ServeHTTP(w, r.WithContext(withKeyKind(withTenant(r.Context(), t), constant.KeyKindPublishable)))
	})
}

// RequireSecretKey guards a backend route.
func (m *TenantMiddleware) RequireSecretKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A call from inside this process (an embedded engine) names its
		// tenant directly instead of presenting the secret key.
		if slug, ok := trustedTenantFrom(r.Context()); ok {
			t, err := m.tenants.FindBySlug(r.Context(), slug)
			if err != nil {
				response.SendErrorResponse(w, err)
				return
			}
			if t.Status == constant.TenantSuspended || t.Status == constant.TenantDeleted {
				response.SendErrorResponse(w, errors.ErrTenantUnavailable)
				return
			}
			next.ServeHTTP(w, r.WithContext(withKeyKind(withTenant(r.Context(), t), constant.KeyKindSecret)))
			return
		}
		// A secret key must never be in a browser. A request that carries
		// an Origin came from one, so it is refused before the key is
		// even looked at.
		if r.Header.Get("Origin") != "" {
			response.SendErrorResponse(w, errors.ErrOriginNotAllowed)
			return
		}
		presented, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found {
			presented = ""
		}
		t, ok := m.resolve(w, r, presented, constant.KeyKindSecret)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(withKeyKind(withTenant(r.Context(), t), constant.KeyKindSecret)))
	})
}

// RequireTenantSlug guards a public route under /t/{slug}: the OAuth
// provider endpoints, which other applications and devices call with no
// key of ours. The tenant is named in the path.
func (m *TenantMiddleware) RequireTenantSlug(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		t, err := m.tenants.FindBySlug(r.Context(), slug)
		if err != nil {
			if _, isAppError := errors.AsAppError(err); !isAppError {
				m.log.Error(r.Context(), "tenant lookup failed", "error", err.Error(), "request_id", MetaFrom(r.Context()).RequestID)
			}
			response.SendErrorResponse(w, err)
			return
		}
		if t.Status == constant.TenantSuspended || t.Status == constant.TenantDeleted {
			response.SendErrorResponse(w, errors.ErrTenantUnavailable)
			return
		}
		// A public client in a browser may call the token endpoint from
		// anywhere. Nothing here uses a cookie.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r.WithContext(withKeyKind(withTenant(r.Context(), t), "public")))
	})
}

// RequireSCIMToken guards the directory sync routes. The company's
// identity provider sends the token it was given; it opens one
// organization's people and nothing else.
func RequireSCIMToken(resolve func(ctx context.Context, token string) (tenantID, directoryID, organizationID string, err error), log logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			tenantID, directoryID, organizationID, err := resolve(r.Context(), token)
			if err != nil {
				if _, isAppError := errors.AsAppError(err); !isAppError {
					log.Error(r.Context(), "scim token lookup failed", "error", err.Error(), "request_id", MetaFrom(r.Context()).RequestID)
				}
				w.Header().Set("Content-Type", "application/scim+json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"the sync token is not valid"}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(withDirectory(r.Context(), Directory{TenantID: tenantID, DirectoryID: directoryID, OrganizationID: organizationID})))
		})
	}
}

// resolve finds the tenant for a key of the wanted kind and checks that
// the tenant may be used. It writes the error answer itself.
func (m *TenantMiddleware) resolve(w http.ResponseWriter, r *http.Request, presented, wantKind string) (*model.Tenant, bool) {
	if presented == "" {
		response.SendErrorResponse(w, errors.ErrInvalidKey)
		return nil, false
	}
	t, kind, err := m.tenants.ResolveKey(r.Context(), presented)
	if err != nil {
		if _, isAppError := errors.AsAppError(err); !isAppError {
			m.log.Error(r.Context(), "key lookup failed", "error", err.Error(),
				"request_id", MetaFrom(r.Context()).RequestID)
		}
		response.SendErrorResponse(w, err)
		return nil, false
	}
	// A wrong kind of key gets the same answer as an unknown key.
	if kind != wantKind {
		response.SendErrorResponse(w, errors.ErrInvalidKey)
		return nil, false
	}
	if t.Status == constant.TenantSuspended || t.Status == constant.TenantDeleted {
		response.SendErrorResponse(w, errors.ErrTenantUnavailable)
		return nil, false
	}
	return t, true
}

// allowedHeaders are the request headers a browser may send.
var allowedHeaders = strings.Join([]string{
	"Content-Type", constant.HeaderPublishableKey, constant.HeaderSession, "Authorization",
}, ", ")

func allowOrigin(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", constant.HeaderRequestID)
	h.Add("Vary", "Origin")
}

// Preflight answers the question a browser asks before a cross-origin
// call. The tenant is not known yet, because a preflight carries no key,
// so this only says which methods and headers exist. The real request
// that follows is checked against the tenant's allowed origins, and a
// browser discards the answer to a request that fails that check.
func Preflight(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		allowOrigin(w, origin)
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", allowedHeaders)
	h.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}
