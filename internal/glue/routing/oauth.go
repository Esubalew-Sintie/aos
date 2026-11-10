package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
)

// InitOAuthRoutes registers the tenant's OAuth and OpenID Connect
// provider: the public endpoints under /t/{slug}, the consent routes a
// signed-in person uses, and the client registry at the backend door.
func InitOAuthRoutes(r chi.Router, h rest.OAuthHandler, tenant *middleware.TenantMiddleware) {
	public := []func(next http.Handler) http.Handler{tenant.RequireTenantSlug}
	frontend := []func(next http.Handler) http.Handler{tenant.RequirePublishableKey}
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	RegisterRoutes(r, []Route{
		{Method: http.MethodGet, Path: "/t/{slug}/.well-known/openid-configuration", Handler: h.Discovery, Middlewares: public},
		{Method: http.MethodGet, Path: "/t/{slug}/.well-known/oauth-authorization-server", Handler: h.Discovery, Middlewares: public},
		{Method: http.MethodGet, Path: "/t/{slug}/oauth/jwks.json", Handler: h.JWKS, Middlewares: public},
		{Method: http.MethodGet, Path: "/t/{slug}/oauth/authorize", Handler: h.Authorize, Middlewares: public},
		{Method: http.MethodPost, Path: "/t/{slug}/oauth/token", Handler: h.Token, Middlewares: public},
		{Method: http.MethodPost, Path: "/t/{slug}/oauth/device", Handler: h.DeviceAuthorization, Middlewares: public},
		{Method: http.MethodGet, Path: "/t/{slug}/oauth/userinfo", Handler: h.UserInfo, Middlewares: public},
		{Method: http.MethodPost, Path: "/t/{slug}/oauth/introspect", Handler: h.Introspect, Middlewares: public},
		{Method: http.MethodPost, Path: "/t/{slug}/oauth/revoke", Handler: h.Revoke, Middlewares: public},

		{Method: http.MethodGet, Path: "/v1/oauth/requests/{id}", Handler: h.GetAuthorizationRequest, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/oauth/consent", Handler: h.Consent, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/oauth/device/approve", Handler: h.ApproveDevice, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/consents", Handler: h.ListConsents, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/me/consents/{client_id}", Handler: h.RevokeConsent, Middlewares: frontend},

		{Method: http.MethodPut, Path: "/v1/oauth-clients", Handler: h.PutClient, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/oauth-clients", Handler: h.ListClients, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/oauth-clients/{id}", Handler: h.DisableClient, Middlewares: backend},
	})
}
