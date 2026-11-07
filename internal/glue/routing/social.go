package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
)

// InitSocialRoutes registers the backend routes for social sign-in providers.
func InitSocialRoutes(r chi.Router, handler rest.SocialProviderHandler, tenant *middleware.TenantMiddleware) {
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}
	RegisterRoutes(r, []Route{
		{Method: http.MethodPut, Path: "/v1/oauth-providers", Handler: handler.Put, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/oauth-providers", Handler: handler.List, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/oauth-providers/{provider}", Handler: handler.Delete, Middlewares: backend},
	})
}
