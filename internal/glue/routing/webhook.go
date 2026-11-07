package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
)

// InitWebhookRoutes registers the backend routes for the endpoints the
// engine calls.
func InitWebhookRoutes(r chi.Router, handler rest.WebhookHandler, tenant *middleware.TenantMiddleware) {
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	RegisterRoutes(r, []Route{
		{Method: http.MethodPost, Path: "/v1/webhooks", Handler: handler.Create, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/webhooks", Handler: handler.List, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/webhooks/{id}", Handler: handler.Delete, Middlewares: backend},
	})
}
