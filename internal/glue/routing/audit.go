package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
)

// InitAuditRoutes registers the backend route that reads the audit log.
func InitAuditRoutes(r chi.Router, handler rest.AuditHandler, tenant *middleware.TenantMiddleware) {
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	RegisterRoutes(r, []Route{
		{Method: http.MethodGet, Path: "/v1/audit", Handler: handler.List, Middlewares: backend},
	})
}
