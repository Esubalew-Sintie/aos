package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
)

// InitUserRoutes registers the backend routes for accounts.
func InitUserRoutes(r chi.Router, handler rest.UserHandler, tenant *middleware.TenantMiddleware) {
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	RegisterRoutes(r, []Route{
		{Method: http.MethodGet, Path: "/v1/users", Handler: handler.ListUsers, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/users", Handler: handler.CreateUser, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/users/{id}", Handler: handler.GetUser, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/users/{id}/suspend", Handler: handler.SuspendUser, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/users/{id}/reinstate", Handler: handler.ReinstateUser, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/users/{id}", Handler: handler.DeleteUser, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/users/{id}/second-factor/reset", Handler: handler.ResetSecondFactor, Middlewares: backend},
	})
}
