package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
)

// InitIamRoutes registers the backend routes. Every one needs a secret
// key, so none of them can be reached from a browser.
func InitIamRoutes(r chi.Router, handler rest.IAMHandler, tenant *middleware.TenantMiddleware) {
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	RegisterRoutes(r, []Route{
		{Method: http.MethodPost, Path: "/v1/can", Handler: handler.Can, Middlewares: backend},
		{Method: http.MethodPut, Path: "/v1/permissions", Handler: handler.PutPermission, Middlewares: backend},
		{Method: http.MethodPut, Path: "/v1/roles", Handler: handler.PutRole, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/permissions", Handler: handler.ListPermissions, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/roles", Handler: handler.ListRoles, Middlewares: backend},
		{Method: http.MethodPut, Path: "/v1/resources", Handler: handler.CreateResource, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/grants", Handler: handler.CreateGrant, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/grants/{id}", Handler: handler.DeleteGrant, Middlewares: backend},

		// The other questions (user-flow PERM-3 to PERM-7).
		{Method: http.MethodPost, Path: "/v1/can/batch", Handler: handler.CanBatch, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/explain", Handler: handler.Explain, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/filter", Handler: handler.Filter, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/principals", Handler: handler.ListPrincipals, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/simulate", Handler: handler.Simulate, Middlewares: backend},

		// Groups (user-flow PERM-8).
		{Method: http.MethodPut, Path: "/v1/groups", Handler: handler.PutGroup, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/groups", Handler: handler.ListGroups, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/groups/{id}", Handler: handler.DeleteGroup, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/groups/{id}/members", Handler: handler.AddGroupMember, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/groups/{id}/members/{principal_id}", Handler: handler.RemoveGroupMember, Middlewares: backend},
	})
}
