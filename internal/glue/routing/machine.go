package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
)

// InitMachineRoutes registers the routes for service accounts, agents,
// API keys, delegations and approvals. Management is at the backend
// door; what a person does for themselves is at the frontend door.
func InitMachineRoutes(r chi.Router, h rest.MachineHandler, tenant *middleware.TenantMiddleware) {
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}
	frontend := []func(next http.Handler) http.Handler{tenant.RequirePublishableKey}

	RegisterRoutes(r, []Route{
		{Method: http.MethodPost, Path: "/v1/service-accounts", Handler: h.CreateServiceAccount, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/service-accounts", Handler: h.ListServiceAccounts, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/agents", Handler: h.CreateAgent, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/agents", Handler: h.ListAgents, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/machines/{id}", Handler: h.GetMachine, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/machines/{id}/disable", Handler: h.DisableMachine, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/machines/{id}/enable", Handler: h.EnableMachine, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/machines/{id}/revoke", Handler: h.RevokeAgent, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/machines/{id}/audit", Handler: h.AgentAudit, Middlewares: backend},

		{Method: http.MethodPost, Path: "/v1/api-keys", Handler: h.CreateAPIKey, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/api-keys", Handler: h.ListAPIKeys, Middlewares: backend},
		{Method: http.MethodDelete, Path: "/v1/api-keys/{id}", Handler: h.RevokeAPIKey, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/api-keys/check", Handler: h.CheckAPIKey, Middlewares: backend},
		{Method: http.MethodGet, Path: "/v1/approvals/{id}", Handler: h.GetApproval, Middlewares: backend},

		{Method: http.MethodPost, Path: "/v1/me/api-keys", Handler: h.CreateAPIKey, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/api-keys", Handler: h.ListAPIKeys, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/me/api-keys/{id}", Handler: h.RevokeAPIKey, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/delegations", Handler: h.CreateDelegation, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/delegations", Handler: h.ListDelegations, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/me/delegations/{id}", Handler: h.RevokeDelegation, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/approvals", Handler: h.ListApprovals, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/approvals/{id}/approve", Handler: h.ApproveApproval, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/approvals/{id}/decline", Handler: h.DeclineApproval, Middlewares: frontend},
	})
}
