package routing

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	"github.com/flash-software-technology/aos/platform/logger"
)

// InitEnterpriseRoutes registers SSO connections (both doors), the setup
// page (opened with its link, no account needed), enterprise sign-in and
// organization policies.
func InitEnterpriseRoutes(r chi.Router, h rest.EnterpriseHandler, tenant *middleware.TenantMiddleware) {
	frontend := []func(next http.Handler) http.Handler{tenant.RequirePublishableKey}
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	for _, door := range []struct {
		prefix string
		mw     []func(next http.Handler) http.Handler
	}{{"/v1", frontend}, {"/v1/admin", backend}} {
		p := door.prefix
		RegisterRoutes(r, []Route{
			{Method: http.MethodPost, Path: p + "/sso/connections", Handler: h.CreateConnection, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations/{id}/sso", Handler: h.ListConnections, Middlewares: door.mw},
			{Method: http.MethodPost, Path: p + "/sso/connections/{id}/setup-link", Handler: h.NewSetupLink, Middlewares: door.mw},
			{Method: http.MethodDelete, Path: p + "/sso/connections/{id}", Handler: h.DisableConnection, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations/{id}/policies", Handler: h.GetPolicies, Middlewares: door.mw},
			{Method: http.MethodPatch, Path: p + "/organizations/{id}/policies", Handler: h.SetPolicies, Middlewares: door.mw},
		})
	}
	RegisterRoutes(r, []Route{
		{Method: http.MethodGet, Path: "/v1/sso/setup/{token}", Handler: h.SetupView, Middlewares: frontend},
		{Method: http.MethodPut, Path: "/v1/sso/setup/{token}/settings", Handler: h.SetupSettings, Middlewares: frontend},
		{Method: http.MethodPut, Path: "/v1/sso/setup/{token}/mappings", Handler: h.SetupMappings, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/setup/{token}/domains", Handler: h.SetupAddDomain, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/setup/{token}/domains/{domain_id}/verify", Handler: h.SetupVerifyDomain, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/setup/{token}/test", Handler: h.SetupTest, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/setup/{token}/activate", Handler: h.SetupActivate, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/setup/{token}/directory", Handler: h.SetupCreateDirectory, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/start", Handler: h.StartSSO, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sso/finish", Handler: h.FinishSSO, Middlewares: frontend},
	})
}

// InitSCIMRoutes registers directory sync. The identity provider calls
// these with the sync token; no key of ours is involved.
func InitSCIMRoutes(r chi.Router, h rest.SCIMHandler, resolve func(ctx context.Context, token string) (string, string, string, error), log logger.Logger) {
	guard := []func(next http.Handler) http.Handler{middleware.RequireSCIMToken(resolve, log)}
	RegisterRoutes(r, []Route{
		{Method: http.MethodGet, Path: "/scim/v2/ServiceProviderConfig", Handler: h.ServiceProviderConfig, Middlewares: guard},
		{Method: http.MethodGet, Path: "/scim/v2/Users", Handler: h.ListUsers, Middlewares: guard},
		{Method: http.MethodPost, Path: "/scim/v2/Users", Handler: h.CreateUser, Middlewares: guard},
		{Method: http.MethodGet, Path: "/scim/v2/Users/{id}", Handler: h.GetUser, Middlewares: guard},
		{Method: http.MethodPut, Path: "/scim/v2/Users/{id}", Handler: h.ReplaceUser, Middlewares: guard},
		{Method: http.MethodPatch, Path: "/scim/v2/Users/{id}", Handler: h.PatchUser, Middlewares: guard},
		{Method: http.MethodDelete, Path: "/scim/v2/Users/{id}", Handler: h.DeleteUser, Middlewares: guard},
		{Method: http.MethodGet, Path: "/scim/v2/Groups", Handler: h.ListGroups, Middlewares: guard},
		{Method: http.MethodPost, Path: "/scim/v2/Groups", Handler: h.CreateGroup, Middlewares: guard},
		{Method: http.MethodGet, Path: "/scim/v2/Groups/{id}", Handler: h.GetGroup, Middlewares: guard},
		{Method: http.MethodPut, Path: "/scim/v2/Groups/{id}", Handler: h.ReplaceGroup, Middlewares: guard},
		{Method: http.MethodPatch, Path: "/scim/v2/Groups/{id}", Handler: h.PatchGroup, Middlewares: guard},
		{Method: http.MethodDelete, Path: "/scim/v2/Groups/{id}", Handler: h.DeleteGroup, Middlewares: guard},
	})
}
