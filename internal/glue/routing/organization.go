package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
)

// InitOrganizationRoutes registers the organization routes at both doors.
// Behind the frontend door the signed-in person acts, bound by their
// grants. Behind the backend door, under /v1/admin, the application acts
// as Root.
func InitOrganizationRoutes(r chi.Router, handler rest.OrganizationHandler, tenant *middleware.TenantMiddleware) {
	frontend := []func(next http.Handler) http.Handler{tenant.RequirePublishableKey}
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}

	for _, door := range []struct {
		prefix string
		mw     []func(next http.Handler) http.Handler
	}{
		{"/v1", frontend},
		{"/v1/admin", backend},
	} {
		p := door.prefix
		RegisterRoutes(r, []Route{
			{Method: http.MethodPost, Path: p + "/organizations", Handler: handler.Create, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations", Handler: handler.List, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations/{id}", Handler: handler.Get, Middlewares: door.mw},
			{Method: http.MethodDelete, Path: p + "/organizations/{id}", Handler: handler.Delete, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations/{id}/members", Handler: handler.ListMembers, Middlewares: door.mw},
			{Method: http.MethodPut, Path: p + "/organizations/{id}/members/{principal_id}/role", Handler: handler.ChangeMemberRole, Middlewares: door.mw},
			{Method: http.MethodDelete, Path: p + "/organizations/{id}/members/{principal_id}", Handler: handler.RemoveMember, Middlewares: door.mw},
			{Method: http.MethodPost, Path: p + "/organizations/{id}/invitations", Handler: handler.Invite, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations/{id}/invitations", Handler: handler.ListInvitations, Middlewares: door.mw},
			{Method: http.MethodDelete, Path: p + "/organizations/{id}/invitations/{invitation_id}", Handler: handler.RevokeInvitation, Middlewares: door.mw},
		})
	}

	// Switching is a session matter, so it exists only at the frontend door.
	// The invitation routes are reached from the link in the email.
	RegisterRoutes(r, []Route{
		{Method: http.MethodPost, Path: "/v1/organizations/{id}/switch", Handler: handler.Switch, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/invitations/{token}", Handler: handler.PreviewInvitation, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/invitations/accept", Handler: handler.AcceptInvitation, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/invitations/decline", Handler: handler.DeclineInvitation, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/invitations/sign-up", Handler: handler.SignUpByInvitation, Middlewares: frontend},
	})
}
