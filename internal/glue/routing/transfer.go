package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
)

// InitTransferRoutes registers import, export and access reviews. Moving
// people is the application's to do (backend door); reviews are open to
// both doors.
func InitTransferRoutes(r chi.Router, h rest.TransferHandler, tenant *middleware.TenantMiddleware) {
	frontend := []func(next http.Handler) http.Handler{tenant.RequirePublishableKey}
	backend := []func(next http.Handler) http.Handler{tenant.RequireSecretKey}
	RegisterRoutes(r, []Route{
		{Method: http.MethodPost, Path: "/v1/import/users", Handler: h.ImportUsers, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/export", Handler: h.Export, Middlewares: backend},
		{Method: http.MethodPost, Path: "/v1/import/archive", Handler: h.Import, Middlewares: backend},
	})
	for _, door := range []struct {
		prefix string
		mw     []func(next http.Handler) http.Handler
	}{{"/v1", frontend}, {"/v1/admin", backend}} {
		p := door.prefix
		RegisterRoutes(r, []Route{
			{Method: http.MethodPost, Path: p + "/access-reviews", Handler: h.StartReview, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/organizations/{id}/access-reviews", Handler: h.ListReviews, Middlewares: door.mw},
			{Method: http.MethodGet, Path: p + "/access-reviews/{id}", Handler: h.GetReview, Middlewares: door.mw},
			{Method: http.MethodPost, Path: p + "/access-reviews/{id}/items/{item_id}", Handler: h.DecideReview, Middlewares: door.mw},
		})
	}
}
