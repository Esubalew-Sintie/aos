package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/rest"
)

// InitDevRoutes registers the development helpers. They exist only on a
// development engine that keeps emails in its inbox, and answer only
// requests from this machine.
func InitDevRoutes(r chi.Router, h rest.DevHandler) {
	RegisterRoutes(r, []Route{
		{Method: http.MethodGet, Path: "/dev/mail", Handler: h.ListMail},
		{Method: http.MethodDelete, Path: "/dev/mail", Handler: h.ClearMail},
	})
}
