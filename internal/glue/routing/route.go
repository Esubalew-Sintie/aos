// Package routing connects URLs to handlers.
package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Route struct {
	Method      string
	Path        string
	Handler     func(w http.ResponseWriter, r *http.Request)
	Middlewares []func(next http.Handler) http.Handler
}

func RegisterRoutes(router chi.Router, routes []Route) {
	for _, route := range routes {
		router.With(route.Middlewares...).Method(route.Method, route.Path, http.HandlerFunc(route.Handler))
	}
}
