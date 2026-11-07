package initiator

import (
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/glue/routing"
	"github.com/flash-softeware/aos/platform/openapi"

	"github.com/flash-softeware/aos/platform/config"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/mailer"
	"github.com/flash-softeware/aos/platform/secret"
)

// RouteInfo is one route as the router holds it.
type RouteInfo struct {
	Method string
	Path   string
	// Door is how the route is reached: frontend (publishable key),
	// backend (secret key), public (/t/{slug}, no key), scim (sync
	// token), dev (development only) or open (health).
	Door string
}

// Routes lists every route the engine serves, sorted. It builds the
// router without a database, which is never touched while routing is set up.
func Routes() ([]RouteInfo, error) {
	master, err := secret.ParseMasterKey(secret.NewMasterKeyString())
	if err != nil {
		return nil, err
	}
	log := logger.NewDiscard()
	app, err := NewApp(config.Config{Env: "development", PublicURL: "https://aos.example"}, nil, master,
		ModuleOptions{Sender: mailer.NewInbox(log, 1), PasswordParams: secret.PasswordParams{MemoryKiB: 64, Time: 1, Threads: 1}}, log)
	if err != nil {
		return nil, err
	}
	var out []RouteInfo
	err = chi.Walk(app.Router.(chi.Router), func(method, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if method == http.MethodOptions {
			return nil
		}
		door := "open"
		for _, mw := range middlewares {
			name := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
			switch {
			case strings.Contains(name, "RequirePublishableKey"):
				door = "frontend"
			case strings.Contains(name, "RequireSecretKey"):
				door = "backend"
			case strings.Contains(name, "RequireTenantSlug"):
				door = "public"
			case strings.Contains(name, "RequireSCIMToken"):
				door = "scim"
			}
		}
		if strings.HasPrefix(route, "/dev/") {
			door = "dev"
		}
		out = append(out, RouteInfo{Method: method, Path: strings.TrimSuffix(route, "/"), Door: door})
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out, err
}

// OpenAPI builds the OpenAPI document of the engine's API from the router
// and the route docs. It fails when a route has no doc, or a doc no route.
func OpenAPI(version string) ([]byte, error) {
	routes, err := Routes()
	if err != nil {
		return nil, err
	}
	docs := map[string]routing.Doc{}
	for _, d := range routing.Docs {
		if strings.HasPrefix(d.Path, "{p}") {
			for _, prefix := range []string{"/v1", "/v1/admin"} {
				c := d
				c.Path = prefix + strings.TrimPrefix(d.Path, "{p}")
				docs[c.Method+" "+c.Path] = c
			}
			continue
		}
		docs[d.Method+" "+d.Path] = d
	}
	security := map[string]any{
		"publishableKey": map[string]any{"type": "apiKey", "in": "header", "name": "X-AOS-Publishable-Key",
			"description": "Frontend door. The person's session travels in the __Host-aos_session cookie, in X-AOS-Session (development tenants), or as Authorization: Bearer <access token> (token sessions)."},
		"secretKey":  map[string]any{"type": "http", "scheme": "bearer", "description": "Backend door: the tenant's secret key. Refused from browsers."},
		"scimToken":  map[string]any{"type": "http", "scheme": "bearer", "description": "The directory sync token from the SSO setup page."},
		"clientAuth": map[string]any{"type": "http", "scheme": "basic", "description": "OAuth client authentication, or client_id and client_secret in the form."},
	}
	doc := openapi.New("AOS identity engine", version,
		"Sign-in and fine-grained permissions for many applications. Envelope answers are {status, message, data, error}.", security)
	doc.SetSchema("Envelope", map[string]any{"type": "object", "properties": map[string]any{
		"status": map[string]any{"type": "integer"}, "message": map[string]any{"type": "string"}, "data": map[string]any{},
		"meta": map[string]any{}, "error": map[string]any{"type": "object", "properties": map[string]any{
			"type": map[string]any{"type": "string"}, "code": map[string]any{"type": "string"}, "message": map[string]any{"type": "string"},
			"details": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}}}}})
	seen := map[string]bool{}
	var missing []string
	for _, r := range routes {
		key := r.Method + " " + r.Path
		d, ok := docs[key]
		if !ok {
			missing = append(missing, key)
			continue
		}
		seen[key] = true
		op := openapi.Operation{Method: r.Method, Path: r.Path, Summary: d.Summary, Request: d.Request, Response: d.Response, Envelope: !d.Raw, Form: d.Form, Tag: tagOf(r.Path)}
		switch r.Door {
		case "frontend":
			op.Security = "publishableKey"
		case "backend":
			op.Security = "secretKey"
		case "scim":
			op.Security = "scimToken"
		case "public":
			if d.Form && !strings.HasSuffix(r.Path, "/device") {
				op.Security = "clientAuth"
			}
		}
		doc.Add(op)
	}
	var stale []string
	for key := range docs {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		return nil, fmt.Errorf("openapi: routes without a doc: %v; docs without a route: %v", missing, stale)
	}
	return doc.JSON()
}

func tagOf(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case parts[0] == "t":
		return "oauth-provider"
	case parts[0] == "scim":
		return "scim"
	case parts[0] == "dev", parts[0] == "healthz", parts[0] == "readyz":
		return "operations"
	case len(parts) > 2 && parts[1] == "platform" && parts[2] == "admin":
		return "platform-admin"
	case len(parts) > 1 && parts[1] == "platform":
		return "platform"
	case len(parts) > 2 && parts[1] == "admin":
		return parts[2]
	case len(parts) > 2 && parts[1] == "me":
		return "me"
	case len(parts) > 1:
		return parts[1]
	}
	return "other"
}
