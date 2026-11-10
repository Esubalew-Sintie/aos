package initiator

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/glue/routing"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	rest_dev "github.com/flash-software-technology/aos/internal/handler/rest/http/dev"
	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/mailer"
	"github.com/flash-software-technology/aos/platform/postgres"
)

func InitRoutes(r chi.Router, handler Handler, module Module, cfg config.Config, db *postgres.DB, inbox *mailer.Inbox, log logger.Logger,
	extra ...func(r chi.Router, tenant *middleware.TenantMiddleware)) {
	r.Use(middleware.RequestContext(cfg.TrustedProxies))
	r.Use(middleware.Recovery(log.Named("recovery")))
	r.Use(middleware.AccessLog(log.Named("http")))

	// Is the process up?
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Can it serve requests? It cannot without the database.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// A browser asks before a cross-origin call.
	r.Options("/v1/*", middleware.Preflight)
	r.Options("/t/*", middleware.Preflight)

	tenantMiddleware := middleware.NewTenantMiddleware(module.Tenant, log.Named("middleware.tenant"))
	routing.InitAuthRoutes(r, handler.AuthHandler, tenantMiddleware)
	routing.InitIamRoutes(r, handler.IAMHandler, tenantMiddleware)
	routing.InitUserRoutes(r, handler.UserHandler, tenantMiddleware)
	routing.InitAuditRoutes(r, handler.AuditHandler, tenantMiddleware)
	routing.InitWebhookRoutes(r, handler.WebhookHandler, tenantMiddleware)
	routing.InitOrganizationRoutes(r, handler.OrganizationHandler, tenantMiddleware)
	routing.InitSocialRoutes(r, handler.SocialHandler, tenantMiddleware)
	routing.InitMachineRoutes(r, handler.MachineHandler, tenantMiddleware)
	routing.InitOAuthRoutes(r, handler.OAuthHandler, tenantMiddleware)
	routing.InitEnterpriseRoutes(r, handler.EnterpriseHandler, tenantMiddleware)
	routing.InitTransferRoutes(r, handler.TransferHandler, tenantMiddleware)
	if inbox != nil && cfg.Development() {
		routing.InitDevRoutes(r, rest_dev.NewDevHandler(inbox))
	}
	routing.InitSCIMRoutes(r, handler.SCIMHandler, module.Enterprise.ResolveDirectory, log.Named("middleware.scim"))
	for _, add := range extra {
		add(r, tenantMiddleware)
	}
}
