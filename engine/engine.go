// Package engine is the AOS identity engine as a Go package: sign-up and
// sign-in, sessions, permissions, organizations and the rest, served
// from a Postgres database.
//
// An Engine is multi-tenant: one engine serves many applications, each a
// tenant with its own keys. It is what the aos program and the hosted
// service run. To put the engine inside one application's own backend,
// use the embed package instead.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"

	"github.com/flash-software-technology/aos/initiator"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	apperrors "github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/mailer"
	"github.com/flash-software-technology/aos/platform/postgres"
	"github.com/flash-software-technology/aos/platform/secret"
	"github.com/jackc/pgx/v5"
)

// Config is how an engine is set up. DatabaseURL and MasterKey are required.
type Config struct {
	// DatabaseURL is the Postgres connection string. The engine keeps its
	// tables in its own schemas; the schema is created or upgraded on start.
	DatabaseURL string
	// MasterKey wraps every tenant's keys: base64 of 32 random bytes (see
	// NewMasterKey). Losing it makes every tenant's secrets unreadable.
	MasterKey string
	// PublicURL is the address the engine is reached at, such as
	// https://auth.example.com. It is the issuer of the tokens it signs
	// as an OAuth provider.
	PublicURL string
	// Development relaxes what production forbids: email without SMTP is
	// kept in a development inbox (/dev/mail), and webhooks may point at
	// this machine.
	Development bool
	// Sender delivers email. Nil means SMTP when SMTPAddr is set, the
	// development inbox in development, and an error otherwise.
	Sender                                         mailer.Sender
	SMTPAddr, SMTPUsername, SMTPPassword, MailFrom string
	// TrustedProxies are the networks whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix
	// Logger receives the engine's log. Nil means a default one.
	Logger logger.Logger
}

// Engine is a running engine.
type Engine struct {
	app *initiator.App
	db  *postgres.DB
	log logger.Logger
}

// NewMasterKey returns a new random master key for Config.MasterKey.
func NewMasterKey() string { return secret.NewMasterKeyString() }

// New connects to the database, applies the schema and wires the engine.
// Call Run to deliver email and webhooks, and Close when done.
func New(ctx context.Context, cfg Config) (*Engine, error) {
	if cfg.DatabaseURL == "" {
		return nil, errors.New("engine: DatabaseURL is required")
	}
	if cfg.MasterKey == "" {
		return nil, errors.New("engine: MasterKey is required (make one with engine.NewMasterKey)")
	}
	c := config.Config{
		DatabaseURL: cfg.DatabaseURL, MasterKey: cfg.MasterKey,
		PublicURL: strings.TrimRight(cfg.PublicURL, "/"), Env: "production",
		TrustedProxies: cfg.TrustedProxies,
		SMTPAddr:       cfg.SMTPAddr, SMTPUsername: cfg.SMTPUsername, SMTPPassword: cfg.SMTPPassword, MailFrom: cfg.MailFrom,
		BreachCheck: "local",
	}
	if cfg.Development {
		c.Env = "development"
	}
	log := cfg.Logger
	if log == nil {
		log = initiator.InitLogger(c)
	}
	master, err := initiator.InitMasterKey(c)
	if err != nil {
		return nil, fmt.Errorf("engine: master key: %w", err)
	}
	sender := cfg.Sender
	if sender == nil {
		if sender, err = initiator.InitMailer(c, log); err != nil {
			return nil, fmt.Errorf("engine: %w", err)
		}
	}
	db, err := initiator.InitDatabase(ctx, c, log)
	if err != nil {
		return nil, fmt.Errorf("engine: database: %w", err)
	}
	app, err := initiator.NewApp(c, db, master, initiator.ModuleOptions{
		Sender: sender, Breach: initiator.InitBreachChecker(c, log), AllowPrivateWebhooks: c.Development(),
	}, log)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Engine{app: app, db: db, log: log}, nil
}

// Handler serves every route of the API: /v1/..., /t/{slug}/..., /scim/v2/...
func (e *Engine) Handler() http.Handler { return e.app.Router }

// Run delivers email and webhooks until ctx ends. Run it in its own
// goroutine; several engines on one database share the work safely.
func (e *Engine) Run(ctx context.Context) { e.app.Module.Notification.Run(ctx) }

// Close releases the database connections.
func (e *Engine) Close() { e.db.Close() }

// TenantSpec describes a new tenant.
type TenantSpec struct {
	Slug string
	Name string
	// Kind is "single" or "multi" (with organizations).
	Kind string
	// Environment is "development", "staging" or "production".
	Environment string
	// AppURL is the application's own address; email links point there.
	AppURL string
	// Origins are the browser origins allowed to call the frontend routes.
	Origins []string
}

// TenantKeys are a new tenant's keys. SecretKey is shown only here.
type TenantKeys struct {
	TenantID       string
	Slug           string
	PublishableKey string
	SecretKey      string
}

// CreateTenant makes a tenant and its keys.
func (e *Engine) CreateTenant(ctx context.Context, s TenantSpec) (*TenantKeys, error) {
	out, err := e.app.Module.Tenant.Create(ctx, request.CreateTenantRequest{
		Slug: s.Slug, Name: s.Name, Kind: s.Kind, Environment: s.Environment, AppURL: s.AppURL, AllowedOrigins: s.Origins,
	})
	if err != nil {
		return nil, describe(err)
	}
	return &TenantKeys{TenantID: out.TenantID, Slug: out.Slug, PublishableKey: out.PublishableKey, SecretKey: out.SecretKey}, nil
}

// ErrNoTenant is returned for a slug no tenant has.
var ErrNoTenant = errors.New("engine: no such tenant")

// PublishableKey returns a tenant's live publishable key.
func (e *Engine) PublishableKey(ctx context.Context, slug string) (string, error) {
	t, err := e.app.Module.Tenant.FindBySlug(ctx, slug)
	if err != nil {
		if ae, ok := apperrors.AsAppError(err); ok && ae.Status == http.StatusNotFound {
			return "", ErrNoTenant
		}
		return "", err
	}
	var key string
	err = e.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		key, err = e.app.Storage.OAuthRepo.PublishableKey(ctx, tx, t.ID)
		return err
	})
	if err == nil && key == "" {
		err = errors.New("engine: the tenant has no publishable key")
	}
	return key, err
}

// Transport returns an http.RoundTripper that serves requests inside this
// process, as the tenant's backend. Give it to an SDK client (aos-go's
// Config.HTTPClient) to call the backend routes with no network and no
// secret key.
func (e *Engine) Transport(slug string) http.RoundTripper {
	return inProcess{h: e.app.Router, slug: slug}
}

// TenantHandler serves every request as the tenant's backend, trusted
// like Transport's. Put it only behind an authentication of your own,
// such as the local token of the aos app command.
func (e *Engine) TenantHandler(slug string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(middleware.WithTrustedTenant(r.Context(), slug))
		r.Header.Del("Origin")
		e.app.Router.ServeHTTP(w, r)
	})
}

type inProcess struct {
	h    http.Handler
	slug string
}

func (t inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(middleware.WithTrustedTenant(req.Context(), t.slug))
	r.RequestURI = req.URL.RequestURI()
	r.RemoteAddr = "127.0.0.1:0"
	// The backend door refuses browsers by their Origin; this is not one.
	r.Header.Del("Origin")
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func describe(err error) error {
	ae, ok := apperrors.AsAppError(err)
	if !ok {
		return err
	}
	if len(ae.Details) == 0 {
		return fmt.Errorf("engine: %s", ae.Message)
	}
	var parts []string
	for k, v := range ae.Details {
		parts = append(parts, k+": "+v)
	}
	return fmt.Errorf("engine: %s (%s)", ae.Message, strings.Join(parts, "; "))
}
