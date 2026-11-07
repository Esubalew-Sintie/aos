// Package embed runs the AOS engine inside one application's own Go
// backend, with its users in the application's own Postgres. There is no
// separate auth server to deploy.
//
//	auth, err := embed.New(ctx, embed.Config{
//		DatabaseURL: os.Getenv("DATABASE_URL"),
//		MasterKey:   os.Getenv("AOS_MASTER_KEY"),
//		AppURL:      "https://shop.example.com",
//	})
//	defer auth.Close()
//	mux.Handle("/aos/", auth.Handler())        // the routes the browser SDK calls
//	mux.Handle("GET /api/invoices", auth.Middleware(
//		auth.RequirePermission("invoice.read", aos.ActiveOrganization)(invoices)))
//
// Auth has every method of the Go SDK's client (aos-go): Middleware,
// RequirePermission, Can, CreateUser, CanHandler and the rest, answered
// inside the process. Code written against the hosted service keeps
// working; only how the client is made changes.
package embed

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	aos "github.com/flash-softeware/aos-go"

	"github.com/flash-softeware/aos/engine"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/mailer"
)

// Config sets up an embedded engine. DatabaseURL, MasterKey and AppURL
// are required.
type Config struct {
	// DatabaseURL is the application's Postgres. The engine keeps its
	// tables in its own schemas (aos, aos_platform) and creates or
	// upgrades them on start.
	DatabaseURL string
	// MasterKey wraps the engine's keys: base64 of 32 random bytes
	// (engine.NewMasterKey). Keep it out of the database and out of git.
	MasterKey string
	// AppURL is the application's address. Links in emails point there,
	// and its origin may call the routes from a browser.
	AppURL string
	// Path is where Handler is mounted. Default "/aos".
	Path string
	// Origins are more browser origins allowed to call the routes, such
	// as a frontend dev server. AppURL's origin is always allowed.
	Origins []string
	// Slug and Name name the application. Default "app" and "App".
	Slug, Name string
	// Kind is "multi" (with organizations, the default) or "single".
	Kind string
	// Development keeps email in a development inbox at <Path>/dev/mail
	// when no SMTP is set, and hands sessions to the browser in a header.
	Development bool
	// Sender delivers email; nil means SMTP when SMTPAddr is set.
	Sender                                         mailer.Sender
	SMTPAddr, SMTPUsername, SMTPPassword, MailFrom string
	// TrustedProxies are the networks whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix
	// Logger receives the engine's log. Nil means a default one.
	Logger logger.Logger
}

// Auth is an engine running inside the application.
type Auth struct {
	// Client answers every SDK call inside the process.
	*aos.Client
	eng    *engine.Engine
	path   string
	pk     string
	cancel context.CancelFunc
}

// The same methods, in the hosted and the embedded form.
var _ aos.Auth = (*Auth)(nil)

// New starts the engine: the schema, the application's tenant (made on
// first start) and the delivery of email and webhooks in the background.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	app, err := url.Parse(cfg.AppURL)
	if err != nil || app.Scheme == "" || app.Host == "" {
		return nil, errors.New("embed: AppURL must be an address such as https://shop.example.com")
	}
	if cfg.Path == "" {
		cfg.Path = "/aos"
	}
	cfg.Path = "/" + strings.Trim(cfg.Path, "/")
	if cfg.Slug == "" {
		cfg.Slug = "app"
	}
	if cfg.Name == "" {
		cfg.Name = "App"
	}
	if cfg.Kind == "" {
		cfg.Kind = "multi"
	}
	origin := app.Scheme + "://" + app.Host
	public := origin + cfg.Path

	eng, err := engine.New(ctx, engine.Config{
		DatabaseURL: cfg.DatabaseURL, MasterKey: cfg.MasterKey, PublicURL: public,
		Development: cfg.Development, Sender: cfg.Sender,
		SMTPAddr: cfg.SMTPAddr, SMTPUsername: cfg.SMTPUsername, SMTPPassword: cfg.SMTPPassword, MailFrom: cfg.MailFrom,
		TrustedProxies: cfg.TrustedProxies, Logger: cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	pk, err := eng.PublishableKey(ctx, cfg.Slug)
	if errors.Is(err, engine.ErrNoTenant) {
		env := "production"
		if cfg.Development {
			env = "development"
		}
		var keys *engine.TenantKeys
		keys, err = eng.CreateTenant(ctx, engine.TenantSpec{
			Slug: cfg.Slug, Name: cfg.Name, Kind: cfg.Kind, Environment: env,
			AppURL: strings.TrimRight(cfg.AppURL, "/"), Origins: append([]string{origin}, cfg.Origins...),
		})
		if keys != nil {
			pk = keys.PublishableKey
		}
	}
	if err != nil {
		eng.Close()
		return nil, fmt.Errorf("embed: the application's tenant: %w", err)
	}

	client, err := aos.New(aos.Config{
		URL:            "http://aos.embedded",
		PublishableKey: pk,
		// Never sent anywhere: the in-process transport names the tenant
		// itself. The SDK only checks that a key is set.
		SecretKey:  "sk_embedded",
		HTTPClient: &http.Client{Transport: eng.Transport(cfg.Slug)},
	})
	if err != nil {
		eng.Close()
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	go eng.Run(runCtx)
	return &Auth{Client: client, eng: eng, path: cfg.Path, pk: pk, cancel: cancel}, nil
}

// Handler serves the routes the browser SDK and the email links use.
// Mount it at Config.Path: mux.Handle("/aos/", auth.Handler()). In the
// browser, point @aos-auth/js or @aos-auth/react at <AppURL>/aos with
// PublishableKey().
func (a *Auth) Handler() http.Handler {
	inner := a.eng.Handler()
	return http.StripPrefix(a.path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One application: a browser that leaves the key out means this one.
		if r.Header.Get("X-AOS-Publishable-Key") == "" && r.Method != http.MethodOptions {
			r.Header.Set("X-AOS-Publishable-Key", a.pk)
		}
		inner.ServeHTTP(w, r)
	}))
}

// PublishableKey is the key the browser SDK sends. It is not a secret.
func (a *Auth) PublishableKey() string { return a.pk }

// Engine is the engine underneath, for what the SDK methods do not cover.
func (a *Auth) Engine() *engine.Engine { return a.eng }

// Close stops background delivery and releases the database.
func (a *Auth) Close() {
	a.cancel()
	a.eng.Close()
}
