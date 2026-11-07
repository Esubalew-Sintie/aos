// Package initiator wires the engine together: configuration, database,
// storage, modules, handlers and routes, in that order.
package initiator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/handler/middleware"

	"github.com/flash-softeware/aos/platform/config"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/mailer"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

// App is the engine, wired and ready to serve.
type App struct {
	Config  config.Config
	DB      *postgres.DB
	Storage Storage
	Module  Module
	Handler Handler
	Router  http.Handler
	Log     logger.Logger
	// Options are the replaceable parts the modules were built with.
	Options ModuleOptions
	// Extras holds what extensions made, by name.
	Extras map[string]any
}

// NewApp builds every layer on top of an open database. The server and
// the tests both start here, so the tests exercise the same wiring that
// runs in production.
func NewApp(cfg config.Config, db *postgres.DB, master *secret.MasterKey, opts ModuleOptions, log logger.Logger) (*App, error) {
	if opts.PublicURL == "" {
		opts.PublicURL = cfg.PublicURL
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	storage := InitStorage(log)
	module, err := InitModule(db, storage, master, opts, log)
	if err != nil {
		return nil, err
	}
	handler := InitHandler(module, log)
	app := &App{Config: cfg, DB: db, Storage: storage, Module: module, Handler: handler, Log: log, Options: opts, Extras: map[string]any{}}

	var extra []func(chi.Router, *middleware.TenantMiddleware)
	for _, e := range extensions {
		if e.Build == nil {
			continue
		}
		add, err := e.Build(app)
		if err != nil {
			return nil, fmt.Errorf("extension %s: %w", e.Name, err)
		}
		if add != nil {
			extra = append(extra, add)
		}
	}

	r := chi.NewRouter()
	inbox, _ := opts.Sender.(*mailer.Inbox)
	InitRoutes(r, handler, module, cfg, db, inbox, log, extra...)
	app.Router = r
	return app, nil
}

// Initiator runs the HTTP API until the process is asked to stop.
func Initiator(ctx context.Context) error {
	cfg, err := InitConfig(true)
	if err != nil {
		return err
	}
	log := InitLogger(cfg)

	master, err := InitMasterKey(cfg)
	if err != nil {
		return err
	}
	sender, err := InitMailer(cfg, log)
	if err != nil {
		return err
	}
	db, err := InitDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Infof("database ready")

	app, err := NewApp(cfg, db, master, ModuleOptions{
		Sender: sender, Breach: InitBreachChecker(cfg, log), AllowPrivateWebhooks: cfg.Development(),
	}, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Messages are delivered in the background.
	go app.Module.Notification.Run(ctx)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServe() }()
	log.Infof("listening on %s (%s)", cfg.ListenAddr, cfg.Env)

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}

	// Let requests that are in flight finish.
	log.Infof("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
