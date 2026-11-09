package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/flash-softeware/aos/embed"
	"github.com/flash-softeware/aos/initiator"
)

const appUsage = `aos app runs the engine for one application, started by its backend
(the Node and Python SDKs do this). It makes or finds the application's
tenant, listens on a local address, and prints one line of JSON when ready:
  {"url": "...", "path": "/aos", "publishable_key": "pk_...", "version": "..."}

Requests under --path are the browser's (the application proxies them).
Other requests carrying "Authorization: Bearer $AOS_LOCAL_TOKEN" are the
application's backend calls; without it they need the usual keys.

Flags:
  --database-url URL   Postgres (default $AOS_DATABASE_URL)
  --app-url URL        the application's address; email links point there (required)
  --origin URL         another browser origin allowed; repeat
  --path PATH          where the browser routes are mounted (default /aos)
  --listen ADDR        default 127.0.0.1:0 (any free port)
  --slug, --name, --kind   the application's tenant (default app, App, multi)
  --development        keep email in a development inbox; hand sessions to the browser
  --exit-with-stdin    stop when standard input closes (the parent is gone)

Environment: AOS_MASTER_KEY (required), AOS_LOCAL_TOKEN (required: sk_local_
and at least 32 more characters), AOS_SMTP_* and AOS_MAIL_FROM for email.
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runApp(args []string) error {
	var cfg embed.Config
	var origins stringList
	var listen string
	var exitWithStdin bool
	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, appUsage) }
	fs.StringVar(&cfg.DatabaseURL, "database-url", os.Getenv("AOS_DATABASE_URL"), "")
	fs.StringVar(&cfg.AppURL, "app-url", "", "")
	fs.Var(&origins, "origin", "")
	fs.StringVar(&cfg.Path, "path", "/aos", "")
	fs.StringVar(&listen, "listen", "127.0.0.1:0", "")
	fs.StringVar(&cfg.Slug, "slug", "app", "")
	fs.StringVar(&cfg.Name, "name", "App", "")
	fs.StringVar(&cfg.Kind, "kind", "multi", "")
	fs.BoolVar(&cfg.Development, "development", false, "")
	fs.BoolVar(&exitWithStdin, "exit-with-stdin", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.Origins = origins
	cfg.MasterKey = os.Getenv("AOS_MASTER_KEY")
	cfg.SMTPAddr, cfg.SMTPUsername, cfg.SMTPPassword, cfg.MailFrom = os.Getenv("AOS_SMTP_ADDR"), os.Getenv("AOS_SMTP_USERNAME"), os.Getenv("AOS_SMTP_PASSWORD"), os.Getenv("AOS_MAIL_FROM")
	// The application's own server is the proxy in front of this one.
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	token := os.Getenv("AOS_LOCAL_TOKEN")
	if !strings.HasPrefix(token, "sk_local_") || len(token) < len("sk_local_")+32 {
		return errors.New("AOS_LOCAL_TOKEN must be sk_local_ followed by at least 32 random characters")
	}
	if cfg.MasterKey == "" {
		return errors.New("AOS_MASTER_KEY is not set (make one with: aos keygen)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	auth, err := embed.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer auth.Close()

	browser := auth.Handler()
	backend := auth.Engine().TenantHandler(auth.Slug())
	public := auth.Engine().Handler()
	want := []byte("Bearer " + token)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == auth.Path() || strings.HasPrefix(r.URL.Path, auth.Path()+"/"):
			browser.ServeHTTP(w, r)
		case subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) == 1:
			backend.ServeHTTP(w, r)
		default:
			public.ServeHTTP(w, r)
		}
	})

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(ln) }()

	ready, _ := json.Marshal(map[string]string{
		"url": "http://" + ln.Addr().String(), "path": auth.Path(),
		"publishable_key": auth.PublishableKey(), "version": initiator.BuildVersion,
	})
	fmt.Println(string(ready))

	if exitWithStdin {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			stop()
		}()
	}
	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shut)
}
