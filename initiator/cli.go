package initiator

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

const usageText = `aos runs the AOS identity engine.

Usage:
  aos serve                 run the HTTP API (the default)
  aos migrate               create or upgrade the database schema
  aos tenant create ...     create a tenant and print its keys
  aos owner create ...      create the first admin of a tenant
  aos keygen                print a new master key for AOS_MASTER_KEY
  aos doctor                check configuration, database, schema and keys
  aos openapi               print the OpenAPI document of the API
  aos permissions sync ...  apply a permissions.json file to a tenant
  aos export ...            write an encrypted archive of a tenant
  aos import ...            fill an empty tenant from an archive

Tenant options:
  --slug          short name: lower-case letters, digits, hyphens (required)
  --name          display name (required)
  --kind          single (default) or multi (has organizations)
  --env           development (default), staging or production
  --app-url       the application's own address; email links point there
  --origin        a web address allowed to call the API from a browser;
                  repeat for several

Owner options:
  --tenant        the tenant's slug (required)
  --email         the person's email address (required)
  --name          their name
  The person receives a setup link by email and chooses their own
  password. In development the link is written to this terminal.

Permissions sync: --tenant <slug> --file permissions.json
  {"permissions": [{"name": "payment.refund", "step_up_seconds": 300}],
   "roles": [{"name": "Finance", "permissions": ["payment.*"]}]}
Export and import: --tenant <slug> --out <file> | --in <file>
  The passphrase is read from AOS_ARCHIVE_PASSPHRASE.

Environment:
  AOS_DATABASE_URL      Postgres connection string (required)
  AOS_MASTER_KEY        wraps every tenant's keys (required except for migrate)
  AOS_ENV               production (default) or development
  AOS_LISTEN_ADDR       default :8080
  AOS_PUBLIC_URL        the address the engine is reached at (OAuth issuer, SCIM)
  AOS_TRUSTED_PROXIES   networks whose X-Forwarded-For is believed, e.g. 10.0.0.0/8
  AOS_SMTP_ADDR         host:port of the SMTP server
  AOS_SMTP_USERNAME, AOS_SMTP_PASSWORD
  AOS_MAIL_FROM         the address emails are sent from
`

// usage is the help text, with the commands extensions add.
func usage() string {
	text := usageText
	for _, e := range extensions {
		for _, c := range e.Commands {
			text += "\n" + c.Usage
		}
	}
	return text
}

// Version is the API version written into the OpenAPI document.
const Version = "1.0.0"

// Run executes one command and returns the process exit code.
func Run(ctx context.Context, args []string) int {
	command := "serve"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}

	var err error
	switch command {
	case "serve":
		err = Initiator(ctx)
	case "migrate":
		err = runMigrate(ctx)
	case "tenant":
		err = runTenant(ctx, args, os.Stdout)
	case "owner":
		err = runOwner(ctx, args, os.Stdout)
	case "openapi":
		var spec []byte
		if spec, err = OpenAPI(Version); err == nil {
			_, err = os.Stdout.Write(append(spec, '\n'))
		}
	case "doctor":
		err = runDoctor(ctx, os.Stdout)
	case "permissions":
		err = runPermissions(ctx, args, os.Stdout)
	case "export":
		err = runExport(ctx, args, os.Stdout)
	case "import":
		err = runImport(ctx, args, os.Stdout)
	case "keygen":
		fmt.Println(secret.NewMasterKeyString())
	case "help", "-h", "--help":
		fmt.Print(usage())
	default:
		ran := false
		for _, e := range extensions {
			for _, c := range e.Commands {
				if c.Name == command {
					err, ran = c.Run(ctx, args, os.Stdout), true
				}
			}
		}
		if !ran {
			fmt.Fprintf(os.Stderr, "aos: unknown command %q\n\n%s", command, usage())
			return 2
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "aos:", describe(err))
		return 1
	}
	return 0
}

func runMigrate(ctx context.Context) error {
	cfg, err := InitConfig(false)
	if err != nil {
		return err
	}
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	applied, err := db.Migrate(ctx)
	for _, name := range applied {
		fmt.Println("applied", name)
	}
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("the schema is up to date")
	}
	return nil
}

func runTenant(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("usage: aos tenant create --slug <slug> --name <name>")
	}
	var req request.CreateTenantRequest
	var origins stringList
	fs := flag.NewFlagSet("tenant create", flag.ContinueOnError)
	fs.StringVar(&req.Slug, "slug", "", "")
	fs.StringVar(&req.Name, "name", "", "")
	fs.StringVar(&req.Kind, "kind", "", "")
	fs.StringVar(&req.Environment, "env", "", "")
	fs.StringVar(&req.AppURL, "app-url", "", "")
	fs.Var(&origins, "origin", "")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	req.AllowedOrigins = origins

	cfg, err := InitConfig(true)
	if err != nil {
		return err
	}
	master, err := InitMasterKey(cfg)
	if err != nil {
		return err
	}
	log := logger.NewDiscard()
	db, err := InitDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer db.Close()

	// Creating a tenant sends no email, so no sender is needed.
	app, err := NewApp(cfg, db, master, ModuleOptions{}, log)
	if err != nil {
		return err
	}
	created, err := app.Module.Tenant.Create(ctx, req)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Tenant created.\n\n")
	fmt.Fprintf(out, "  tenant id        %s\n", created.TenantID)
	fmt.Fprintf(out, "  slug             %s\n", created.Slug)
	fmt.Fprintf(out, "  publishable key  %s\n", created.PublishableKey)
	fmt.Fprintf(out, "  secret key       %s\n\n", created.SecretKey)
	fmt.Fprintf(out, "The secret key is shown only this once. Only its hash is stored.\n")
	fmt.Fprintf(out, "Keep it in the application's backend. Never put it in browser code.\n")
	return nil
}

// describe makes an error readable on the command line, including which
// fields failed validation.
func describe(err error) string {
	appErr, ok := errors.AsAppError(err)
	if !ok {
		return err.Error()
	}
	if len(appErr.Details) == 0 {
		return appErr.Message
	}
	parts := make([]string, 0, len(appErr.Details))
	for field, problem := range appErr.Details {
		parts = append(parts, field+" "+problem)
	}
	return appErr.Message + ": " + strings.Join(parts, "; ")
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// runOwner creates a user who holds Owner on the tenant's root, and
// sends them a setup link.
func runOwner(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("usage: aos owner create --tenant <slug> --email <address>")
	}
	var slug string
	var req request.CreateUserRequest
	fs := flag.NewFlagSet("owner create", flag.ContinueOnError)
	fs.StringVar(&slug, "tenant", "", "")
	fs.StringVar(&req.Email, "email", "", "")
	fs.StringVar(&req.Name, "name", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if slug == "" {
		return fmt.Errorf("--tenant is required")
	}
	return createOwner(ctx, slug, req, out)
}

// createOwner creates a user who holds Owner on a tenant's root and
// sends them a setup link.
func createOwner(ctx context.Context, slug string, req request.CreateUserRequest, out io.Writer) error {

	cfg, err := InitConfig(true)
	if err != nil {
		return err
	}
	master, err := InitMasterKey(cfg)
	if err != nil {
		return err
	}
	log := logger.NewLogger(cfg.Development())
	sender, err := InitMailer(cfg, log)
	if err != nil {
		return err
	}
	db, err := InitDatabase(ctx, cfg, logger.NewDiscard())
	if err != nil {
		return err
	}
	defer db.Close()
	app, err := NewApp(cfg, db, master, ModuleOptions{Sender: sender, AllowPrivateWebhooks: cfg.Development()}, logger.NewDiscard())
	if err != nil {
		return err
	}

	tenant, err := app.Module.Tenant.FindBySlug(ctx, slug)
	if err != nil {
		return err
	}
	meta := model.RequestMeta{RequestID: "cli"}
	user, err := app.Module.Auth.CreateUser(ctx, tenant, req, meta)
	if err != nil {
		return err
	}
	if _, err := app.Module.IAM.CreateGrant(ctx, tenant, request.CreateGrantRequest{
		PrincipalID: user.ID, Role: "Owner", Effect: "allow", Reason: "first owner, created from the command line",
		Resource: request.ResourceRef{Type: "tenant", ID: "root"},
	}, meta); err != nil {
		return err
	}
	fmt.Fprintf(out, "Owner created: %s (%s)\n", user.Email, user.ID)

	// The setup email waits in the outbox. The server sends it when it
	// runs. In development, send it now so the link appears here.
	if cfg.Development() {
		if _, err := app.Module.Notification.DeliverDue(ctx); err != nil {
			return err
		}
		fmt.Fprintf(out, "The setup link is in the email written above. It works once and expires in 1 hour.\n")
	} else {
		fmt.Fprintf(out, "A setup link will be emailed to them when the server next sends mail.\n")
	}
	return nil
}
