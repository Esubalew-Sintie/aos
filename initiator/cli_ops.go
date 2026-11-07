package initiator

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/platform/logger"
)

// openApp builds the engine for a one-off command.
func openApp(ctx context.Context) (*App, func(), error) {
	cfg, err := InitConfig(true)
	if err != nil {
		return nil, nil, err
	}
	master, err := InitMasterKey(cfg)
	if err != nil {
		return nil, nil, err
	}
	log := logger.NewDiscard()
	db, err := InitDatabase(ctx, cfg, log)
	if err != nil {
		return nil, nil, err
	}
	app, err := NewApp(cfg, db, master, ModuleOptions{AllowPrivateWebhooks: cfg.Development()}, log)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return app, db.Close, nil
}

// runDoctor checks what a running engine needs and says what is wrong.
func runDoctor(ctx context.Context, out io.Writer) error {
	problems := 0
	check := func(ok bool, good, bad string) {
		if ok {
			fmt.Fprintf(out, "  ok    %s\n", good)
		} else {
			problems++
			fmt.Fprintf(out, "  FAIL  %s\n", bad)
		}
	}
	cfg, err := InitConfig(true)
	if err != nil {
		fmt.Fprintf(out, "  FAIL  configuration: %s\n", describe(err))
		return fmt.Errorf("1 problem found")
	}
	check(true, "configuration read ("+cfg.Env+")", "")
	master, err := InitMasterKey(cfg)
	check(err == nil, "master key is well formed", "master key: "+fmt.Sprint(err))
	if !cfg.Development() {
		check(cfg.SMTPAddr != "", "email is sent through "+cfg.SMTPAddr, "AOS_SMTP_ADDR is not set: production cannot send email")
		check(strings.HasPrefix(cfg.PublicURL, "https://"), "public address "+cfg.PublicURL, "AOS_PUBLIC_URL must be an https address in production")
	}
	db, err := InitDatabase(ctx, cfg, logger.NewDiscard())
	if err != nil {
		check(false, "", "database: "+err.Error())
		return fmt.Errorf("%d problem(s) found", problems)
	}
	defer db.Close()
	check(true, "database reachable", "")
	pending, err := db.Pending(ctx)
	check(err == nil && len(pending) == 0, "schema up to date", fmt.Sprintf("schema not up to date (run aos migrate): %v %v", pending, err))
	for _, role := range []string{"aos_app", "aos_platform"} {
		ok, err := db.HasRole(ctx, role)
		check(err == nil && ok, "can act as "+role, "the database user cannot act as "+role)
	}
	if master != nil && len(pending) == 0 {
		// Every tenant's data key must open with this master key.
		app, err := NewApp(cfg, db, master, ModuleOptions{}, logger.NewDiscard())
		if err == nil {
			var ids []string
			_ = db.Platform(ctx, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `SELECT id::text FROM aos.tenants WHERE status <> 'deleted'`)
				if err != nil {
					return err
				}
				ids, err = pgx.CollectRows(rows, pgx.RowTo[string])
				return err
			})
			bad := 0
			for _, id := range ids {
				if err := db.Tenant(ctx, id, func(tx pgx.Tx) error {
					_, _, err := app.Module.Tenant.(interface {
						DataKey(context.Context, pgx.Tx, string) (string, []byte, error)
					}).DataKey(ctx, tx, id)
					return err
				}); err != nil {
					bad++
				}
			}
			check(bad == 0, fmt.Sprintf("master key opens the keys of all %d tenants", len(ids)), fmt.Sprintf("master key cannot open the keys of %d tenant(s): wrong AOS_MASTER_KEY?", bad))
		}
	}
	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Fprintln(out, "Everything looks right.")
	return nil
}

// permissionsFile is what `aos permissions sync` reads: the permissions
// and roles an application declares in its code (PERM-1).
type permissionsFile struct {
	Permissions []request.PutPermissionRequest `json:"permissions"`
	Roles       []request.PutRoleRequest       `json:"roles"`
}

func runPermissions(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "sync" {
		return fmt.Errorf("usage: aos permissions sync --tenant <slug> --file permissions.json")
	}
	var slug, file string
	fs := flag.NewFlagSet("permissions sync", flag.ContinueOnError)
	fs.StringVar(&slug, "tenant", "", "")
	fs.StringVar(&file, "file", "permissions.json", "")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if slug == "" {
		return fmt.Errorf("--tenant is required")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var pf permissionsFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	app, closeDB, err := openApp(ctx)
	if err != nil {
		return err
	}
	defer closeDB()
	t, err := app.Module.Tenant.FindBySlug(ctx, slug)
	if err != nil {
		return err
	}
	meta := model.RequestMeta{RequestID: "cli"}
	for _, p := range pf.Permissions {
		if _, err := app.Module.IAM.PutPermission(ctx, t, p, constant.SourceCode, meta); err != nil {
			return fmt.Errorf("permission %s: %s", p.Name, describe(err))
		}
	}
	for _, r := range pf.Roles {
		if _, err := app.Module.IAM.PutRole(ctx, t, r, constant.SourceCode, meta); err != nil {
			return fmt.Errorf("role %s: %s", r.Name, describe(err))
		}
	}
	fmt.Fprintf(out, "Synced %d permissions and %d roles into %s.\n", len(pf.Permissions), len(pf.Roles), slug)
	return nil
}

// runExport writes an encrypted archive of a tenant (HOST-6). The
// passphrase comes from AOS_ARCHIVE_PASSPHRASE, never from a flag.
func runExport(ctx context.Context, args []string, out io.Writer) error {
	var slug, file string
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.StringVar(&slug, "tenant", "", "")
	fs.StringVar(&file, "out", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if slug == "" || file == "" {
		return fmt.Errorf("usage: aos export --tenant <slug> --out <file>  (passphrase in AOS_ARCHIVE_PASSPHRASE)")
	}
	app, closeDB, err := openApp(ctx)
	if err != nil {
		return err
	}
	defer closeDB()
	t, err := app.Module.Tenant.FindBySlug(ctx, slug)
	if err != nil {
		return err
	}
	res, err := app.Module.Transfer.Export(ctx, t, request.ExportRequest{Passphrase: os.Getenv("AOS_ARCHIVE_PASSPHRASE")}, model.RequestMeta{RequestID: "cli"})
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(res.Archive), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "Archive written to %s: %v\n", file, res.Counts)
	return nil
}

func runImport(ctx context.Context, args []string, out io.Writer) error {
	var slug, file string
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.StringVar(&slug, "tenant", "", "")
	fs.StringVar(&file, "in", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if slug == "" || file == "" {
		return fmt.Errorf("usage: aos import --tenant <slug> --in <file>  (passphrase in AOS_ARCHIVE_PASSPHRASE)")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	app, closeDB, err := openApp(ctx)
	if err != nil {
		return err
	}
	defer closeDB()
	t, err := app.Module.Tenant.FindBySlug(ctx, slug)
	if err != nil {
		return err
	}
	res, err := app.Module.Transfer.Import(ctx, t, request.ImportArchiveRequest{Archive: strings.TrimSpace(string(raw)), Passphrase: os.Getenv("AOS_ARCHIVE_PASSPHRASE")}, model.RequestMeta{RequestID: "cli"})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Imported into %s: %v\n", slug, res.Counts)
	return nil
}
