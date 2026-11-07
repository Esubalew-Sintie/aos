package initiator

import (
	"context"
	"net"
	"time"

	"github.com/flash-softeware/aos/internal/module"
	authmodule "github.com/flash-softeware/aos/internal/module/auth"
	enterprisemodule "github.com/flash-softeware/aos/internal/module/enterprise"
	iammodule "github.com/flash-softeware/aos/internal/module/iam"
	machinemodule "github.com/flash-softeware/aos/internal/module/machine"
	notificationmodule "github.com/flash-softeware/aos/internal/module/notification"
	oauthmodule "github.com/flash-softeware/aos/internal/module/oauth"
	organizationmodule "github.com/flash-softeware/aos/internal/module/organization"
	reviewmodule "github.com/flash-softeware/aos/internal/module/review"
	tenantmodule "github.com/flash-softeware/aos/internal/module/tenant"
	transfermodule "github.com/flash-softeware/aos/internal/module/transfer"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/mailer"
	"github.com/flash-softeware/aos/platform/oidc"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

type Module struct {
	Tenant       module.Tenant
	Notification module.Notification
	Auth         module.Auth
	IAM          module.IAM
	Organization module.Organization
	Machine      module.Machine
	OAuth        module.OAuthProvider
	Enterprise   module.Enterprise
	Transfer     module.Transfer
	Review       module.Review
}

// ModuleOptions are the parts a test replaces.
type ModuleOptions struct {
	// Sender delivers email.
	Sender mailer.Sender
	// PasswordParams is the cost of password hashing. Zero means the default.
	PasswordParams secret.PasswordParams
	// Now is the clock. Nil means the real one.
	Now func() time.Time
	// Breach refuses leaked passwords. Nil means the built-in list only.
	Breach secret.BreachChecker
	// AllowPrivateWebhooks lets webhooks and social sign-in providers be
	// on this machine or a private network. For development only.
	AllowPrivateWebhooks bool
	// OIDC talks to social sign-in providers. Nil means a real client.
	OIDC *oidc.Client
	// PublicURL is the address the engine is reached at, the issuer of
	// the tokens it signs as a provider. Empty means the configured one.
	PublicURL string
	// DNS answers TXT lookups for domain verification. Nil means the
	// system resolver.
	DNS func(ctx context.Context, name string) ([]string, error)
}

func InitModule(db *postgres.DB, storage Storage, master *secret.MasterKey, opts ModuleOptions, log logger.Logger) (Module, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PasswordParams == (secret.PasswordParams{}) {
		opts.PasswordParams = secret.DefaultPasswordParams
	}
	if opts.Breach == nil {
		opts.Breach = secret.NewLocalBreachList()
	}

	// The tenant module also keeps the keys the other modules need.
	tenant := tenantmodule.NewTenantModule(db, storage.TenantRepo, storage.AuditRepo, master, log.Named("tenant"))
	notification := notificationmodule.NewNotificationModule(db, storage.NotificationRepo, storage.AuditRepo, tenant,
		opts.Sender, opts.AllowPrivateWebhooks, opts.Now, log.Named("notification"))
	// An extension (the hosted service) counts what tenants do and sets
	// their limits. Without one there are none.
	meter := extensionMeter(log)
	if opts.OIDC == nil {
		opts.OIDC = oidc.New(opts.AllowPrivateWebhooks)
	}
	if opts.DNS == nil {
		opts.DNS = net.DefaultResolver.LookupTXT
	}
	auth, err := authmodule.NewAuthModule(db, storage.AuthRepo, storage.IAMRepo, storage.TenantRepo, storage.EnterpriseRepo, storage.OrganizationRepo,
		storage.AuditRepo, notification, tenant, opts.Breach, opts.PasswordParams, meter, opts.OIDC, opts.Now, log.Named("auth"))
	if err != nil {
		return Module{}, err
	}
	iam := iammodule.NewIAMModule(db, storage.IAMRepo, storage.MachineRepo, storage.AuthRepo, storage.AuditRepo, notification, meter, opts.Now, log.Named("iam"))
	organization := organizationmodule.NewOrganizationModule(db, storage.OrganizationRepo, storage.IAMRepo, storage.AuthRepo,
		storage.AuditRepo, notification, iam, auth, opts.Breach, opts.PasswordParams, meter, opts.Now, log.Named("organization"))
	machine := machinemodule.NewMachineModule(db, storage.MachineRepo, storage.IAMRepo, storage.AuthRepo, storage.AuditRepo,
		notification, iam, auth, opts.Now, log.Named("machine"))
	oauthProvider := oauthmodule.NewOAuthModule(db, storage.OAuthRepo, storage.AuthRepo, storage.MachineRepo, storage.IAMRepo, storage.AuditRepo,
		notification, auth, tenant, tenant, opts.OIDC, opts.PublicURL, opts.Now, log.Named("oauth"))
	enterprise := enterprisemodule.NewEnterpriseModule(db, storage.EnterpriseRepo, storage.OrganizationRepo, storage.AuthRepo, storage.IAMRepo,
		storage.AuditRepo, notification, iam, auth, tenant, opts.OIDC, enterprisemodule.DNSLookup(opts.DNS), opts.PublicURL, opts.Now, log.Named("enterprise"))
	transfer := transfermodule.NewTransferModule(db, storage.TransferRepo, storage.AuthRepo, storage.IAMRepo, storage.OrganizationRepo,
		storage.TenantRepo, storage.AuditRepo, tenant, opts.Now, log.Named("transfer"))
	review := reviewmodule.NewReviewModule(db, storage.ReviewRepo, storage.OrganizationRepo, storage.IAMRepo, storage.AuditRepo,
		notification, iam, opts.Now, log.Named("review"))

	return Module{
		Tenant:       tenant,
		Notification: notification,
		Auth:         auth,
		IAM:          iam,
		Organization: organization,
		Machine:      machine,
		OAuth:        oauthProvider,
		Enterprise:   enterprise,
		Transfer:     transfer,
		Review:       review,
	}, nil
}
