package initiator

import (
	"github.com/flash-software-technology/aos/internal/handler/rest"
	rest_auth "github.com/flash-software-technology/aos/internal/handler/rest/http/auth"
	rest_enterprise "github.com/flash-software-technology/aos/internal/handler/rest/http/enterprise"
	rest_iam "github.com/flash-software-technology/aos/internal/handler/rest/http/iam"
	rest_machine "github.com/flash-software-technology/aos/internal/handler/rest/http/machine"
	rest_oauth "github.com/flash-software-technology/aos/internal/handler/rest/http/oauth"
	rest_organization "github.com/flash-software-technology/aos/internal/handler/rest/http/organization"
	rest_scim "github.com/flash-software-technology/aos/internal/handler/rest/http/scim"
	rest_social "github.com/flash-software-technology/aos/internal/handler/rest/http/social"
	rest_transfer "github.com/flash-software-technology/aos/internal/handler/rest/http/transfer"
	rest_user "github.com/flash-software-technology/aos/internal/handler/rest/http/user"
	rest_webhook "github.com/flash-software-technology/aos/internal/handler/rest/http/webhook"
	"github.com/flash-software-technology/aos/platform/logger"
)

type Handler struct {
	AuthHandler         rest.AuthHandler
	IAMHandler          rest.IAMHandler
	UserHandler         rest.UserHandler
	WebhookHandler      rest.WebhookHandler
	OrganizationHandler rest.OrganizationHandler
	SocialHandler       rest.SocialProviderHandler
	MachineHandler      rest.MachineHandler
	OAuthHandler        rest.OAuthHandler
	EnterpriseHandler   rest.EnterpriseHandler
	SCIMHandler         rest.SCIMHandler
	TransferHandler     rest.TransferHandler
}

func InitHandler(module Module, log logger.Logger) Handler {
	return Handler{
		AuthHandler:         rest_auth.NewAuthHandler(module.Auth, module.Tenant, log.Named("handler.auth")),
		IAMHandler:          rest_iam.NewIamHandler(module.IAM, log.Named("handler.iam")),
		UserHandler:         rest_user.NewUserHandler(module.Auth, module.IAM, log.Named("handler.user")),
		WebhookHandler:      rest_webhook.NewWebhookHandler(module.Notification, log.Named("handler.webhook")),
		OrganizationHandler: rest_organization.NewOrganizationHandler(module.Organization, module.Auth, log.Named("handler.organization")),
		SocialHandler:       rest_social.NewSocialProviderHandler(module.Auth, log.Named("handler.social")),
		MachineHandler:      rest_machine.NewMachineHandler(module.Machine, module.Auth, log.Named("handler.machine")),
		OAuthHandler:        rest_oauth.NewOAuthHandler(module.OAuth, module.Tenant, log.Named("handler.oauth")),
		EnterpriseHandler:   rest_enterprise.NewEnterpriseHandler(module.Enterprise, module.Auth, log.Named("handler.enterprise")),
		SCIMHandler:         rest_scim.NewSCIMHandler(module.Enterprise, log.Named("handler.scim")),
		TransferHandler:     rest_transfer.NewTransferHandler(module.Transfer, module.Review, module.Auth, log.Named("handler.transfer")),
	}
}
