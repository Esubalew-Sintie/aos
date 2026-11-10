package initiator

import (
	"github.com/flash-software-technology/aos/internal/storage"
	auditrepo "github.com/flash-software-technology/aos/internal/storage/audit"
	authrepo "github.com/flash-software-technology/aos/internal/storage/auth"
	enterpriserepo "github.com/flash-software-technology/aos/internal/storage/enterprise"
	iamrepo "github.com/flash-software-technology/aos/internal/storage/iam"
	machinerepo "github.com/flash-software-technology/aos/internal/storage/machine"
	notificationrepo "github.com/flash-software-technology/aos/internal/storage/notification"
	oauthrepo "github.com/flash-software-technology/aos/internal/storage/oauth"
	organizationrepo "github.com/flash-software-technology/aos/internal/storage/organization"
	reviewrepo "github.com/flash-software-technology/aos/internal/storage/review"
	tenantrepo "github.com/flash-software-technology/aos/internal/storage/tenant"
	transferrepo "github.com/flash-software-technology/aos/internal/storage/transfer"
	"github.com/flash-software-technology/aos/platform/logger"
)

type Storage struct {
	TenantRepo       storage.TenantRepository
	AuthRepo         storage.AuthRepository
	IAMRepo          storage.IAMRepository
	AuditRepo        storage.AuditRepository
	NotificationRepo storage.NotificationRepository
	OrganizationRepo storage.OrganizationRepository
	MachineRepo      storage.MachineRepository
	OAuthRepo        storage.OAuthRepository
	EnterpriseRepo   storage.EnterpriseRepository
	TransferRepo     storage.TransferRepository
	ReviewRepo       storage.ReviewRepository
}

func InitStorage(log logger.Logger) Storage {
	return Storage{
		TenantRepo:       tenantrepo.NewTenantRepository(log),
		AuthRepo:         authrepo.NewAuthRepository(log),
		IAMRepo:          iamrepo.NewIAMRepository(log),
		AuditRepo:        auditrepo.NewAuditRepository(log),
		NotificationRepo: notificationrepo.NewNotificationRepository(log),
		OrganizationRepo: organizationrepo.NewOrganizationRepository(log),
		MachineRepo:      machinerepo.NewMachineRepository(log),
		OAuthRepo:        oauthrepo.NewOAuthRepository(log),
		EnterpriseRepo:   enterpriserepo.NewEnterpriseRepository(log),
		TransferRepo:     transferrepo.NewTransferRepository(log),
		ReviewRepo:       reviewrepo.NewReviewRepository(log),
	}
}
