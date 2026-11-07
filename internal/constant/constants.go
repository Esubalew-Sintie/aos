// Package constant holds values shared by every layer.
package constant

import "time"

// HTTP names.
const (
	// HeaderPublishableKey carries the key that names the tenant on the
	// frontend routes. It is safe in browser code.
	HeaderPublishableKey = "X-AOS-Publishable-Key"
	// HeaderSession carries the session token for development tenants,
	// where a first-party cookie is not possible (user-flow SYS-2).
	HeaderSession = "X-AOS-Session"
	// HeaderRequestID is echoed on every response.
	HeaderRequestID = "X-Request-Id"
	// SessionCookie is host-locked: the "__Host-" prefix makes the browser
	// refuse it unless it is Secure, has Path=/ and names no Domain.
	SessionCookie = "__Host-aos_session"
	// MaxBodyBytes caps every request body.
	MaxBodyBytes = 64 << 10
)

// Key kinds and prefixes.
const (
	KeyKindPublishable = "publishable"
	KeyKindSecret      = "secret"
)

// Tenant states and kinds.
const (
	TenantActive     = "active"
	TenantRestricted = "restricted"
	TenantSuspended  = "suspended"
	TenantDeleted    = "deleted"

	EnvDevelopment = "development"
	EnvStaging     = "staging"
	EnvProduction  = "production"

	KindSingle = "single"
	KindMulti  = "multi"

	SignupOpen       = "open"
	SignupInviteOnly = "invite_only"
	SignupDomains    = "domains"
)

// Principal states.
const (
	PrincipalActive    = "active"
	PrincipalSuspended = "suspended"
)

// Token purposes. They match the check constraint on aos.tokens.
const (
	TokenEmailVerification = "email_verification"
	TokenPasswordReset     = "password_reset"
	TokenAccountSetup      = "owner_setup"
	TokenEmailChange       = "email_change"
)

// Hooks the application can answer before an action happens.
const (
	HookUserBeforeCreate = "user.before_create"
	HookUserBeforeDelete = "user.before_delete"

	WebhookKindEvents      = "events"
	WebhookKindBeforeHook  = "before_hook"
	WebhookKindAuditExport = "audit_export"
)

// Lifetimes. These are the defaults proposed in user-flow/README.md.
const (
	EmailVerificationTTL = 24 * time.Hour
	PasswordResetTTL     = 30 * time.Minute
	AccountSetupTTL      = time.Hour
	EmailChangeTTL       = 24 * time.Hour
	// DeletionGrace is how long a deleted account can still be restored.
	DeletionGrace   = 30 * 24 * time.Hour
	SessionTokenTTL = 60 * time.Second
	// SessionTouchInterval is how often a busy session's "last seen" time
	// is written, so a session does not cause a write on every request.
	SessionTouchInterval = time.Minute
)

// Password rules: a length range and no forced symbols (PRD, Passwords).
const (
	PasswordMinLength = 8
	PasswordMaxLength = 256
)

// Rate limits and lockout (user-flow SIGN-10).
const (
	// Failed sign-ins for one account before delays start, and before
	// the account is locked.
	LockoutDelayAfter = 5
	LockoutLockAfter  = 10
	LockoutWindow     = 15 * time.Minute
	LockoutDuration   = 15 * time.Minute

	// Requests from one address, per minute, on the routes that take an
	// email address or a password.
	AddressLimitPerMinute = 30
	AddressLimitWindow    = time.Minute
	// Emails that may be sent to one address, per hour, by sign-up and
	// forgotten-password requests.
	EmailLimitPerHour = 5
	EmailLimitWindow  = time.Hour
)

// Rate limit buckets.
const (
	BucketSignInAccount = "signin_account"
	BucketAddress       = "address"
	BucketEmail         = "email"
	BucketSecondFactor  = "second_factor"
	BucketCode          = "code"
)

// ---------------------------------------------------------------------
// Strong sign-in (user-flow SIGN-2, SIGN-4, SIGN-9, SIGN-11, REG-8)
// ---------------------------------------------------------------------

const (
	// Sign-in methods, as recorded on a session.
	MethodPassword     = "password"
	MethodTOTP         = "totp"
	MethodRecoveryCode = "recovery_code"
	MethodPasskey      = "passkey"
	MethodOneTimeCode  = "one_time_code"
	MethodMagicLink    = "magic_link"
	MethodEmailLink    = "email_link"
	MethodGuest        = "guest"
	MethodSocial       = "social"

	ChallengePendingSignIn       = "pending_sign_in"
	ChallengePasskeyRegistration = "passkey_registration"
	ChallengePasskeySignIn       = "passkey_sign_in"
	ChallengeOAuthState          = "oauth_state"
	// SocialCeremonyTTL is how long a trip to the provider may take.
	SocialCeremonyTTL = 10 * time.Minute
	// PasskeyCeremonyTTL is how long a browser has to answer a challenge.
	PasskeyCeremonyTTL = 5 * time.Minute
	// PendingSignInTTL is how long a person has to give the second factor.
	PendingSignInTTL = 5 * time.Minute
	// SecondFactorMaxAttempts cancels the pending sign-in.
	SecondFactorMaxAttempts = 5
	// SecondFactorLimitPerWindow bounds step-up and settings attempts.
	SecondFactorLimitPerWindow = 10
	SecondFactorLimitWindow    = 15 * time.Minute

	TOTPDigits = 6
	TOTPPeriod = 30 * time.Second
	// TOTPSkew is how many time steps either side are accepted.
	TOTPSkew          = 1
	RecoveryCodeCount = 10

	MFAOptional = "optional"
	MFARequired = "required"

	// Session kinds.
	SessionBrowser = "browser"
	SessionToken   = "token"

	TokenOneTimeCode = "one_time_code"
	TokenMagicLink   = "magic_link"
	// OneTimeCodeTTL is how long a sign-in code or magic link lasts.
	OneTimeCodeTTL         = 10 * time.Minute
	OneTimeCodeMaxAttempts = 5
	CodeLimitPerHour       = 5
	CodeLimitWindow        = time.Hour

	// AccessTokenTTL is how long an access token of a token session lives
	// (SIGN-8). RefreshTokenTTL bounds a refresh token on top of the
	// session's own timeouts.
	AccessTokenTTL  = 10 * time.Minute
	RefreshTokenTTL = 30 * 24 * time.Hour

	// DeviceCookie remembers a browser, so a new one can be announced.
	DeviceCookie = "__Host-aos_device"
	DeviceTTL    = 365 * 24 * time.Hour

	TemplateSecondFactorEnabled  = "second_factor_enabled"
	TemplateSecondFactorDisabled = "second_factor_disabled"
	TemplateRecoveryCodeUsed     = "recovery_code_used"
	TemplateSignInCode           = "sign_in_code"
	TemplateNewDevice            = "new_device"
	TemplateTokenReused          = "token_reused"
)

// AOS's own permissions. They are registered in every tenant, with the
// source "system". Owner holds "*" and so holds all of them. An
// application grants them to its own admin roles as it sees fit.
const (
	PermOrganizationCreate = "aos.organization.create"
	PermOrganizationManage = "aos.organization.manage"
	PermMemberRead         = "aos.member.read"
	PermMemberInvite       = "aos.member.invite"
	PermMemberRemove       = "aos.member.remove"
	PermGrantManage        = "aos.grant.manage"
	PermRoleManage         = "aos.role.manage"
	PermGroupManage        = "aos.group.manage"
	PermUserManage         = "aos.user.manage"
	PermUserImpersonate    = "aos.user.impersonate"
	PermAuditRead          = "aos.audit.read"
	PermWebhookManage      = "aos.webhook.manage"
	PermSSOManage          = "aos.sso.manage"
)

// SystemPermissions lists them with a description each.
var SystemPermissions = map[string]string{
	PermOrganizationCreate: "Create an organization",
	PermOrganizationManage: "Change or delete an organization",
	PermMemberRead:         "See who belongs to an organization",
	PermMemberInvite:       "Invite people and give them roles",
	PermMemberRemove:       "Remove people",
	PermGrantManage:        "Give and take away roles",
	PermRoleManage:         "Create and change roles",
	PermGroupManage:        "Create and change groups",
	PermUserManage:         "Suspend, reinstate and delete accounts",
	PermUserImpersonate:    "Act as another user, for support",
	PermAuditRead:          "Read the audit log",
	PermWebhookManage:      "Register endpoints the engine calls",
	PermSSOManage:          "Set up enterprise sign-in",
}

// Invitations.
const (
	InvitationTTL      = 7 * 24 * time.Hour
	TemplateInvitation = "invitation"
	GrantSourceInvite  = "invitation"
)

// Organization creation policies, from the tenant's settings.
const (
	OrgCreationSelfService = "self_service"
	OrgCreationAdminOnly   = "admin_only"
	OrgCreationApplication = "application"
)

// Built-in resource types and roles.
const (
	ResourceTypeTenant       = "tenant"
	ResourceTypeOrganization = "organization"
	RootExternalID           = "root"
	RoleOwner                = "Owner"

	SourceSystem = "system"
	SourceCode   = "code"
	SourcePortal = "portal"

	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Message templates.
const (
	TemplateVerifyEmail     = "verify_email"
	TemplateExistingAccount = "existing_account"
	TemplatePasswordReset   = "password_reset"
	TemplatePasswordChanged = "password_changed"
	TemplateAccountLocked   = "account_locked"
	TemplateAccountSetup    = "account_setup"
	TemplateEmailChange     = "email_change"
	TemplateEmailChangeNote = "email_change_notice"

	ChannelEmail = "email"
)

// Delivery of messages.
const (
	MessageMaxAttempts = 8
	MessageBatchSize   = 50
	MessagePollEvery   = 2 * time.Second

	// Webhooks are retried with growing delays for about a day.
	WebhookMaxAttempts = 12
	WebhookBatchSize   = 50
)

// Paging.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// Usage metrics and limits (HOST-7).
const (
	MetricUsers         = "users"         // a limit: how many accounts a tenant may hold
	MetricOrganizations = "organizations" // a limit: how many organizations
	MetricSignUps       = "sign_ups"      // counted per day
	MetricSignIns       = "sign_ins"
	MetricChecks        = "permission_checks"

	// SupportAccessMaxHours is the longest a tenant owner may grant.
	SupportAccessMaxHours = 72
	// SupportRoleName is the role the support person acts with inside the
	// customer's tenant.
	SupportRoleName = RoleOwner

	PrincipalKindGuest = "guest"
	PrincipalKindUser  = "user"
)

// SocialPresets are the issuers of the providers that need no issuer
// address from the developer. Any other OpenID Connect provider is
// configured as "oidc" with its issuer.
var SocialPresets = map[string]string{
	"google": "https://accounts.google.com",
	"apple":  "https://appleid.apple.com",
}

// ---------------------------------------------------------------------
// Machines and agents (user-flow MACH-1 to MACH-10)
// ---------------------------------------------------------------------

const (
	PrincipalKindService = "service"
	PrincipalKindAgent   = "agent"

	// APIKeyPrefix is the readable start of every key, so secret scanners
	// can recognise one.
	APIKeyPrefix = "aos_"
	// APIKeyLimitPerMinute bounds one key's calls.
	APIKeyLimitPerMinute = 600
	APIKeyLimitWindow    = time.Minute
	BucketAPIKey         = "api_key"
	// APIKeyTouchInterval is how often "last used" is written.
	APIKeyTouchInterval = time.Minute

	// DelegationMaxHours bounds how long an agent may act for a user.
	DelegationMaxHours = 7 * 24
	// ApprovalTTL is how long an agent's request waits for a human.
	ApprovalTTL = time.Hour
	// ApprovalStepUpWindow: approving needs a second factor no older than this.
	ApprovalStepUpWindow = 5 * time.Minute

	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDeclined = "declined"
	ApprovalExpired  = "expired"
	ApprovalUsed     = "used"

	TemplateApprovalRequested = "approval_requested"
)

// ---------------------------------------------------------------------
// The tenant as an OAuth and OpenID Connect provider (MACH-5 to MACH-7)
// ---------------------------------------------------------------------

const (
	ChallengeAuthorizationRequest = "authorization_request"
	AuthorizationRequestTTL       = 10 * time.Minute
	AuthorizationCodeTTL          = 5 * time.Minute
	DeviceCodeTTL                 = 10 * time.Minute
	DeviceCodeInterval            = 5 // seconds between polls

	ClientConfidential     = "confidential"
	ClientPublic           = "public"
	ClientMetadataDocument = "metadata_document"

	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"

	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"

	// OAuthTokenType marks an access token the engine issued as a provider.
	OAuthTokenType = "oauth"

	// CLIClientID is the developer CLI (aosctl). Finishing the device flow
	// with it opens a token session, so the CLI can call the same routes a
	// signed-in person can.
	CLIClientID = "aos-cli"
)

// StandardScopes are always allowed on top of a client's own list.
var StandardScopes = map[string]bool{ScopeOpenID: true, ScopeProfile: true, ScopeEmail: true, ScopeOfflineAccess: true}

// ---------------------------------------------------------------------
// Enterprise sign-in and directory sync (user-flow ENT-1 to ENT-8)
// ---------------------------------------------------------------------

const (
	SSOProtocolOIDC = "oidc"
	SSOProtocolSAML = "saml"

	SSOStatusDraft    = "draft"
	SSOStatusActive   = "active"
	SSOStatusDisabled = "disabled"

	// TokenSSOSetup is the link an organization admin hands to their IT
	// admin. It opens one connection's settings and nothing else.
	TokenSSOSetup = "sso_setup"
	SSOSetupTTL   = 7 * 24 * time.Hour

	MethodEnterprise = "enterprise"

	GrantSourceSSO       = "sso"
	GrantSourceDirectory = "directory"

	// DomainVerificationPrefix is the DNS name that carries the TXT record.
	DomainVerificationPrefix = "_aos-verify."

	// AuditExportBatch is how many entries go in one export call.
	AuditExportBatch = 100
	// AuditExportInterval is how often the exporter looks for new entries.
	AuditExportInterval = 5 * time.Second
)
