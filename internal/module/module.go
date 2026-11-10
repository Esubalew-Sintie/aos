// Package module declares the engine's business logic. Handlers call
// these interfaces and nothing below them.
package module

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/model"
)

// Tenant creates tenants and finds the tenant behind a presented key.
type Tenant interface {
	// CreateIn creates a tenant inside a switching transaction.
	CreateIn(ctx context.Context, tx pgx.Tx, req request.CreateTenantRequest) (*response.CreateTenantResponse, error)
	// NewSecretKey makes another secret key, inside the tenant's scope.
	NewSecretKey(ctx context.Context, tx pgx.Tx, t *model.Tenant) (string, error)
	// Get loads a tenant by id, or nil.
	Get(ctx context.Context, tenantID string) (*model.Tenant, error)
	// Create makes a tenant with its root resource, Owner role, keys and
	// first audit entry, all in one transaction. The secret key in the
	// answer cannot be shown again.
	Create(ctx context.Context, req request.CreateTenantRequest) (*response.CreateTenantResponse, error)
	// ResolveKey finds the tenant a key belongs to and, for a secret key,
	// checks the secret. It returns the kind of key that was presented.
	ResolveKey(ctx context.Context, presented string) (*model.Tenant, string, error)
	IsAllowedOrigin(ctx context.Context, tenantID, origin string) (bool, error)
	// FindBySlug finds a tenant by its short name, for the command line.
	FindBySlug(ctx context.Context, slug string) (*model.Tenant, error)
	// JWKS returns the public keys that verify this tenant's signed tokens.
	JWKS(ctx context.Context, t *model.Tenant) (*response.JWKSResponse, error)
}

// KeyRing hands a tenant's keys to the modules that encrypt and sign.
// Keys are decrypted with the master key and held in memory only.
type KeyRing interface {
	// DataKey returns the tenant's current data key and its id.
	DataKey(ctx context.Context, tx pgx.Tx, tenantID string) (id string, key []byte, err error)
	DataKeyByID(ctx context.Context, tx pgx.Tx, tenantID, id string) ([]byte, error)
	// SigningKey returns the tenant's current signing key and its key id.
	SigningKey(ctx context.Context, tx pgx.Tx, tenantID string) (kid string, key ed25519.PrivateKey, err error)
	// PublicKey returns the public half of one of the tenant's signing
	// keys, or nil for an unknown key id.
	PublicKey(ctx context.Context, tx pgx.Tx, tenantID, kid string) (ed25519.PublicKey, error)
}

// Notification is the outbox: messages to people, events and webhooks to
// the application, and the hooks the application answers before an action.
type Notification interface {
	// Enqueue stores a message in the caller's transaction. It is sent
	// only if that transaction commits.
	Enqueue(ctx context.Context, tx pgx.Tx, t *model.Tenant, m model.Message) error
	// Emit stores an event in the caller's transaction, and queues one
	// delivery of it for every endpoint that wants it.
	Emit(ctx context.Context, tx pgx.Tx, tenantID, eventType string, payload map[string]any) error
	// Hook asks the application's before-hook endpoints whether an action
	// may go ahead. It returns an error the caller can show when any of
	// them refuses, or cannot be reached in time.
	Hook(ctx context.Context, t *model.Tenant, name string, payload map[string]any) error

	CreateEndpoint(ctx context.Context, t *model.Tenant, req request.CreateWebhookRequest, meta model.RequestMeta) (*response.Webhook, error)
	ListEndpoints(ctx context.Context, t *model.Tenant) ([]response.Webhook, error)
	DeleteEndpoint(ctx context.Context, t *model.Tenant, id string, meta model.RequestMeta) error

	// DeliverDue sends the messages that are waiting and returns how many
	// it sent.
	DeliverDue(ctx context.Context) (int, error)
	// DeliverWebhooks sends the webhook deliveries that are waiting and
	// returns how many succeeded.
	// ExportAudit sends new audit entries to each organization's export
	// endpoint (ENT-8). It returns how many entries went out.
	ExportAudit(ctx context.Context) (int, error)
	DeliverWebhooks(ctx context.Context) (int, error)
	// Run delivers messages and webhooks until ctx ends.
	Run(ctx context.Context)
	// Wake asks Run to look for work now, without waiting for its timer.
	Wake()
}

// Auth is sign-up, sign-in, sessions and password reset.
type Auth interface {
	// SignUp always succeeds from the caller's point of view, whether or
	// not the address already has an account (user-flow REG-1, REG-3).
	SignUp(ctx context.Context, t *model.Tenant, req request.SignUpRequest, meta model.RequestMeta) error
	VerifyEmail(ctx context.Context, t *model.Tenant, req request.VerifyEmailRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	SignIn(ctx context.Context, t *model.Tenant, req request.SignInRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	SignOut(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) error
	// CurrentUser answers "who am I" for a session token.
	CurrentUser(ctx context.Context, t *model.Tenant, sessionToken string) (*response.SessionResponse, error)
	// IssueToken returns the short-lived signed token that the
	// application's own backend verifies (user-flow SYS-4).
	IssueToken(ctx context.Context, t *model.Tenant, sessionToken string) (*response.TokenResponse, error)
	// ForgotPassword always succeeds from the caller's point of view.
	ForgotPassword(ctx context.Context, t *model.Tenant, req request.ForgotPasswordRequest, meta model.RequestMeta) error
	ResetPassword(ctx context.Context, t *model.Tenant, req request.ResetPasswordRequest, meta model.RequestMeta) error

	// Authenticate returns the live session behind a token, or
	// ErrUnauthorized.
	Authenticate(ctx context.Context, t *model.Tenant, sessionToken string) (*model.Session, error)
	// StartSession signs a principal in inside the caller's transaction,
	// for flows that end in a sign-in, such as accepting an invitation.
	StartSession(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method string, meta model.RequestMeta) (*response.AuthResponse, error)

	// StartTokenSession opens a token session (an access and a refresh
	// token) inside the caller's transaction, for the developer CLI.
	StartTokenSession(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method string, meta model.RequestMeta) (*response.AuthResponse, error)

	// FinishExternalSignIn ends a sign-in that an outside system vouched
	// for (enterprise). With secondFactorAt the provider's second factor
	// is trusted; without it the engine asks for its own when the person
	// has one. activeOrg becomes the session's organization.
	FinishExternalSignIn(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method, kind string, secondFactorAt *time.Time, activeOrg string, meta model.RequestMeta) (*response.AuthResponse, error)

	// Second factors (SIGN-2, SIGN-9).
	SecondFactor(ctx context.Context, t *model.Tenant, req request.SecondFactorRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	Factors(ctx context.Context, t *model.Tenant, sessionToken string) (*response.Factors, error)
	EnrollTOTP(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) (*response.TOTPEnrollment, error)
	ConfirmTOTP(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) (*response.RecoveryCodes, error)
	DisableTOTP(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) error
	RegenerateRecoveryCodes(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) (*response.RecoveryCodes, error)
	StepUp(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) (*response.StepUpResponse, error)
	// ResetSecondFactor removes every second factor of a user, for an
	// admin helping someone who lost their phone and codes.
	ResetSecondFactor(ctx context.Context, t *model.Tenant, principalID string, meta model.RequestMeta) error

	// One-time codes and magic links (SIGN-4).
	SendCode(ctx context.Context, t *model.Tenant, req request.SendCodeRequest, meta model.RequestMeta) error
	VerifyCode(ctx context.Context, t *model.Tenant, req request.VerifyCodeRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	MagicLink(ctx context.Context, t *model.Tenant, req request.MagicLinkRequest, meta model.RequestMeta) (*response.AuthResponse, error)

	// Passkeys (SIGN-3).
	BeginPasskeyRegistration(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) (*response.PasskeyChallenge, error)
	FinishPasskeyRegistration(ctx context.Context, t *model.Tenant, sessionToken string, req request.PasskeyFinishRequest, meta model.RequestMeta) (*response.Passkey, error)
	ListPasskeys(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Passkey, error)
	DeletePasskey(ctx context.Context, t *model.Tenant, sessionToken, id string, meta model.RequestMeta) error
	BeginPasskeySignIn(ctx context.Context, t *model.Tenant, meta model.RequestMeta) (*response.PasskeyChallenge, error)
	FinishPasskeySignIn(ctx context.Context, t *model.Tenant, req request.PasskeyFinishRequest, meta model.RequestMeta) (*response.AuthResponse, error)

	// Social sign-in (REG-5, SIGN-5).
	PutOAuthProvider(ctx context.Context, t *model.Tenant, req request.PutOAuthProviderRequest, meta model.RequestMeta) (*response.OAuthProvider, error)
	ListOAuthProviders(ctx context.Context, t *model.Tenant) ([]response.OAuthProvider, error)
	DeleteOAuthProvider(ctx context.Context, t *model.Tenant, provider string, meta model.RequestMeta) error
	// StartSocial begins a sign-in, or a link when a session is given.
	StartSocial(ctx context.Context, t *model.Tenant, provider, sessionToken string, req request.SocialStartRequest, meta model.RequestMeta) (*response.SocialStart, error)
	FinishSocial(ctx context.Context, t *model.Tenant, provider string, req request.SocialFinishRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	ListIdentities(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Identity, error)
	UnlinkIdentity(ctx context.Context, t *model.Tenant, sessionToken, provider string, meta model.RequestMeta) error

	// Token sessions (SIGN-8).
	Refresh(ctx context.Context, t *model.Tenant, req request.RefreshRequest, meta model.RequestMeta) (*response.AuthResponse, error)

	// Guests (REG-8).
	CreateGuest(ctx context.Context, t *model.Tenant, req request.GuestRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	// UpgradeGuest turns the signed-in guest into a user with a pending
	// password and a verification email.
	UpgradeGuest(ctx context.Context, t *model.Tenant, sessionToken string, req request.SignUpRequest, meta model.RequestMeta) error
	// ListSessions is the person's device list.
	ListSessions(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.SessionInfo, error)
	// RevokeSession ends one of the person's own sessions.
	RevokeSession(ctx context.Context, t *model.Tenant, sessionToken, sessionID string, meta model.RequestMeta) error
	// SignOutEverywhere ends every session of the person, this one included.
	SignOutEverywhere(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) error
	// ChangePassword needs the current password. It ends every other session.
	ChangePassword(ctx context.Context, t *model.Tenant, sessionToken string, req request.ChangePasswordRequest, meta model.RequestMeta) error
	// ChangeEmail sends a confirmation link to the new address and a notice
	// to the old one. Nothing changes until the link is confirmed.
	ChangeEmail(ctx context.Context, t *model.Tenant, sessionToken string, req request.ChangeEmailRequest, meta model.RequestMeta) error
	ConfirmEmail(ctx context.Context, t *model.Tenant, req request.ConfirmEmailRequest, meta model.RequestMeta) (*response.User, error)
	// DeleteAccount needs the password. The account stops at once and is
	// erased after the grace period.
	DeleteAccount(ctx context.Context, t *model.Tenant, sessionToken string, req request.PasswordConfirmRequest, meta model.RequestMeta) error
	// Export returns everything AOS holds about the person.
	Export(ctx context.Context, t *model.Tenant, sessionToken string, req request.PasswordConfirmRequest, meta model.RequestMeta) (*response.ExportResponse, error)
	// SetupAccount finishes an account an admin created: the person opens
	// the setup link and chooses a password.
	SetupAccount(ctx context.Context, t *model.Tenant, req request.SetupAccountRequest, meta model.RequestMeta) (*response.AuthResponse, error)

	// Admin actions, for the backend door and the command line.
	CreateUser(ctx context.Context, t *model.Tenant, req request.CreateUserRequest, meta model.RequestMeta) (*response.User, error)
	GetUser(ctx context.Context, t *model.Tenant, principalID string) (*response.User, error)
	ListUsers(ctx context.Context, t *model.Tenant, cursor string, limit int) (*response.UserPage, error)
	SuspendUser(ctx context.Context, t *model.Tenant, principalID, reason string, meta model.RequestMeta) error
	ReinstateUser(ctx context.Context, t *model.Tenant, principalID string, meta model.RequestMeta) error
	DeleteUser(ctx context.Context, t *model.Tenant, principalID string, meta model.RequestMeta) error
}

// Authorizer answers permission questions inside another module's
// transaction, so an action and its check commit together.
type Authorizer interface {
	// Check reports whether a principal holds a permission on a resource.
	// Root actors are not checked here: callers skip the check for them.
	Check(ctx context.Context, tx pgx.Tx, tenantID, principalID, permission, resourceID string) (bool, string, error)
	// MayGrant reports whether an actor holds, on the resource, every
	// permission the role carries. Nobody can hand out more than they hold.
	MayGrant(ctx context.Context, tx pgx.Tx, tenantID, actorID, roleID, resourceID string) (bool, error)
}

// IAM is permissions, roles, resources, grants and the permission check.
type IAM interface {
	Authorizer
	// Can answers "may this principal do this action on this resource?".
	Can(ctx context.Context, t *model.Tenant, req request.CanRequest, meta model.RequestMeta) (*response.CanResponse, error)
	// PutPermission creates a permission or updates its description.
	// source says where it comes from: "code" or "portal".
	PutPermission(ctx context.Context, t *model.Tenant, req request.PutPermissionRequest, source string, meta model.RequestMeta) (*response.Permission, error)
	// PutRole creates a role or replaces what it holds.
	PutRole(ctx context.Context, t *model.Tenant, req request.PutRoleRequest, source string, meta model.RequestMeta) (*response.Role, error)
	// CreateResource adds a node to the tree. Asking again for a node that
	// already exists in the same place returns it.
	CreateResource(ctx context.Context, t *model.Tenant, req request.CreateResourceRequest, meta model.RequestMeta) (*response.Resource, error)
	// ListPermissions and ListRoles return the catalog, for tools that
	// compare it with what an application declares.
	ListPermissions(ctx context.Context, t *model.Tenant) ([]response.Permission, error)
	ListRoles(ctx context.Context, t *model.Tenant) ([]response.Role, error)
	CreateGrant(ctx context.Context, t *model.Tenant, req request.CreateGrantRequest, meta model.RequestMeta) (*response.Grant, error)
	DeleteGrant(ctx context.Context, t *model.Tenant, grantID string, meta model.RequestMeta) error

	// CanBatch answers many questions in one call, for showing and hiding buttons.
	CanBatch(ctx context.Context, t *model.Tenant, req request.CanBatchRequest, meta model.RequestMeta) (*response.CanBatchResponse, error)
	// Explain returns the path that decided a question.
	Explain(ctx context.Context, t *model.Tenant, req request.CanRequest) (*response.ExplainResponse, error)
	// Filter lists the resources of a type where the permission holds.
	Filter(ctx context.Context, t *model.Tenant, req request.FilterRequest) (*response.FilterResponse, error)
	// ListPrincipals says who may do an action on a resource.
	ListPrincipals(ctx context.Context, t *model.Tenant, req request.ListPrincipalsRequest) (*response.PrincipalsResponse, error)
	// Simulate says who would lose what if a grant were removed. Nothing changes.
	Simulate(ctx context.Context, t *model.Tenant, req request.SimulateRequest) (*response.SimulateResponse, error)

	PutGroup(ctx context.Context, t *model.Tenant, req request.PutGroupRequest, meta model.RequestMeta) (*response.Group, error)
	ListGroups(ctx context.Context, t *model.Tenant, organizationID string) ([]response.Group, error)
	DeleteGroup(ctx context.Context, t *model.Tenant, groupID string, meta model.RequestMeta) error
	AddGroupMember(ctx context.Context, t *model.Tenant, groupID, principalID string, meta model.RequestMeta) error
	RemoveGroupMember(ctx context.Context, t *model.Tenant, groupID, principalID string, meta model.RequestMeta) error
}

// Organization is a customer of the application and its people.
//
// Every method takes the actor: Root for the backend door, or the
// signed-in person, whose grants decide what they may do.
type Organization interface {
	Create(ctx context.Context, t *model.Tenant, actor model.Actor, req request.CreateOrganizationRequest, meta model.RequestMeta) (*response.Organization, error)
	// List returns the organizations the actor belongs to, or all of them for Root.
	List(ctx context.Context, t *model.Tenant, actor model.Actor) ([]response.Organization, error)
	Get(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string) (*response.Organization, error)
	// Switch makes the organization the active one in the actor's session.
	Switch(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string, meta model.RequestMeta) error
	Delete(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string, meta model.RequestMeta) error

	ListMembers(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string) ([]response.Member, error)
	ChangeMemberRole(ctx context.Context, t *model.Tenant, actor model.Actor, orgID, principalID string, req request.ChangeMemberRoleRequest, meta model.RequestMeta) error
	RemoveMember(ctx context.Context, t *model.Tenant, actor model.Actor, orgID, principalID string, meta model.RequestMeta) error

	Invite(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string, req request.InviteRequest, meta model.RequestMeta) (*response.Invitation, error)
	ListInvitations(ctx context.Context, t *model.Tenant, actor model.Actor, orgID string) ([]response.Invitation, error)
	RevokeInvitation(ctx context.Context, t *model.Tenant, actor model.Actor, orgID, invitationID string, meta model.RequestMeta) error
	// Preview shows an invitation to whoever holds its link.
	Preview(ctx context.Context, t *model.Tenant, token string) (*response.InvitationPreview, error)
	// Accept needs a signed-in person whose address matches the invitation.
	Accept(ctx context.Context, t *model.Tenant, actor model.Actor, req request.InvitationTokenRequest, meta model.RequestMeta) (*response.Organization, error)
	Decline(ctx context.Context, t *model.Tenant, req request.InvitationTokenRequest, meta model.RequestMeta) error
	// SignUp creates an account from an invitation and accepts it.
	SignUp(ctx context.Context, t *model.Tenant, req request.InvitationSignUpRequest, meta model.RequestMeta) (*response.AuthResponse, error)
}

// UsageMeter counts what a tenant does and knows its limits. It is a
// small door into the platform from inside a tenant's scope.
type UsageMeter interface {
	Count(ctx context.Context, tx pgx.Tx, tenantID, metric string) error
	// Limit returns -1 when there is none.
	Limit(ctx context.Context, tx pgx.Tx, tenantID, metric string) (int64, error)
}

// Machine is the non-human side (user-flow MACH-1 to MACH-4, MACH-8 to
// MACH-10): service accounts, agents, API keys, delegations, approvals.
type Machine interface {
	CreateMachine(ctx context.Context, t *model.Tenant, kind string, req request.CreateMachineRequest, meta model.RequestMeta) (*response.Machine, error)
	ListMachines(ctx context.Context, t *model.Tenant, kind string) ([]response.Machine, error)
	GetMachine(ctx context.Context, t *model.Tenant, id string) (*response.Machine, error)
	// DisableMachine suspends it; its keys stop on the next request.
	DisableMachine(ctx context.Context, t *model.Tenant, id, reason string, meta model.RequestMeta) error
	EnableMachine(ctx context.Context, t *model.Tenant, id string, meta model.RequestMeta) error
	// RevokeAgent is the one switch: tokens, delegations, keys and grants.
	RevokeAgent(ctx context.Context, t *model.Tenant, id, reason string, meta model.RequestMeta) (*response.AgentRevocation, error)
	AgentAudit(ctx context.Context, t *model.Tenant, id string, limit int) ([]response.AuditEntry, error)

	// CreateAPIKey issues a key. actor is Root from the backend, or the
	// person issuing one for themselves.
	CreateAPIKey(ctx context.Context, t *model.Tenant, actor model.Actor, req request.CreateAPIKeyRequest, meta model.RequestMeta) (*response.CreatedAPIKey, error)
	ListAPIKeys(ctx context.Context, t *model.Tenant, actor model.Actor, principalID string) ([]response.APIKey, error)
	RevokeAPIKey(ctx context.Context, t *model.Tenant, actor model.Actor, id string, meta model.RequestMeta) error
	// CheckAPIKey identifies the key and, with a permission, answers the
	// question as the key's principal within the key's scopes.
	CheckAPIKey(ctx context.Context, t *model.Tenant, req request.CheckAPIKeyRequest, meta model.RequestMeta) (*response.APIKeyCheck, error)

	CreateDelegation(ctx context.Context, t *model.Tenant, sessionToken string, req request.CreateDelegationRequest, meta model.RequestMeta) (*response.Delegation, error)
	ListDelegations(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Delegation, error)
	RevokeDelegation(ctx context.Context, t *model.Tenant, sessionToken, id string, meta model.RequestMeta) error

	// Approvals from the person's side, and the agent's.
	ListApprovals(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Approval, error)
	DecideApproval(ctx context.Context, t *model.Tenant, sessionToken, id string, approve bool, meta model.RequestMeta) (*response.Approval, error)
	GetApproval(ctx context.Context, t *model.Tenant, id string) (*response.Approval, error)
}

// OAuthProvider makes the tenant an OAuth and OpenID Connect provider
// (user-flow MACH-5 to MACH-7). The public door, under /t/{slug}, speaks
// the standard protocol with plain JSON; the rest uses the envelope.
type OAuthProvider interface {
	PutClient(ctx context.Context, t *model.Tenant, req request.PutOAuthClientRequest, meta model.RequestMeta) (*response.OAuthClient, error)
	ListClients(ctx context.Context, t *model.Tenant) ([]response.OAuthClient, error)
	DisableClient(ctx context.Context, t *model.Tenant, id string, meta model.RequestMeta) error

	// Discovery is the provider's configuration document.
	Discovery(t *model.Tenant) map[string]any
	// Authorize checks an authorization request and returns where the
	// browser goes: the application's consent page, or back to the client
	// with an error. A request that cannot be trusted at all returns an
	// OAuthError instead.
	Authorize(ctx context.Context, t *model.Tenant, query map[string]string, meta model.RequestMeta) (redirect string, err error)
	GetAuthorizationRequest(ctx context.Context, t *model.Tenant, sessionToken, requestID string) (*response.AuthorizationRequestView, error)
	Consent(ctx context.Context, t *model.Tenant, sessionToken string, req request.ConsentRequest, meta model.RequestMeta) (*response.ConsentResult, error)
	// Token is the token endpoint. It returns the body to send, with its
	// status, in the protocol's own shape.
	Token(ctx context.Context, t *model.Tenant, form map[string]string, basicUser, basicSecret string, meta model.RequestMeta) (int, map[string]any)
	DeviceAuthorization(ctx context.Context, t *model.Tenant, form map[string]string, meta model.RequestMeta) (int, map[string]any)
	ApproveDevice(ctx context.Context, t *model.Tenant, sessionToken string, req request.DeviceApproveRequest, meta model.RequestMeta) (*response.DeviceApproval, error)
	UserInfo(ctx context.Context, t *model.Tenant, bearer string) (int, map[string]any)
	Introspect(ctx context.Context, t *model.Tenant, form map[string]string, basicUser, basicSecret string) (int, map[string]any)
	Revoke(ctx context.Context, t *model.Tenant, form map[string]string, basicUser, basicSecret string, meta model.RequestMeta) (int, map[string]any)

	ListConsents(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Consent, error)
	RevokeConsent(ctx context.Context, t *model.Tenant, sessionToken, clientID string, meta model.RequestMeta) error
}

// OAuthError is a refusal in the protocol's own words.
type OAuthError struct {
	Status      int
	Code        string
	Description string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

// Enterprise is the company side (user-flow ENT-1 to ENT-8): a
// connection to the company's identity provider, set up by its IT admin
// through a link; verified domains; sign-in through the provider;
// directory sync; organization policies.
type Enterprise interface {
	CreateConnection(ctx context.Context, t *model.Tenant, actor model.Actor, req request.CreateConnectionRequest, meta model.RequestMeta) (*response.SetupLink, error)
	ListConnections(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string) ([]response.SSOConnection, error)
	// NewSetupLink makes another link for an existing connection.
	NewSetupLink(ctx context.Context, t *model.Tenant, actor model.Actor, connectionID string, meta model.RequestMeta) (*response.SetupLink, error)
	DisableConnection(ctx context.Context, t *model.Tenant, actor model.Actor, connectionID string, meta model.RequestMeta) error

	// The setup page, opened with the link. No account is needed.
	SetupView(ctx context.Context, t *model.Tenant, token string) (*response.SSOConnection, error)
	SetupSettings(ctx context.Context, t *model.Tenant, token string, req request.ConnectionSettingsRequest, meta model.RequestMeta) (*response.SSOConnection, error)
	SetupMappings(ctx context.Context, t *model.Tenant, token string, req request.MappingsRequest, meta model.RequestMeta) (*response.SSOConnection, error)
	SetupAddDomain(ctx context.Context, t *model.Tenant, token string, req request.DomainRequest, meta model.RequestMeta) (*response.Domain, error)
	SetupVerifyDomain(ctx context.Context, t *model.Tenant, token, domainID string, meta model.RequestMeta) (*response.Domain, error)
	SetupTest(ctx context.Context, t *model.Tenant, token string, req request.SocialStartRequest, meta model.RequestMeta) (*response.SSOStart, error)
	SetupActivate(ctx context.Context, t *model.Tenant, token string, meta model.RequestMeta) (*response.SSOConnection, error)
	SetupCreateDirectory(ctx context.Context, t *model.Tenant, token string, req request.CreateDirectoryRequest, meta model.RequestMeta) (*response.Directory, error)

	// Enterprise sign-in (ENT-3, ENT-4).
	StartSSO(ctx context.Context, t *model.Tenant, req request.SSOStartRequest, meta model.RequestMeta) (*response.SSOStart, error)
	FinishSSO(ctx context.Context, t *model.Tenant, req request.SocialFinishRequest, meta model.RequestMeta) (*response.AuthResponse, error)
	// ConnectionForEmail returns the active connection an email's domain
	// is bound to, or nil. Used to send people to their provider.
	ConnectionForEmail(ctx context.Context, tx pgx.Tx, t *model.Tenant, email string) (*model.SSOConnection, *model.OrgPolicies, error)

	// Policies (ENT-6, ENT-7).
	GetPolicies(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string) (*response.OrgPolicies, error)
	SetPolicies(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string, req request.OrgPoliciesRequest, meta model.RequestMeta) (*response.OrgPolicies, error)

	// Directory sync (ENT-5). The SCIM handler calls these with the
	// directory the token resolved to.
	SCIMListUsers(ctx context.Context, tenantID, directoryID, filterEmail string) ([]model.DirectoryUser, error)
	SCIMGetUser(ctx context.Context, tenantID, directoryID, id string) (*model.DirectoryUser, error)
	SCIMCreateUser(ctx context.Context, tenantID, directoryID, externalID, email, name string, active bool) (*model.DirectoryUser, error)
	SCIMUpdateUser(ctx context.Context, tenantID, directoryID, id string, email, name *string, active *bool) (*model.DirectoryUser, error)
	SCIMDeleteUser(ctx context.Context, tenantID, directoryID, id string) error
	SCIMListGroups(ctx context.Context, tenantID, directoryID string) ([]model.Group, error)
	SCIMGetGroup(ctx context.Context, tenantID, directoryID, id string) (*model.Group, error)
	SCIMCreateGroup(ctx context.Context, tenantID, directoryID, externalID, name string, members []string) (*model.Group, error)
	SCIMUpdateGroup(ctx context.Context, tenantID, directoryID, id string, name *string, members []string, add, remove []string) (*model.Group, error)
	SCIMDeleteGroup(ctx context.Context, tenantID, directoryID, id string) error
	// ResolveDirectory finds the tenant and directory behind a sync token.
	ResolveDirectory(ctx context.Context, token string) (tenantID, directoryID, organizationID string, err error)
}

// Transfer moves people and whole tenants between homes (SET-4 step 6,
// HOST-6).
type Transfer interface {
	ImportUsers(ctx context.Context, t *model.Tenant, req request.ImportUsersRequest, meta model.RequestMeta) (*response.ImportResult, error)
	Export(ctx context.Context, t *model.Tenant, req request.ExportRequest, meta model.RequestMeta) (*response.Archive, error)
	// Import fills an empty tenant from an archive.
	Import(ctx context.Context, t *model.Tenant, req request.ImportArchiveRequest, meta model.RequestMeta) (*response.ArchiveImport, error)
}

// Review is access reviews (ADM-6).
type Review interface {
	Start(ctx context.Context, t *model.Tenant, actor model.Actor, req request.StartReviewRequest, meta model.RequestMeta) (*response.AccessReview, error)
	List(ctx context.Context, t *model.Tenant, actor model.Actor, organizationID string) ([]response.AccessReview, error)
	Get(ctx context.Context, t *model.Tenant, actor model.Actor, id string) (*response.AccessReview, error)
	Decide(ctx context.Context, t *model.Tenant, actor model.Actor, reviewID, itemID string, req request.ReviewDecisionRequest, meta model.RequestMeta) (*response.AccessReview, error)
}
