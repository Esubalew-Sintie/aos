// Package rest declares the HTTP handlers.
package rest

import "net/http"

// AuthHandler serves the frontend routes. They are called from browsers
// and mobile apps with a publishable key.
type AuthHandler interface {
	SignUp(w http.ResponseWriter, r *http.Request)
	VerifyEmail(w http.ResponseWriter, r *http.Request)
	SignIn(w http.ResponseWriter, r *http.Request)
	SignOut(w http.ResponseWriter, r *http.Request)
	SignOutEverywhere(w http.ResponseWriter, r *http.Request)
	Session(w http.ResponseWriter, r *http.Request)
	ListSessions(w http.ResponseWriter, r *http.Request)
	RevokeSession(w http.ResponseWriter, r *http.Request)
	Token(w http.ResponseWriter, r *http.Request)
	ForgotPassword(w http.ResponseWriter, r *http.Request)
	ResetPassword(w http.ResponseWriter, r *http.Request)
	ChangePassword(w http.ResponseWriter, r *http.Request)
	ChangeEmail(w http.ResponseWriter, r *http.Request)
	ConfirmEmail(w http.ResponseWriter, r *http.Request)
	DeleteAccount(w http.ResponseWriter, r *http.Request)
	Export(w http.ResponseWriter, r *http.Request)
	SetupAccount(w http.ResponseWriter, r *http.Request)
	JWKS(w http.ResponseWriter, r *http.Request)

	// Strong sign-in (slice 5).
	SecondFactor(w http.ResponseWriter, r *http.Request)
	Factors(w http.ResponseWriter, r *http.Request)
	EnrollTOTP(w http.ResponseWriter, r *http.Request)
	ConfirmTOTP(w http.ResponseWriter, r *http.Request)
	DisableTOTP(w http.ResponseWriter, r *http.Request)
	RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request)
	StepUp(w http.ResponseWriter, r *http.Request)
	SendCode(w http.ResponseWriter, r *http.Request)
	VerifyCode(w http.ResponseWriter, r *http.Request)
	MagicLink(w http.ResponseWriter, r *http.Request)
	CreateGuest(w http.ResponseWriter, r *http.Request)
	UpgradeGuest(w http.ResponseWriter, r *http.Request)
	Refresh(w http.ResponseWriter, r *http.Request)
	BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request)
	FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request)
	ListPasskeys(w http.ResponseWriter, r *http.Request)
	DeletePasskey(w http.ResponseWriter, r *http.Request)
	BeginPasskeySignIn(w http.ResponseWriter, r *http.Request)
	FinishPasskeySignIn(w http.ResponseWriter, r *http.Request)
	StartSocial(w http.ResponseWriter, r *http.Request)
	FinishSocial(w http.ResponseWriter, r *http.Request)
	ListIdentities(w http.ResponseWriter, r *http.Request)
	UnlinkIdentity(w http.ResponseWriter, r *http.Request)
}

// SocialProviderHandler serves the backend routes that set providers up.
type SocialProviderHandler interface {
	Put(w http.ResponseWriter, r *http.Request)
	List(w http.ResponseWriter, r *http.Request)
	Delete(w http.ResponseWriter, r *http.Request)
}

// IAMHandler serves the backend routes for permissions. They are called
// from the application's own server with a secret key.
type IAMHandler interface {
	Can(w http.ResponseWriter, r *http.Request)
	PutPermission(w http.ResponseWriter, r *http.Request)
	PutRole(w http.ResponseWriter, r *http.Request)
	ListPermissions(w http.ResponseWriter, r *http.Request)
	ListRoles(w http.ResponseWriter, r *http.Request)
	CreateResource(w http.ResponseWriter, r *http.Request)
	CreateGrant(w http.ResponseWriter, r *http.Request)
	DeleteGrant(w http.ResponseWriter, r *http.Request)
	CanBatch(w http.ResponseWriter, r *http.Request)
	Explain(w http.ResponseWriter, r *http.Request)
	Filter(w http.ResponseWriter, r *http.Request)
	ListPrincipals(w http.ResponseWriter, r *http.Request)
	Simulate(w http.ResponseWriter, r *http.Request)
	PutGroup(w http.ResponseWriter, r *http.Request)
	ListGroups(w http.ResponseWriter, r *http.Request)
	DeleteGroup(w http.ResponseWriter, r *http.Request)
	AddGroupMember(w http.ResponseWriter, r *http.Request)
	RemoveGroupMember(w http.ResponseWriter, r *http.Request)
}

// OrganizationHandler serves organizations, members and invitations. The
// same handlers sit behind both doors: a signed-in person behind the
// frontend door, the application itself behind the backend door.
type OrganizationHandler interface {
	Create(w http.ResponseWriter, r *http.Request)
	List(w http.ResponseWriter, r *http.Request)
	Get(w http.ResponseWriter, r *http.Request)
	Switch(w http.ResponseWriter, r *http.Request)
	Delete(w http.ResponseWriter, r *http.Request)
	ListMembers(w http.ResponseWriter, r *http.Request)
	ChangeMemberRole(w http.ResponseWriter, r *http.Request)
	RemoveMember(w http.ResponseWriter, r *http.Request)
	Invite(w http.ResponseWriter, r *http.Request)
	ListInvitations(w http.ResponseWriter, r *http.Request)
	RevokeInvitation(w http.ResponseWriter, r *http.Request)
	PreviewInvitation(w http.ResponseWriter, r *http.Request)
	AcceptInvitation(w http.ResponseWriter, r *http.Request)
	DeclineInvitation(w http.ResponseWriter, r *http.Request)
	SignUpByInvitation(w http.ResponseWriter, r *http.Request)
}

// UserHandler serves the backend routes for accounts.
type UserHandler interface {
	ListUsers(w http.ResponseWriter, r *http.Request)
	CreateUser(w http.ResponseWriter, r *http.Request)
	GetUser(w http.ResponseWriter, r *http.Request)
	SuspendUser(w http.ResponseWriter, r *http.Request)
	ReinstateUser(w http.ResponseWriter, r *http.Request)
	DeleteUser(w http.ResponseWriter, r *http.Request)
	ResetSecondFactor(w http.ResponseWriter, r *http.Request)
}

// WebhookHandler serves the backend routes for endpoints the engine calls.
type WebhookHandler interface {
	Create(w http.ResponseWriter, r *http.Request)
	List(w http.ResponseWriter, r *http.Request)
	Delete(w http.ResponseWriter, r *http.Request)
}

// MachineHandler serves service accounts, agents, API keys, delegations
// and approvals.
type MachineHandler interface {
	CreateServiceAccount(w http.ResponseWriter, r *http.Request)
	ListServiceAccounts(w http.ResponseWriter, r *http.Request)
	CreateAgent(w http.ResponseWriter, r *http.Request)
	ListAgents(w http.ResponseWriter, r *http.Request)
	GetMachine(w http.ResponseWriter, r *http.Request)
	DisableMachine(w http.ResponseWriter, r *http.Request)
	EnableMachine(w http.ResponseWriter, r *http.Request)
	RevokeAgent(w http.ResponseWriter, r *http.Request)
	AgentAudit(w http.ResponseWriter, r *http.Request)
	CreateAPIKey(w http.ResponseWriter, r *http.Request)
	ListAPIKeys(w http.ResponseWriter, r *http.Request)
	RevokeAPIKey(w http.ResponseWriter, r *http.Request)
	CheckAPIKey(w http.ResponseWriter, r *http.Request)
	CreateDelegation(w http.ResponseWriter, r *http.Request)
	ListDelegations(w http.ResponseWriter, r *http.Request)
	RevokeDelegation(w http.ResponseWriter, r *http.Request)
	ListApprovals(w http.ResponseWriter, r *http.Request)
	ApproveApproval(w http.ResponseWriter, r *http.Request)
	DeclineApproval(w http.ResponseWriter, r *http.Request)
	GetApproval(w http.ResponseWriter, r *http.Request)
}

// OAuthHandler serves the tenant as an OAuth and OpenID Connect provider.
type OAuthHandler interface {
	PutClient(w http.ResponseWriter, r *http.Request)
	ListClients(w http.ResponseWriter, r *http.Request)
	DisableClient(w http.ResponseWriter, r *http.Request)
	Discovery(w http.ResponseWriter, r *http.Request)
	JWKS(w http.ResponseWriter, r *http.Request)
	Authorize(w http.ResponseWriter, r *http.Request)
	Token(w http.ResponseWriter, r *http.Request)
	DeviceAuthorization(w http.ResponseWriter, r *http.Request)
	UserInfo(w http.ResponseWriter, r *http.Request)
	Introspect(w http.ResponseWriter, r *http.Request)
	Revoke(w http.ResponseWriter, r *http.Request)
	GetAuthorizationRequest(w http.ResponseWriter, r *http.Request)
	Consent(w http.ResponseWriter, r *http.Request)
	ApproveDevice(w http.ResponseWriter, r *http.Request)
	ListConsents(w http.ResponseWriter, r *http.Request)
	RevokeConsent(w http.ResponseWriter, r *http.Request)
}

// EnterpriseHandler serves SSO connections, the setup page, enterprise
// sign-in and organization policies.
type EnterpriseHandler interface {
	CreateConnection(w http.ResponseWriter, r *http.Request)
	ListConnections(w http.ResponseWriter, r *http.Request)
	NewSetupLink(w http.ResponseWriter, r *http.Request)
	DisableConnection(w http.ResponseWriter, r *http.Request)
	SetupView(w http.ResponseWriter, r *http.Request)
	SetupSettings(w http.ResponseWriter, r *http.Request)
	SetupMappings(w http.ResponseWriter, r *http.Request)
	SetupAddDomain(w http.ResponseWriter, r *http.Request)
	SetupVerifyDomain(w http.ResponseWriter, r *http.Request)
	SetupTest(w http.ResponseWriter, r *http.Request)
	SetupActivate(w http.ResponseWriter, r *http.Request)
	SetupCreateDirectory(w http.ResponseWriter, r *http.Request)
	StartSSO(w http.ResponseWriter, r *http.Request)
	FinishSSO(w http.ResponseWriter, r *http.Request)
	GetPolicies(w http.ResponseWriter, r *http.Request)
	SetPolicies(w http.ResponseWriter, r *http.Request)
}

// SCIMHandler serves directory sync in the SCIM 2.0 shape.
type SCIMHandler interface {
	ServiceProviderConfig(w http.ResponseWriter, r *http.Request)
	ListUsers(w http.ResponseWriter, r *http.Request)
	GetUser(w http.ResponseWriter, r *http.Request)
	CreateUser(w http.ResponseWriter, r *http.Request)
	ReplaceUser(w http.ResponseWriter, r *http.Request)
	PatchUser(w http.ResponseWriter, r *http.Request)
	DeleteUser(w http.ResponseWriter, r *http.Request)
	ListGroups(w http.ResponseWriter, r *http.Request)
	GetGroup(w http.ResponseWriter, r *http.Request)
	CreateGroup(w http.ResponseWriter, r *http.Request)
	ReplaceGroup(w http.ResponseWriter, r *http.Request)
	PatchGroup(w http.ResponseWriter, r *http.Request)
	DeleteGroup(w http.ResponseWriter, r *http.Request)
}

// TransferHandler serves user import, tenant export and import, and
// access reviews.
type TransferHandler interface {
	ImportUsers(w http.ResponseWriter, r *http.Request)
	Export(w http.ResponseWriter, r *http.Request)
	Import(w http.ResponseWriter, r *http.Request)
	StartReview(w http.ResponseWriter, r *http.Request)
	ListReviews(w http.ResponseWriter, r *http.Request)
	GetReview(w http.ResponseWriter, r *http.Request)
	DecideReview(w http.ResponseWriter, r *http.Request)
}

// DevHandler serves development-only helpers, such as the inbox.
type DevHandler interface {
	ListMail(w http.ResponseWriter, r *http.Request)
	ClearMail(w http.ResponseWriter, r *http.Request)
}
