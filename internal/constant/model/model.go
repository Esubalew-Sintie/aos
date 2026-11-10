// Package model holds the plain data that moves between the storage and
// module layers. Nothing here knows about HTTP or SQL.
package model

import "time"

// Tenant is one application's isolated pool of users, settings and keys.
type Tenant struct {
	ID            string
	Slug          string
	Name          string
	Kind          string
	Environment   string
	Status        string
	SignupPolicy  string
	SignupDomains []string
	// OrgCreationPolicy says who may create an organization (user-flow WHO-4).
	OrgCreationPolicy string
	// MFAPolicy is "optional" or "required" (SIGN-1 step 9).
	MFAPolicy       string
	DefaultRoleID   string // empty when new users receive no role
	SessionIdle     time.Duration
	SessionAbsolute time.Duration
	RootResourceID  string
	// AppURL is the application's own address. Links in emails point there.
	AppURL string
}

// Development reports whether this is a development tenant, where the
// session token may travel in a header instead of a cookie.
func (t *Tenant) Development() bool { return t.Environment == "development" }

// NewTenant is everything written when a tenant is created.
type NewTenant struct {
	Slug        string
	Name        string
	Kind        string
	Environment string
	Settings    map[string]any
}

// ResolvedKey is what the database returns for a presented key.
type ResolvedKey struct {
	TenantID     string
	KeyID        string
	Kind         string
	SecretHash   []byte
	TenantStatus string
}

// RequestMeta describes where a request came from.
type RequestMeta struct {
	IP        string
	UserAgent string
	RequestID string
	// DeviceToken is the long-lived id the browser holds, when it has one.
	DeviceToken string
}

// UserAuth is what sign-in needs to know about an account.
type UserAuth struct {
	PrincipalID   string
	Kind          string
	Status        string
	EmailVerified bool
	// PasswordHash is the active password, or empty when there is none.
	PasswordHash string
}

// User is a person's profile.
type User struct {
	ID             string
	Email          string
	Name           string
	Status         string
	EmailVerified  bool
	AssuranceLevel int
	CreatedAt      time.Time
	// Guest is true for a principal with no account yet (REG-8).
	Guest bool
}

// PrincipalRow is the row behind any actor: a user, a guest, a service.
type PrincipalRow struct {
	ID          string
	Kind        string
	Status      string
	DisplayName string
	CreatedAt   time.Time
}

// Token is a stored single-use token.
type Token struct {
	ID          string
	PrincipalID string
	Hash        []byte
	Attempts    int
	MaxAttempts int
	ExpiresAt   time.Time
	UsedAt      *time.Time
	Payload     map[string]string
}

// SessionInfo is what a person sees in their device list.
type SessionInfo struct {
	ID          string
	Current     bool
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	IP          string
	UserAgent   string
	AuthMethods []AuthMethod
}

// GrantInfo is a grant as shown to a person or an admin.
type GrantInfo struct {
	ID           string
	PrincipalID  string
	Role         string
	ResourceType string
	ResourceID   string
	Effect       string
	ExpiresAt    *time.Time
	Reason       string
	Source       string
	CreatedAt    time.Time
}

// GrantFilter narrows a list of grants. Empty fields match everything.
type GrantFilter struct {
	PrincipalID string
	Resource    *ResourceRef
}

// WebhookEndpoint is where events, hook calls or audit entries are sent.
type WebhookEndpoint struct {
	ID              string
	Kind            string
	URL             string
	Label           string
	EventTypes      []string
	TimeoutMs       int
	Enabled         bool
	SecretEncrypted []byte
	DataKeyID       string
	OrganizationID  string
	CreatedAt       time.Time
	LastSuccessAt   *time.Time
	LastFailureAt   *time.Time
	LastError       string
}

// DueDelivery points at a webhook delivery that is waiting.
type DueDelivery struct {
	TenantID string
	ID       string
}

// StoredDelivery is a delivery as read back by the worker, with the
// event and the endpoint it belongs to.
type StoredDelivery struct {
	ID              string
	EndpointID      string
	EventID         string
	EventType       string
	Payload         []byte
	EventCreatedAt  time.Time
	Attempts        int
	URL             string
	SecretEncrypted []byte
	DataKeyID       string
	TimeoutMs       int
}

// AuditView is an audit entry as shown to a person.
type AuditView struct {
	Seq        int64
	OccurredAt time.Time
	Action     string
	Result     string
	ReasonCode string
	TargetType string
	TargetID   string
}

// AuditRecord is an audit entry as shown to a tenant admin, with who
// acted.
type AuditRecord struct {
	Seq            int64
	OccurredAt     time.Time
	Action         string
	Result         string
	ReasonCode     string
	ActorType      string
	ActorID        string
	ActorEmail     string
	TargetType     string
	TargetID       string
	OrganizationID string
	IP             string
}

// AuditFilter narrows the audit log. Empty fields match everything.
type AuditFilter struct {
	// Before returns entries older than this sequence number. 0 starts at the newest.
	Before int64
	// ActionPrefix matches actions that start with it, such as "user.".
	ActionPrefix string
	ActorID      string
	TargetID     string
}

// NewToken is a single-use token to store. Only its hash is kept.
type NewToken struct {
	Purpose     string
	PrincipalID string
	Target      string
	Hash        []byte
	ExpiresAt   time.Time
	// MaxAttempts is how many wrong guesses a code allows. Zero means one.
	MaxAttempts int
	// Payload holds what the token carries, such as a new email address.
	Payload map[string]string
}

// AuthMethod records one way a person proved who they are, and when.
type AuthMethod struct {
	Method string    `json:"method"`
	At     time.Time `json:"at"`
}

// NewSession is a session to store. Only the hash of its id is kept.
type NewSession struct {
	PrincipalID       string
	IDHash            []byte
	Kind              string // "browser" (default) or "token"
	AuthMethods       []AuthMethod
	AssuranceLevel    int
	SecondFactorAt    *time.Time
	DeviceID          string
	IP                string
	UserAgent         string
	Now               time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// Session is a stored signed-in state.
type Session struct {
	ID                string
	PrincipalID       string
	PrincipalStatus   string
	AssuranceLevel    int
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	// ActiveResourceID is the organization the person is working in, as
	// a resource id. Empty when none is chosen.
	ActiveResourceID string
	ActiveExternalID string
	Kind             string
	AuthMethods      []AuthMethod
	// SecondFactorAt is when a second factor was last given, or nil.
	SecondFactorAt *time.Time
	DeviceID       string
}

// TOTPFactor is an authenticator app set up for a person.
type TOTPFactor struct {
	ID              string
	SecretEncrypted []byte
	DataKeyID       string
	Confirmed       bool
	LastUsedStep    int64
}

// Challenge is a short-lived state the engine keeps between two steps,
// such as a pending sign-in waiting for its second factor.
type Challenge struct {
	ID          string
	Kind        string
	PrincipalID string
	Data        map[string]any
	Attempts    int
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

type NewChallenge struct {
	Kind        string
	PrincipalID string
	TokenHash   []byte
	Data        map[string]any
	ExpiresAt   time.Time
}

// Device is a browser or app a person has signed in from before.
type Device struct {
	ID          string
	Label       string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// Factors is what a person has set up as second factors.
type Factors struct {
	TOTP              bool
	Passkeys          int
	RecoveryCodesLeft int
}

// Actor is who is asking. A call through the backend door, with the
// tenant's secret key, is Root: it holds every permission. A call from a
// signed-in person is bound by that person's grants.
type Actor struct {
	Root        bool
	PrincipalID string
	SessionID   string
}

// Organization is a customer of the application: a branch of the
// resource tree with its own members.
type Organization struct {
	ID        string // the resource id
	Slug      string
	Name      string
	Status    string
	CreatedAt time.Time
}

// Member is a person with a role in an organization.
type Member struct {
	PrincipalID string
	Email       string
	Name        string
	Status      string
	Roles       []string
}

// Invitation is a pending invitation to an organization.
type Invitation struct {
	ID               string
	Email            string
	RoleID           string
	RoleName         string
	ResourceID       string
	ResourceType     string
	ResourceExtID    string
	OrganizationID   string
	OrganizationName string
	InviterID        string
	InviterName      string
	ExpiresAt        time.Time
	AcceptedAt       *time.Time
	DeclinedAt       *time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
}

// NewInvitation is an invitation to store. Only the hash of its token is kept.
type NewInvitation struct {
	Email      string
	RoleID     string
	ResourceID string
	InviterID  string
	TokenHash  []byte
	ExpiresAt  time.Time
}

// Group is a set of principals that receive grants together.
type Group struct {
	ID             string
	Name           string
	OrganizationID string
	MemberCount    int
	CreatedAt      time.Time
	// ExternalID is the company directory's id for a synced group.
	ExternalID string
	Members    []string
}

// Principal is any actor, as listed.
type Principal struct {
	ID     string
	Kind   string
	Email  string
	Name   string
	Status string
}

// ResourceNode is a node of the tree as shown in an explanation.
type ResourceNode struct {
	ID         string
	Type       string
	ExternalID string
	Depth      int
}

// RateLimit is the state of one counter after a hit.
type RateLimit struct {
	Count       int
	LockedUntil *time.Time
}

// DataKey is a tenant's data key as stored: wrapped by the master key.
type DataKey struct {
	ID      string
	Wrapped []byte
}

// SigningKey is a tenant's signing key as stored: the private half is
// encrypted with the tenant's data key.
type SigningKey struct {
	KID              string
	Public           []byte
	PrivateEncrypted []byte
	DataKeyID        string
}

// ResourceRef names a resource the way the application knows it: by its
// type and the application's own id.
type ResourceRef struct {
	Type string
	ID   string
}

// MatchedGrant is a grant that applies to a permission question.
type MatchedGrant struct {
	ID          string
	Effect      string
	RoleName    string
	Conditional bool
	Condition   string
	// Depth is how far above the resource the grant was made. 0 is the
	// resource itself.
	Depth int
}

// NewGrant is a grant to store. Exactly one of PrincipalID and GroupID.
type NewGrant struct {
	PrincipalID string
	GroupID     string
	RoleID      string
	ResourceID  string
	Effect      string
	Condition   string
	ExpiresAt   *time.Time
	Source      string
	Reason      string
	CreatedBy   string
}

// Decision is one permission decision to log.
type Decision struct {
	PrincipalID string
	Permission  string
	ResourceID  string
	Allowed     bool
	ReasonCode  string
	GrantID     string
	RequestID   string
}

// Message is an email or SMS to send.
type Message struct {
	Channel   string
	Recipient string
	Template  string
	// Data fills the template. It can hold a raw token, so it is stored
	// encrypted and wiped once the message is sent.
	Data map[string]string
}

// DueMessage points at a message that is waiting to be sent.
type DueMessage struct {
	TenantID string
	ID       string
}

// StoredMessage is a message as read back for delivery.
type StoredMessage struct {
	Channel   string
	Recipient string
	Template  string
	Body      []byte
	DataKeyID string
	Attempts  int
}

// AuditEntry is one thing that happened. It holds ids, never names or
// email addresses, so erasing a person does not touch the log.
type AuditEntry struct {
	Action         string // for example "signin.succeeded" or "grant.created"
	Result         string // "success", "failure" or "denied"
	ReasonCode     string
	OrganizationID string
	ActorID        string // the principal who did it
	ImpersonatorID string // the support person acting as ActorID, if any
	OnBehalfOfID   string // the user an agent acted for, if any
	TargetType     string
	TargetID       string
	SessionID      string
	RequestID      string
	Data           map[string]any

	// Personal details. They are stored apart from the entry and are not
	// part of its hash, so they can be erased later.
	IP        string
	UserAgent string
}

// Audit results.
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
	AuditDenied  = "denied"
)

// TenantKey is a key as its owner sees it: never the secret.
type TenantKey struct {
	ID         string
	Kind       string
	PublicID   string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// TenantSettings are what a developer may change on a tenant.
type TenantSettings struct {
	Name              string
	AppURL            string
	SignupPolicy      string
	SignupDomains     []string
	OrgCreationPolicy string
	// DefaultRoleID is the role every new user receives, "" for none.
	DefaultRoleID   string
	SessionIdle     time.Duration
	SessionAbsolute time.Duration
}

// RefreshToken is one link in a token family (SIGN-8, MACH-5).
type RefreshToken struct {
	ID            string
	FamilyID      string
	PrincipalID   string
	SessionID     string
	ClientID      string // the OAuth client, for a family a client holds
	Scopes        []string
	Audience      string
	ExpiresAt     time.Time
	UsedAt        *time.Time
	FamilyRevoked bool
}

// OAuthClient is another application that signs people in through this
// tenant, or a machine that proves itself with a secret.
type OAuthClient struct {
	ID                 string
	ClientID           string
	Name               string
	Description        string
	Kind               string
	SecretHash         []byte
	MetadataURL        string
	RedirectURIs       []string
	AllowedScopes      []string
	GrantTypes         []string
	ServicePrincipalID string
	CreatedAt          time.Time
	DisabledAt         *time.Time
}

type AuthorizationCode struct {
	ID            string
	ClientID      string
	PrincipalID   string
	RedirectURI   string
	Scopes        []string
	CodeChallenge string
	Resource      string
	Nonce         string
	ExpiresAt     time.Time
	UsedAt        *time.Time
}

type Consent struct {
	ClientID   string
	ClientName string
	ClientKey  string
	Scopes     []string
	GrantedAt  time.Time
	RevokedAt  *time.Time
}

type DeviceCode struct {
	ID           string
	ClientID     string
	UserCode     string
	PrincipalID  string
	Scopes       []string
	Status       string
	ExpiresAt    time.Time
	LastPolledAt *time.Time
}

// Passkey is a WebAuthn credential (SIGN-3).
type Passkey struct {
	ID             string
	PrincipalID    string
	CredentialID   []byte
	PublicKey      []byte
	SignCount      int64
	Transports     []string
	AAGUID         []byte
	BackupEligible bool
	BackedUp       bool
	Name           string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// OAuthProvider is a social sign-in provider a tenant has set up (REG-5).
type OAuthProvider struct {
	ID              string
	Provider        string
	ClientID        string
	SecretEncrypted []byte
	DataKeyID       string
	Issuer          string
	Scopes          []string
	Enabled         bool
	CreatedAt       time.Time
}

// ExternalIdentity links a person to an account at another system.
type ExternalIdentity struct {
	ID            string
	PrincipalID   string
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
	LastSignInAt  *time.Time
}

// Machine is a service account or an agent, as listed.
type Machine struct {
	ID          string
	Kind        string
	Name        string
	Purpose     string
	OwnerID     string
	Status      string
	CreatedAt   time.Time
	SuspendedAt *time.Time
}

type APIKey struct {
	ID          string
	PrincipalID string
	Name        string
	PublicID    string
	SecretHash  []byte
	Scopes      []string
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	LastUsedAt  *time.Time
	CreatedBy   string
	CreatedAt   time.Time
}

type Delegation struct {
	ID         string
	AgentID    string
	UserID     string
	Scopes     []string
	ResourceID string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

type Approval struct {
	ID         string
	AgentID    string
	UserID     string
	Permission string
	ResourceID string
	Digest     []byte
	Details    map[string]any
	Status     string
	ExpiresAt  time.Time
	DecidedAt  *time.Time
	UsedAt     *time.Time
	CreatedAt  time.Time
}

// SSOConnection joins an organization to its company identity provider.
type SSOConnection struct {
	ID                    string
	OrganizationID        string
	Name                  string
	Protocol              string
	Status                string
	Issuer                string
	ClientID              string
	ClientSecretEncrypted []byte
	DataKeyID             string
	SAMLEntityID          string
	SAMLSSOURL            string
	SAMLCertificate       string
	TrustIdPSecondFactor  bool
	DefaultRoleID         string
	LastTest              map[string]any
	CreatedAt             time.Time
	ActivatedAt           *time.Time
}

type GroupMapping struct {
	ExternalGroup string
	RoleID        string
	RoleName      string
	ResourceID    string
}

type VerifiedDomain struct {
	ID             string
	OrganizationID string
	Domain         string
	TXTValue       string
	VerifiedAt     *time.Time
	LastCheckedAt  *time.Time
	CreatedAt      time.Time
}

type SCIMDirectory struct {
	ID             string
	OrganizationID string
	DefaultRoleID  string
	CreatedAt      time.Time
	LastRequestAt  *time.Time
	DisabledAt     *time.Time
}

// OrgPolicies are the rules an organization adds on top of the tenant's.
type OrgPolicies struct {
	MFARequired           bool
	SessionMaxSeconds     int
	AllowedAuthMethods    []string
	IPAllowlist           []string
	EnforceSSO            bool
	BreakGlassPrincipalID string
}

// AuditExportEntry is one audit line as exported.
type AuditExportEntry struct {
	Seq            int64
	OccurredAt     time.Time
	OrganizationID string
	ActorID        string
	Action         string
	TargetType     string
	TargetID       string
	Result         string
	ReasonCode     string
	Data           map[string]any
	Hash           []byte
}

// AuditEndpoint is an audit export endpoint with its cursor.
type AuditEndpoint struct {
	ID              string
	URL             string
	OrganizationID  string
	SecretEncrypted []byte
	DataKeyID       string
	TimeoutMs       int
	Cursor          int64
}

// DirectoryUser is a person as a company directory sees them.
type DirectoryUser struct {
	PrincipalID string
	ExternalID  string
	Email       string
	Name        string
	Active      bool
	CreatedAt   time.Time
}

// ---------------------------------------------------------------------
// Moving a tenant (HOST-6) and importing users (SET-4 step 6)
// ---------------------------------------------------------------------

// Archive is a whole tenant as it moves between homes. Sessions and API
// keys are never in it.
type Archive struct {
	Format        string                `json:"format"`
	ExportedAt    time.Time             `json:"exported_at"`
	TenantSlug    string                `json:"tenant_slug"`
	Kind          string                `json:"kind"`
	Settings      ArchiveSettings       `json:"settings"`
	Permissions   []ArchivePermission   `json:"permissions"`
	Roles         []ArchiveRole         `json:"roles"`
	Resources     []ArchiveResource     `json:"resources"`
	Organizations []ArchiveOrganization `json:"organizations"`
	Principals    []ArchivePrincipal    `json:"principals"`
	Groups        []ArchiveGroup        `json:"groups"`
	Grants        []ArchiveGrant        `json:"grants"`
	// AuditHead is the last hash of the old chain. The new home starts
	// its chain from it.
	AuditSeq  int64  `json:"audit_seq"`
	AuditHead string `json:"audit_head"`
}

type ArchiveSettings struct {
	SignupPolicy           string   `json:"signup_policy"`
	SignupDomains          []string `json:"signup_domains"`
	OrgCreationPolicy      string   `json:"org_creation_policy"`
	MFAPolicy              string   `json:"mfa_policy"`
	DefaultRole            string   `json:"default_role"`
	SessionIdleSeconds     int      `json:"session_idle_seconds"`
	SessionAbsoluteSeconds int      `json:"session_absolute_seconds"`
}

// CatalogPermission and CatalogRole are what GET /v1/permissions and
// GET /v1/roles list.
type CatalogPermission struct {
	Name          string
	Description   string
	Source        string
	StepUpSeconds int
	NeedsApproval bool
}

type CatalogRole struct {
	ID          string
	Name        string
	Description string
	Source      string
	Patterns    []string
}

type ArchivePermission struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Source        string `json:"source"`
	StepUpSeconds int    `json:"step_up_seconds"`
	NeedsApproval bool   `json:"needs_approval"`
}

type ArchiveRole struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Source      string   `json:"source"`
	Patterns    []string `json:"patterns"`
}

type ArchiveResource struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	ParentType  string `json:"parent_type"`
	ParentID    string `json:"parent_id"`
	DisplayName string `json:"display_name"`
}

type ArchiveOrganization struct {
	ResourceID string      `json:"resource_id"` // the organization node's external id
	Slug       string      `json:"slug"`
	Name       string      `json:"name"`
	Policies   OrgPolicies `json:"policies"`
}

type ArchivePrincipal struct {
	OldID         string           `json:"id"`
	Kind          string           `json:"kind"`
	Status        string           `json:"status"`
	DisplayName   string           `json:"display_name"`
	Purpose       string           `json:"purpose"`
	OwnerOldID    string           `json:"owner_id"`
	Email         string           `json:"email"`
	Name          string           `json:"name"`
	EmailVerified bool             `json:"email_verified"`
	PasswordHash  string           `json:"password_hash"`
	TOTPSecret    []byte           `json:"totp_secret,omitempty"`
	TOTPEncrypted []byte           `json:"-"`
	TOTPKeyID     string           `json:"-"`
	RecoveryCodes [][]byte         `json:"recovery_code_hashes"`
	Passkeys      []ArchivePasskey `json:"passkeys"`
}

type ArchivePasskey struct {
	CredentialID   []byte   `json:"credential_id"`
	PublicKey      []byte   `json:"public_key"`
	SignCount      int64    `json:"sign_count"`
	Transports     []string `json:"transports"`
	AAGUID         []byte   `json:"aaguid"`
	BackupEligible bool     `json:"backup_eligible"`
	BackedUp       bool     `json:"backed_up"`
	Name           string   `json:"name"`
}

type ArchiveGroup struct {
	OldID        string   `json:"id"`
	Name         string   `json:"name"`
	Organization string   `json:"organization_resource_id"`
	Members      []string `json:"members"`
}

type ArchiveGrant struct {
	PrincipalOldID string     `json:"principal_id,omitempty"`
	GroupOldID     string     `json:"group_id,omitempty"`
	Role           string     `json:"role"`
	ResourceType   string     `json:"resource_type"`
	ResourceID     string     `json:"resource_id"`
	Effect         string     `json:"effect"`
	Condition      string     `json:"condition,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Source         string     `json:"source"`
	Reason         string     `json:"reason,omitempty"`
}

// AccessReview is a periodic check of who can do what (ADM-6).
type AccessReview struct {
	ID             string
	OrganizationID string
	Status         string
	ReviewerID     string
	DueAt          *time.Time
	CompletedAt    *time.Time
	CreatedAt      time.Time
}

type AccessReviewItem struct {
	ID           string
	GrantID      string
	Decision     string
	DecidedAt    *time.Time
	PrincipalID  string
	GroupID      string
	Email        string
	Role         string
	ResourceType string
	ResourceID   string
	Effect       string
	// Gone is true when the grant no longer exists.
	Gone bool
}
