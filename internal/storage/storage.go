// Package storage declares what the module layer needs from the database.
//
// Every method takes the transaction it runs in. The module layer opens
// that transaction through platform/postgres, which scopes it to one
// tenant. A repository therefore never decides which tenant it reads:
// row-level security already has.
package storage

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant/model"
)

type TenantRepository interface {
	// ResolveKey finds the tenant a presented key belongs to. It returns
	// nil when the key is unknown, revoked or expired.
	ResolveKey(ctx context.Context, tx pgx.Tx, publicID string) (*model.ResolvedKey, error)
	GetTenant(ctx context.Context, tx pgx.Tx, tenantID string) (*model.Tenant, error)
	// ResolveSlug finds a tenant by its slug. It returns "" when there is none.
	ResolveSlug(ctx context.Context, tx pgx.Tx, slug string) (tenantID, status string, err error)
	IsAllowedOrigin(ctx context.Context, tx pgx.Tx, tenantID, origin string) (bool, error)

	CreateTenant(ctx context.Context, tx pgx.Tx, t model.NewTenant) (string, error)
	CreateResourceType(ctx context.Context, tx pgx.Tx, tenantID, name, source string) error
	// CreateRootResource makes the top of the tenant's resource tree and
	// records it on the tenant.
	CreateRootResource(ctx context.Context, tx pgx.Tx, tenantID string) (string, error)
	// CreateOwnerRole makes the one role AOS ships: Owner, holding "*".
	CreateOwnerRole(ctx context.Context, tx pgx.Tx, tenantID string) (string, error)
	// CreateSystemPermissions registers AOS's own permissions in the tenant.
	CreateSystemPermissions(ctx context.Context, tx pgx.Tx, tenantID string, permissions map[string]string) error
	CreateDataKey(ctx context.Context, tx pgx.Tx, tenantID string, wrapped []byte, masterKeyRef string) (string, error)
	CreateSigningKey(ctx context.Context, tx pgx.Tx, tenantID string, key model.SigningKey) error
	CreateTenantKey(ctx context.Context, tx pgx.Tx, tenantID, kind, publicID string, secretHash []byte) error
	AddAllowedOrigin(ctx context.Context, tx pgx.Tx, tenantID, origin string) error
	// ListTenantKeys returns every key, live and revoked. Never a secret.
	ListTenantKeys(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.TenantKey, error)
	// RevokeTenantKey returns false when there is no such live key.
	RevokeTenantKey(ctx context.Context, tx pgx.Tx, tenantID, keyID string, at time.Time) (bool, error)
	ListAllowedOrigins(ctx context.Context, tx pgx.Tx, tenantID string) ([]string, error)
	RemoveAllowedOrigin(ctx context.Context, tx pgx.Tx, tenantID, origin string) error
	UpdateTenantSettings(ctx context.Context, tx pgx.Tx, tenantID string, s model.TenantSettings) error
	// SetTenantStatus is the platform's to call.
	SetTenantStatus(ctx context.Context, tx pgx.Tx, tenantID, status string) error

	GetActiveDataKey(ctx context.Context, tx pgx.Tx, tenantID string) (*model.DataKey, error)
	GetDataKey(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.DataKey, error)
	GetActiveSigningKey(ctx context.Context, tx pgx.Tx, tenantID string) (*model.SigningKey, error)
	// ListSigningKeys returns every key a token may still be signed with.
	ListSigningKeys(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.SigningKey, error)
}

type AuthRepository interface {
	// FindUserByEmail returns nil when no account has that address.
	FindUserByEmail(ctx context.Context, tx pgx.Tx, tenantID, email string) (*model.UserAuth, error)
	GetUser(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (*model.User, error)
	CreateUser(ctx context.Context, tx pgx.Tx, tenantID, email, name string) (string, error)
	// CountUsers counts the accounts that are not deleted.
	CountUsers(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error)
	GetPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (*model.PrincipalRow, error)
	// CreateGuest makes a principal with no account (REG-8).
	CreateGuest(ctx context.Context, tx pgx.Tx, tenantID, name string) (string, error)
	// AttachAccount gives a guest an email address, turning it into a user.
	AttachAccount(ctx context.Context, tx pgx.Tx, tenantID, principalID, email, name string) error

	// Tokens that are guessed, such as sign-in codes, are found by where
	// they were sent and count their wrong attempts.
	LockTokenByTarget(ctx context.Context, tx pgx.Tx, tenantID, purpose, target string) (*model.Token, error)
	BumpTokenAttempts(ctx context.Context, tx pgx.Tx, tenantID, tokenID string) (int, error)

	// Challenges (pending sign-ins, passkey ceremonies).
	CreateChallenge(ctx context.Context, tx pgx.Tx, tenantID string, c model.NewChallenge) (string, error)
	LockChallengeByToken(ctx context.Context, tx pgx.Tx, tenantID, kind string, tokenHash []byte) (*model.Challenge, error)
	LockChallenge(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Challenge, error)
	BumpChallengeAttempts(ctx context.Context, tx pgx.Tx, tenantID, id string) (int, error)
	ConsumeChallenge(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error

	// Second factors.
	GetTOTP(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (*model.TOTPFactor, error)
	// CreateTOTP replaces any unconfirmed factor. A confirmed one stays.
	CreateTOTP(ctx context.Context, tx pgx.Tx, tenantID, principalID string, secretEncrypted []byte, dataKeyID string) (string, error)
	ConfirmTOTP(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	SetTOTPLastStep(ctx context.Context, tx pgx.Tx, tenantID, id string, step int64) error
	DeleteTOTP(ctx context.Context, tx pgx.Tx, tenantID, principalID string) error
	ReplaceRecoveryCodes(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hashes [][]byte) error
	// UseRecoveryCode returns false when no unused code matches.
	UseRecoveryCode(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hash []byte, at time.Time) (bool, error)
	CountRecoveryCodes(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int, error)
	CountPasskeys(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int, error)
	ListPasskeys(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.Passkey, error)
	CreatePasskey(ctx context.Context, tx pgx.Tx, tenantID string, p model.Passkey) (string, error)
	// FindPasskey finds a credential by its id, whoever owns it.
	FindPasskey(ctx context.Context, tx pgx.Tx, tenantID string, credentialID []byte) (*model.Passkey, error)
	UsePasskey(ctx context.Context, tx pgx.Tx, tenantID, id string, signCount int64, backedUp bool, at time.Time) error
	DeletePasskey(ctx context.Context, tx pgx.Tx, tenantID, principalID, id string) (bool, error)
	// SetSecondFactorAt records a second factor on a session.
	SetSecondFactorAt(ctx context.Context, tx pgx.Tx, tenantID, sessionID, method string, at time.Time) error

	// Social sign-in (REG-5, SIGN-5).
	UpsertOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID string, p model.OAuthProvider) (string, error)
	GetOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID, provider string) (*model.OAuthProvider, error)
	ListOAuthProviders(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.OAuthProvider, error)
	DeleteOAuthProvider(ctx context.Context, tx pgx.Tx, tenantID, provider string) (bool, error)
	FindExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID, provider, subject string) (*model.ExternalIdentity, error)
	CreateExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID string, i model.ExternalIdentity, profile map[string]any) (string, error)
	TouchExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	ListExternalIdentities(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.ExternalIdentity, error)
	DeleteExternalIdentity(ctx context.Context, tx pgx.Tx, tenantID, principalID, provider string) (bool, error)

	// Token sessions (SIGN-8).
	CreateTokenFamily(ctx context.Context, tx pgx.Tx, tenantID, principalID, sessionID string) (string, error)
	CreateRefreshToken(ctx context.Context, tx pgx.Tx, tenantID, familyID string, hash []byte, expires time.Time) (string, error)
	LockRefreshToken(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte) (*model.RefreshToken, error)
	MarkRefreshTokenUsed(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	RevokeTokenFamily(ctx context.Context, tx pgx.Tx, tenantID, familyID, reason string, at time.Time) error
	// RevokeTokenFamiliesOf ends every family of a session.
	RevokeTokenFamiliesOf(ctx context.Context, tx pgx.Tx, tenantID, sessionID, reason string, at time.Time) error

	// Devices (SIGN-11).
	FindDevice(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hash []byte) (*model.Device, error)
	CreateDevice(ctx context.Context, tx pgx.Tx, tenantID, principalID string, hash []byte, label string, at time.Time) (string, error)
	TouchDevice(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	CountDevices(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int, error)
	MarkEmailVerified(ctx context.Context, tx pgx.Tx, tenantID, principalID string, at time.Time) error

	CreateToken(ctx context.Context, tx pgx.Tx, tenantID string, t model.NewToken) (string, error)
	// LockToken finds a token by its hash and locks the row, so two
	// requests cannot both use it. It returns nil when there is none.
	LockToken(ctx context.Context, tx pgx.Tx, tenantID, purpose string, hash []byte) (*model.Token, error)
	MarkTokenUsed(ctx context.Context, tx pgx.Tx, tenantID, tokenID string, at time.Time) error
	// VoidTokens marks every unused token of one purpose as used.
	VoidTokens(ctx context.Context, tx pgx.Tx, tenantID, principalID, purpose string, at time.Time) error

	// AddPendingPassword stores a password that waits for its own
	// verification token (user-flow REG-3).
	AddPendingPassword(ctx context.Context, tx pgx.Tx, tenantID, principalID, hash, tokenID string) error
	// ActivatePendingPassword makes the password tied to tokenID the
	// account's password and discards every other one.
	ActivatePendingPassword(ctx context.Context, tx pgx.Tx, tenantID, principalID, tokenID string) error
	// SetPassword replaces the account's password.
	SetPassword(ctx context.Context, tx pgx.Tx, tenantID, principalID, hash string) error

	CreateSession(ctx context.Context, tx pgx.Tx, tenantID string, s model.NewSession) (string, error)
	// FindSession returns nil when there is no live session with that id.
	FindSession(ctx context.Context, tx pgx.Tx, tenantID string, idHash []byte) (*model.Session, error)
	TouchSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, lastSeen, idleExpires time.Time) error
	RevokeSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID, reason string, at time.Time) (bool, error)
	RevokeAllSessions(ctx context.Context, tx pgx.Tx, tenantID, principalID, reason string, at time.Time) (int64, error)
	// RevokeOtherSessions ends every session of a principal except one.
	RevokeOtherSessions(ctx context.Context, tx pgx.Tx, tenantID, principalID, keepSessionID, reason string, at time.Time) (int64, error)

	// HitRateLimit adds one to a counter and returns its new state. The
	// counter starts again once its window has passed.
	HitRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte, now time.Time, window time.Duration) (*model.RateLimit, error)
	GetRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte) (*model.RateLimit, error)
	LockRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte, until time.Time) error
	ResetRateLimit(ctx context.Context, tx pgx.Tx, tenantID, bucket string, keyHash []byte) error

	// GrantDefaultRole gives a new user the tenant's default role on the
	// root, unless they already hold it.
	GrantDefaultRole(ctx context.Context, tx pgx.Tx, tenantID, principalID, roleID, resourceID string) error

	// ListSessions returns a person's live sessions, newest first.
	ListSessions(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.SessionInfo, error)
	// FindSessionByID returns nil when there is no live session with that id.
	FindSessionByID(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (*model.Session, error)
	// SetActiveResource records the organization a session is working in.
	SetActiveResource(ctx context.Context, tx pgx.Tx, tenantID, sessionID, resourceID string) error
	// ClearActiveResource unsets it on every session that pointed at a resource.
	ClearActiveResource(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) error
	// CapSession shortens a session's absolute expiry.
	CapSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, absolute time.Time) error
	// ClearActiveResourceFor unsets it on one principal's sessions.
	ClearActiveResourceFor(ctx context.Context, tx pgx.Tx, tenantID, principalID, resourceID string) error
	UpdateEmail(ctx context.Context, tx pgx.Tx, tenantID, principalID, email string, at time.Time) error
	SetPrincipalStatus(ctx context.Context, tx pgx.Tx, tenantID, principalID, status, reason string, at time.Time) error
	// MarkPrincipalDeleted stops the account and schedules its erasure.
	MarkPrincipalDeleted(ctx context.Context, tx pgx.Tx, tenantID, principalID string, at, purgeAfter time.Time) error
	// ListUsers pages through users, oldest first, from the cursor given.
	ListUsers(ctx context.Context, tx pgx.Tx, tenantID string, afterCreated time.Time, afterID string, limit int) ([]model.User, error)
}

type IAMRepository interface {
	// UpsertPermission returns where the permission was first created,
	// which a later write does not change.
	UpsertPermission(ctx context.Context, tx pgx.Tx, tenantID, name, description, source string) (string, error)
	// SetPermissionStepUp marks a permission as needing a fresh second
	// factor no older than seconds. Zero clears it.
	SetPermissionStepUp(ctx context.Context, tx pgx.Tx, tenantID, name string, seconds int) error
	// PermissionStepUp returns the seconds, or 0 when none is needed.
	PermissionStepUp(ctx context.Context, tx pgx.Tx, tenantID, name string) (int, error)
	SetPermissionNeedsApproval(ctx context.Context, tx pgx.Tx, tenantID, name string, needs bool) error
	PermissionNeedsApproval(ctx context.Context, tx pgx.Tx, tenantID, name string) (bool, error)
	// GetPrincipalKind returns "" for an unknown principal.
	GetPrincipalKind(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (string, error)
	// SessionSecondFactorAt returns when a live session last had a second
	// factor; found is false for an unknown or ended session.
	SessionSecondFactorAt(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (at *time.Time, found bool, err error)
	// GetRoleByName returns empty strings when there is no such role.
	GetRoleByName(ctx context.Context, tx pgx.Tx, tenantID, name string) (id, source string, err error)
	UpsertRole(ctx context.Context, tx pgx.Tx, tenantID, name, description, source string) (id, storedSource string, err error)
	ReplaceRolePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, patterns []string) error
	// ListPermissions and ListRoles return the catalog: live permissions,
	// and the tenant-wide roles with what each holds.
	ListPermissions(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.CatalogPermission, error)
	ListRoles(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.CatalogRole, error)

	EnsureResourceType(ctx context.Context, tx pgx.Tx, tenantID, name string) error
	// FindResource returns empty strings when there is no such resource.
	FindResource(ctx context.Context, tx pgx.Tx, tenantID string, ref model.ResourceRef) (id, parentID string, err error)
	CreateResource(ctx context.Context, tx pgx.Tx, tenantID string, ref model.ResourceRef, parentID, displayName string) (string, error)

	// GetPrincipalStatus returns "" when there is no such principal.
	GetPrincipalStatus(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (string, error)
	CreateGrant(ctx context.Context, tx pgx.Tx, tenantID string, g model.NewGrant) (string, error)
	// DeleteGrant returns the principal the grant belonged to, or "" when
	// there was no such grant.
	DeleteGrant(ctx context.Context, tx pgx.Tx, tenantID, grantID string) (string, error)

	// MatchingGrants returns every live grant that covers the permission
	// for this principal, on the resource or on anything above it.
	// excludeGrantID, when set, leaves one grant out, to see what would
	// change without it.
	MatchingGrants(ctx context.Context, tx pgx.Tx, tenantID, principalID, resourceID, permission, excludeGrantID string, now time.Time) ([]model.MatchedGrant, error)
	// Ancestors returns the resource and everything above it, nearest first.
	Ancestors(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) ([]model.ResourceNode, error)
	// ActorPatterns returns the permission patterns an actor holds on a
	// resource through allow grants, for the rule that nobody can hand
	// out more than they hold.
	ActorPatterns(ctx context.Context, tx pgx.Tx, tenantID, principalID, resourceID string, now time.Time) ([]string, error)
	// RolePatterns returns what a role holds.
	RolePatterns(ctx context.Context, tx pgx.Tx, tenantID, roleID string) ([]string, error)
	// AllowedResources returns the external ids of the resources of one
	// type on which the principal holds the permission: those with an
	// allow and no deny, and apart from them those allowed only under a
	// condition.
	AllowedResources(ctx context.Context, tx pgx.Tx, tenantID, principalID, permission, resourceType string, now time.Time, limit int) (allowed, conditional []string, err error)
	// CandidatePrincipals returns the principals that hold an allow grant
	// covering the permission on the resource or anything above it.
	CandidatePrincipals(ctx context.Context, tx pgx.Tx, tenantID, resourceID, permission string, now time.Time) ([]model.Principal, error)
	// GetGrant returns a grant with the principals it covers: the one it
	// was made to, or the members of its group. It returns nil when there
	// is no such grant.
	GetGrant(ctx context.Context, tx pgx.Tx, tenantID, grantID string) (*model.GrantInfo, []string, error)
	// IsUnder reports whether a resource is the other, or beneath it.
	IsUnder(ctx context.Context, tx pgx.Tx, tenantID, resourceID, ancestorID string) (bool, error)

	// Groups.
	UpsertGroup(ctx context.Context, tx pgx.Tx, tenantID, name, organizationID string) (string, error)
	ListGroups(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.Group, error)
	DeleteGroup(ctx context.Context, tx pgx.Tx, tenantID, groupID string) (bool, error)
	AddGroupMember(ctx context.Context, tx pgx.Tx, tenantID, groupID, principalID string) error
	RemoveGroupMember(ctx context.Context, tx pgx.Tx, tenantID, groupID, principalID string) (bool, error)
	GroupExists(ctx context.Context, tx pgx.Tx, tenantID, groupID string) (bool, error)
	LogDecision(ctx context.Context, tx pgx.Tx, tenantID string, d model.Decision) error
	// TouchPermission records that a check asked about a permission.
	TouchPermission(ctx context.Context, tx pgx.Tx, tenantID, name string, now time.Time) error
	// ListGrantsForPrincipal returns every grant a principal holds directly.
	ListGrantsForPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.GrantInfo, error)
}

type OrganizationRepository interface {
	CreateOrganization(ctx context.Context, tx pgx.Tx, tenantID, resourceID, slug, name, createdBy string) error
	GetOrganization(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) (*model.Organization, error)
	SlugTaken(ctx context.Context, tx pgx.Tx, tenantID, slug string) (bool, error)
	CountOrganizations(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error)
	GetPolicies(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) (*model.OrgPolicies, error)
	SetPolicies(ctx context.Context, tx pgx.Tx, tenantID, resourceID string, p model.OrgPolicies) error
	// ListOrganizationsFor returns the organizations a principal belongs
	// to: those where it holds a grant on the organization or beneath it.
	ListOrganizationsFor(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.Organization, error)
	ListOrganizations(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.Organization, error)
	// IsMember reports whether a principal holds any grant in the organization.
	IsMember(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID string) (bool, error)
	ListMembers(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) ([]model.Member, error)
	// CountOwners returns how many principals hold the Owner role on the organization itself.
	CountOwners(ctx context.Context, tx pgx.Tx, tenantID, resourceID, ownerRoleID string) (int, error)
	// HoldsRoleOn reports whether the principal holds the role on the resource itself.
	HoldsRoleOn(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID, roleID string) (bool, error)
	// ReplaceRoleOn swaps the principal's role grants on the resource itself.
	ReplaceRoleOn(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID, roleID, createdBy string) error
	// RemoveMember deletes the principal's grants in the organization and
	// beneath it, and takes it out of the organization's groups.
	RemoveMember(ctx context.Context, tx pgx.Tx, tenantID, resourceID, principalID string) (int64, error)
	// DeleteOrganization marks the organization and its subtree deleted
	// and removes every grant inside it.
	DeleteOrganization(ctx context.Context, tx pgx.Tx, tenantID, resourceID string, at, purgeAfter time.Time) error

	CreateInvitation(ctx context.Context, tx pgx.Tx, tenantID string, inv model.NewInvitation) (string, error)
	// LockInvitationByToken finds an invitation by its token's hash and
	// locks it. It returns nil when there is none.
	LockInvitationByToken(ctx context.Context, tx pgx.Tx, tenantID string, tokenHash []byte) (*model.Invitation, error)
	GetInvitation(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Invitation, error)
	ListInvitations(ctx context.Context, tx pgx.Tx, tenantID, resourceID string) ([]model.Invitation, error)
	MarkInvitationAccepted(ctx context.Context, tx pgx.Tx, tenantID, id, principalID string, at time.Time) error
	MarkInvitationDeclined(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	MarkInvitationRevoked(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	// RevokeInvitationsFor withdraws every pending invitation of an address in an organization.
	RevokeInvitationsFor(ctx context.Context, tx pgx.Tx, tenantID, resourceID, email string, at time.Time) error
}

type AuditRepository interface {
	// Append adds an entry in the same transaction as the change it records.
	Append(ctx context.Context, tx pgx.Tx, tenantID string, e model.AuditEntry) error
	// Verify recomputes the whole hash chain and returns the entries checked.
	Verify(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error)
	// ListForPrincipal returns the entries where a principal acted or was
	// the target, newest first.
	ListForPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID string, limit int) ([]model.AuditView, error)
	// ListSince returns an organization's entries after a sequence number.
	ListSince(ctx context.Context, tx pgx.Tx, tenantID, organizationID string, afterSeq int64, limit int) ([]model.AuditExportEntry, error)
}

type NotificationRepository interface {
	CreateMessage(ctx context.Context, tx pgx.Tx, tenantID string, m model.Message, body []byte, dataKeyID string) error
	// DueMessages lists messages waiting to be sent, across tenants, as
	// ids only. It runs in the resolver scope.
	DueMessages(ctx context.Context, tx pgx.Tx, limit int) ([]model.DueMessage, error)
	// LockMessage reads one pending message and locks it. It returns nil
	// when another worker has it or it is no longer pending.
	LockMessage(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.StoredMessage, error)
	// MarkMessageSent also wipes the body, which may hold a raw token.
	MarkMessageSent(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	MarkMessageRetry(ctx context.Context, tx pgx.Tx, tenantID, id string, nextAttempt time.Time) error
	MarkMessageFailed(ctx context.Context, tx pgx.Tx, tenantID, id string) error
	// CreateEvent writes to the outbox in the same transaction as the change
	// and returns the event's id.
	CreateEvent(ctx context.Context, tx pgx.Tx, tenantID, eventType string, payload map[string]any) (string, error)

	CreateWebhookEndpoint(ctx context.Context, tx pgx.Tx, tenantID string, e model.WebhookEndpoint) (string, error)
	// ListWebhookEndpoints returns the enabled endpoints of one kind, or of
	// every kind when kind is "".
	ListWebhookEndpoints(ctx context.Context, tx pgx.Tx, tenantID, kind string) ([]model.WebhookEndpoint, error)
	DeleteWebhookEndpoint(ctx context.Context, tx pgx.Tx, tenantID, id string) (bool, error)
	// CreateDeliveries queues one delivery of an event per endpoint.
	CreateDeliveries(ctx context.Context, tx pgx.Tx, tenantID, eventID string, endpointIDs []string) error
	// DueDeliveries lists deliveries waiting to be sent, across tenants, as
	// ids only. It runs in the resolver scope.
	DueDeliveries(ctx context.Context, tx pgx.Tx, limit int) ([]model.DueDelivery, error)
	// LockDelivery reads one pending delivery with its event and endpoint
	// and locks it. It returns nil when another worker has it.
	LockDelivery(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.StoredDelivery, error)
	MarkDeliveryDelivered(ctx context.Context, tx pgx.Tx, tenantID, id string, statusCode int, at time.Time) error
	MarkDeliveryRetry(ctx context.Context, tx pgx.Tx, tenantID, id string, statusCode int, errMsg string, nextAttempt time.Time) error
	MarkDeliveryFailed(ctx context.Context, tx pgx.Tx, tenantID, id string, statusCode int, errMsg string) error
	RecordEndpointResult(ctx context.Context, tx pgx.Tx, tenantID, endpointID string, ok bool, errMsg string, at time.Time) error
	// Audit export (ENT-8).
	AuditExportEndpoints(ctx context.Context, tx pgx.Tx) ([]struct{ TenantID, EndpointID string }, error)
	GetAuditEndpoint(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.AuditEndpoint, error)
	SetAuditCursor(ctx context.Context, tx pgx.Tx, tenantID, id string, cursor int64) error
}

// MachineRepository holds service accounts, agents, API keys, delegations
// and approvals.
type MachineRepository interface {
	CreateMachine(ctx context.Context, tx pgx.Tx, tenantID, kind, name, purpose, ownerID string) (string, error)
	GetMachine(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Machine, error)
	ListMachines(ctx context.Context, tx pgx.Tx, tenantID, kind string) ([]model.Machine, error)
	SetMachineStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status, reason string, at time.Time) error

	CreateAPIKey(ctx context.Context, tx pgx.Tx, tenantID string, k model.APIKey) (string, error)
	FindAPIKeyByPublicID(ctx context.Context, tx pgx.Tx, tenantID, publicID string) (*model.APIKey, error)
	ListAPIKeys(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.APIKey, error)
	RevokeAPIKey(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) (principalID string, err error)
	RevokeAPIKeysOf(ctx context.Context, tx pgx.Tx, tenantID, principalID string, at time.Time) (int64, error)
	TouchAPIKey(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error

	CreateDelegation(ctx context.Context, tx pgx.Tx, tenantID string, d model.Delegation) (string, error)
	// LiveDelegations returns the delegations from a user to an agent that
	// cover a resource (the resource itself or one above it).
	LiveDelegations(ctx context.Context, tx pgx.Tx, tenantID, agentID, userID, resourceID string, now time.Time) ([]model.Delegation, error)
	ListDelegations(ctx context.Context, tx pgx.Tx, tenantID, userID, agentID string) ([]model.Delegation, error)
	RevokeDelegation(ctx context.Context, tx pgx.Tx, tenantID, id, userID string, at time.Time) (bool, error)
	RevokeDelegationsOf(ctx context.Context, tx pgx.Tx, tenantID, agentID string, at time.Time) (int64, error)

	CreateApproval(ctx context.Context, tx pgx.Tx, tenantID string, a model.Approval) (string, error)
	// FindPendingApproval finds an open request for the same action.
	FindPendingApproval(ctx context.Context, tx pgx.Tx, tenantID, agentID string, digest []byte, now time.Time) (*model.Approval, error)
	LockApproval(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.Approval, error)
	ListApprovals(ctx context.Context, tx pgx.Tx, tenantID, userID string, now time.Time) ([]model.Approval, error)
	SetApprovalStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string, at time.Time) error
	MarkApprovalUsed(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error

	// RevokeTokenFamiliesOfPrincipal ends every token family of a principal.
	RevokeTokenFamiliesOfPrincipal(ctx context.Context, tx pgx.Tx, tenantID, principalID, reason string, at time.Time) error
	DeleteGrantsOf(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (int64, error)
}

// OAuthRepository holds what the tenant keeps as an OAuth provider.
type OAuthRepository interface {
	UpsertClient(ctx context.Context, tx pgx.Tx, tenantID string, c model.OAuthClient) (string, error)
	GetClient(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.OAuthClient, error)
	GetClientByClientID(ctx context.Context, tx pgx.Tx, tenantID, clientID string) (*model.OAuthClient, error)
	ListClients(ctx context.Context, tx pgx.Tx, tenantID string) ([]model.OAuthClient, error)
	DisableClient(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) (bool, error)

	CreateCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte, c model.AuthorizationCode) (string, error)
	LockCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte) (*model.AuthorizationCode, error)
	MarkCodeUsed(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error

	UpsertConsent(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string, scopes []string, at time.Time) error
	GetConsent(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string) (*model.Consent, error)
	ListConsents(ctx context.Context, tx pgx.Tx, tenantID, principalID string) ([]model.Consent, error)
	RevokeConsent(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string, at time.Time) (bool, error)

	CreateDeviceCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte, d model.DeviceCode) (string, error)
	LockDeviceCode(ctx context.Context, tx pgx.Tx, tenantID string, hash []byte) (*model.DeviceCode, error)
	LockDeviceCodeByUserCode(ctx context.Context, tx pgx.Tx, tenantID, userCode string) (*model.DeviceCode, error)
	DecideDeviceCode(ctx context.Context, tx pgx.Tx, tenantID, id, principalID, status string) error
	TouchDeviceCode(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	SetDeviceCodeStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string) error

	// PublishableKey returns the tenant's oldest live publishable key.
	PublishableKey(ctx context.Context, tx pgx.Tx, tenantID string) (string, error)

	// Token families a client holds.
	CreateClientTokenFamily(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID string, scopes []string, audience string) (string, error)
	RevokeClientTokenFamilies(ctx context.Context, tx pgx.Tx, tenantID, principalID, clientID, reason string, at time.Time) error
}

// EnterpriseRepository holds SSO connections, group mappings, verified
// domains and directories.
type EnterpriseRepository interface {
	CreateConnection(ctx context.Context, tx pgx.Tx, tenantID string, c model.SSOConnection) (string, error)
	GetConnection(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.SSOConnection, error)
	ListConnections(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.SSOConnection, error)
	UpdateConnectionSettings(ctx context.Context, tx pgx.Tx, tenantID string, c model.SSOConnection) error
	SetConnectionStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string, at time.Time) error
	SetConnectionTest(ctx context.Context, tx pgx.Tx, tenantID, id string, result map[string]any) error
	SetConnectionDefaultRole(ctx context.Context, tx pgx.Tx, tenantID, id, roleID string, trustIdPFactor bool) error

	ReplaceGroupMappings(ctx context.Context, tx pgx.Tx, tenantID, connectionID string, mappings []model.GroupMapping) error
	ListGroupMappings(ctx context.Context, tx pgx.Tx, tenantID, connectionID string) ([]model.GroupMapping, error)

	CreateDomain(ctx context.Context, tx pgx.Tx, tenantID, organizationID, domain, txtValue string) (string, error)
	ListDomains(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.VerifiedDomain, error)
	GetDomain(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.VerifiedDomain, error)
	MarkDomainChecked(ctx context.Context, tx pgx.Tx, tenantID, id string, verified bool, at time.Time) error
	// ConnectionForDomain finds the active connection of the organization
	// that verified a domain, or nil.
	ConnectionForDomain(ctx context.Context, tx pgx.Tx, tenantID, domain string) (*model.SSOConnection, error)
	DeleteDomain(ctx context.Context, tx pgx.Tx, tenantID, id string) (bool, error)

	// Identities linked through a connection or a directory.
	FindConnectionIdentity(ctx context.Context, tx pgx.Tx, tenantID, connectionID, subject string) (principalID string, err error)
	LinkConnectionIdentity(ctx context.Context, tx pgx.Tx, tenantID, connectionID, principalID, subject, email string, profile map[string]any, at time.Time) error
	// ReplaceSSOGrants removes the grants a connection gave a person and
	// writes the new ones.
	ReplaceSSOGrants(ctx context.Context, tx pgx.Tx, tenantID, connectionID, principalID string, grants []model.NewGrant) error

	CreateDirectory(ctx context.Context, tx pgx.Tx, tenantID, organizationID string, tokenHash []byte, defaultRoleID string) (string, error)
	GetDirectory(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.SCIMDirectory, error)
	ListDirectories(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.SCIMDirectory, error)
	DisableDirectory(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	TouchDirectory(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error
	// ResolveDirectoryToken runs in the resolver scope.
	ResolveDirectoryToken(ctx context.Context, tx pgx.Tx, tokenHash []byte) (tenantID, directoryID, organizationID string, err error)
	// Directory users: the people a directory created or claimed.
	FindDirectoryUser(ctx context.Context, tx pgx.Tx, tenantID, directoryID, externalID string) (*model.DirectoryUser, error)
	FindDirectoryUserByPrincipal(ctx context.Context, tx pgx.Tx, tenantID, directoryID, principalID string) (*model.DirectoryUser, error)
	ListDirectoryUsers(ctx context.Context, tx pgx.Tx, tenantID, directoryID, emailFilter string) ([]model.DirectoryUser, error)
	LinkDirectoryUser(ctx context.Context, tx pgx.Tx, tenantID, directoryID, principalID, externalID, email string, at time.Time) error
	// Directory groups.
	FindDirectoryGroup(ctx context.Context, tx pgx.Tx, tenantID, directoryID, externalID string) (*model.Group, error)
	CreateDirectoryGroup(ctx context.Context, tx pgx.Tx, tenantID, directoryID, organizationID, externalID, name string) (string, error)
	RenameGroup(ctx context.Context, tx pgx.Tx, tenantID, groupID, name string) error
	ListDirectoryGroups(ctx context.Context, tx pgx.Tx, tenantID, directoryID string) ([]model.Group, error)
	ReplaceGroupMembers(ctx context.Context, tx pgx.Tx, tenantID, groupID string, principalIDs []string) error
	DeleteGroup(ctx context.Context, tx pgx.Tx, tenantID, groupID string) error
}

// TransferRepository reads a whole tenant for export and writes the parts
// the other repositories do not.
type TransferRepository interface {
	ReadArchive(ctx context.Context, tx pgx.Tx, tenantID string) (*model.Archive, error)
	CountUsers(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error)
	SetMachineFields(ctx context.Context, tx pgx.Tx, tenantID, principalID, purpose, ownerID string) error
	SetMFAPolicy(ctx context.Context, tx pgx.Tx, tenantID, policy string) error
}

// ReviewRepository holds access reviews (ADM-6).
type ReviewRepository interface {
	CreateReview(ctx context.Context, tx pgx.Tx, tenantID, organizationID, reviewerID string, due *time.Time) (string, error)
	// SnapshotGrants adds one item per grant on the organization or under it.
	SnapshotGrants(ctx context.Context, tx pgx.Tx, tenantID, reviewID, organizationID string) (int64, error)
	GetReview(ctx context.Context, tx pgx.Tx, tenantID, id string) (*model.AccessReview, error)
	ListReviews(ctx context.Context, tx pgx.Tx, tenantID, organizationID string) ([]model.AccessReview, error)
	ListItems(ctx context.Context, tx pgx.Tx, tenantID, reviewID string) ([]model.AccessReviewItem, error)
	LockItem(ctx context.Context, tx pgx.Tx, tenantID, reviewID, itemID string) (*model.AccessReviewItem, error)
	DecideItem(ctx context.Context, tx pgx.Tx, tenantID, itemID, decision string, at time.Time) error
	CountUndecided(ctx context.Context, tx pgx.Tx, tenantID, reviewID string) (int64, error)
	CompleteReview(ctx context.Context, tx pgx.Tx, tenantID, reviewID string, at time.Time) error
}
