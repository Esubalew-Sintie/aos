// Package auth is sign-up, sign-in, sessions and password reset.
//
// Three rules shape every function here (user-flow README):
//
//   - No account discovery. A route that takes an email answers the same
//     way, in the same time, whether or not the account exists.
//   - Limits come first. Rate limits and lockout apply before a password
//     or a token is looked at.
//   - One transaction. A change, its audit entry and its event are
//     written together or not at all.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/module"
	"github.com/flash-softeware/aos/internal/module/auth/core"
	"github.com/flash-softeware/aos/internal/storage"
	"github.com/flash-softeware/aos/platform/jwt"
	"github.com/flash-softeware/aos/platform/logger"
	"github.com/flash-softeware/aos/platform/oidc"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

type authModule struct {
	db      *postgres.DB
	repo    storage.AuthRepository
	iam     storage.IAMRepository
	tenants storage.TenantRepository
	// enterprise and orgs answer "must this address use the company's
	// provider?" and "what does the active organization require?".
	enterprise storage.EnterpriseRepository
	orgs       storage.OrganizationRepository
	audit      storage.AuditRepository
	notify     module.Notification
	keys       module.KeyRing
	breach     secret.BreachChecker
	params     secret.PasswordParams
	// dummyHash is verified against when there is no account, so that an
	// unknown email costs the same time as a wrong password.
	dummyHash string
	// meter counts what the tenant does and knows its limits. Nil in
	// the package modes, where there is no platform.
	meter module.UsageMeter
	// oidc talks to social sign-in providers.
	oidc *oidc.Client
	now  func() time.Time
	log  logger.Logger
}

// withinLimit refuses when the tenant is at a limit set by the platform.
func (m *authModule) withinLimit(ctx context.Context, tx pgx.Tx, tenantID, metric string, current func() (int64, error)) error {
	if m.meter == nil {
		return nil
	}
	limit, err := m.meter.Limit(ctx, tx, tenantID, metric)
	if err != nil {
		return err
	}
	if limit < 0 {
		return nil
	}
	n, err := current()
	if err != nil {
		return err
	}
	if n >= limit {
		return errors.LimitReached(metric)
	}
	return nil
}

func (m *authModule) count(ctx context.Context, tx pgx.Tx, tenantID, metric string) error {
	if m.meter == nil {
		return nil
	}
	return m.meter.Count(ctx, tx, tenantID, metric)
}

func NewAuthModule(db *postgres.DB, repo storage.AuthRepository, iam storage.IAMRepository, tenants storage.TenantRepository,
	enterprise storage.EnterpriseRepository, orgs storage.OrganizationRepository,
	audit storage.AuditRepository, notify module.Notification, keys module.KeyRing, breach secret.BreachChecker,
	params secret.PasswordParams, meter module.UsageMeter, oidcClient *oidc.Client, now func() time.Time, log logger.Logger) (module.Auth, error) {
	dummy, err := secret.HashPassword(secret.Token(16), params)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	return &authModule{
		db: db, repo: repo, iam: iam, tenants: tenants, enterprise: enterprise, orgs: orgs, audit: audit, notify: notify, keys: keys, breach: breach,
		params: params, dummyHash: dummy, meter: meter, oidc: oidcClient, now: now, log: log,
	}, nil
}

// ---------------------------------------------------------------------
// Sign-up and verification
// ---------------------------------------------------------------------

func (m *authModule) SignUp(ctx context.Context, t *model.Tenant, req request.SignUpRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	// The sign-up policy says nothing about any one account, so a closed
	// sign-up may say so.
	if t.Status == constant.TenantRestricted || t.SignupPolicy == constant.SignupInviteOnly {
		return errors.ErrSignupClosed
	}
	if t.SignupPolicy == constant.SignupDomains && !core.EmailInDomains(req.Email, t.SignupDomains) {
		return errors.ErrSignupClosed
	}
	if err := m.refusePwnedPassword(ctx, req.Password, "password"); err != nil {
		return err
	}
	// The application may refuse the sign-up, for example a disposable
	// address. It is asked before anything is written.
	if err := m.notify.Hook(ctx, t, constant.HookUserBeforeCreate, map[string]any{"email": req.Email, "name": req.Name}); err != nil {
		return err
	}

	// Hash before the transaction: it is slow on purpose. It is also done
	// whether or not the account exists, so both cases take the same time.
	hash, err := secret.HashPassword(req.Password, m.params)
	if err != nil {
		return fmt.Errorf("sign up: %w", err)
	}

	// Cap the emails one address can be sent. Over the cap, the answer
	// stays the same and nothing is sent.
	withinLimit, err := m.hit(ctx, t, constant.BucketEmail, req.Email, constant.EmailLimitPerHour, constant.EmailLimitWindow)
	if err != nil {
		return err
	}
	if !withinLimit {
		return nil
	}

	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		existing, err := m.repo.FindUserByEmail(ctx, tx, t.ID, req.Email)
		if err != nil {
			return err
		}

		switch {
		case existing == nil:
			if err := m.withinLimit(ctx, tx, t.ID, constant.MetricUsers, func() (int64, error) { return m.repo.CountUsers(ctx, tx, t.ID) }); err != nil {
				return err
			}
			principalID, err := m.repo.CreateUser(ctx, tx, t.ID, req.Email, req.Name)
			if err != nil {
				return err
			}
			if err := m.count(ctx, tx, t.ID, constant.MetricSignUps); err != nil {
				return err
			}
			if err := m.addPendingPassword(ctx, tx, t, principalID, req.Email, hash, now); err != nil {
				return err
			}
			if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "user.created", Result: model.AuditSuccess,
				ActorID: principalID, TargetType: "user", TargetID: principalID,
				RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			}); err != nil {
				return err
			}
			return m.notify.Emit(ctx, tx, t.ID, "user.created", map[string]any{"user_id": principalID})

		case existing.EmailVerified:
			// A real account. Create nothing, and tell its owner.
			if err := m.notify.Enqueue(ctx, tx, t, model.Message{
				Channel: constant.ChannelEmail, Recipient: req.Email, Template: constant.TemplateExistingAccount,
			}); err != nil {
				return err
			}
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "signup.existing_account", Result: model.AuditFailure,
				TargetType: "user", TargetID: existing.PrincipalID,
				RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})

		default:
			// An earlier sign-up that was never confirmed. This request
			// gets its own link and its own pending password. Whichever
			// link the mailbox owner confirms wins (user-flow REG-3).
			if err := m.addPendingPassword(ctx, tx, t, existing.PrincipalID, req.Email, hash, now); err != nil {
				return err
			}
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "signup.repeated", Result: model.AuditSuccess,
				TargetType: "user", TargetID: existing.PrincipalID,
				RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})
		}
	})
	if postgres.IsUniqueViolation(err) {
		// Two sign-ups for one new address at the same moment. The other
		// one created the account and sent the email.
		return nil
	}
	if err != nil {
		return fmt.Errorf("sign up: %w", err)
	}
	m.notify.Wake()
	return nil
}

// addPendingPassword stores a password that waits for its own
// verification token, and queues the email that carries the token.
func (m *authModule) addPendingPassword(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, email, hash string, now time.Time) error {
	raw := secret.Token(32)
	tokenID, err := m.repo.CreateToken(ctx, tx, t.ID, model.NewToken{
		Purpose: constant.TokenEmailVerification, PrincipalID: principalID, Target: email,
		Hash: secret.Hash(raw), ExpiresAt: now.Add(constant.EmailVerificationTTL),
	})
	if err != nil {
		return err
	}
	if err := m.repo.AddPendingPassword(ctx, tx, t.ID, principalID, hash, tokenID); err != nil {
		return err
	}
	// The raw token goes into the message and nowhere else.
	return m.notify.Enqueue(ctx, tx, t, model.Message{
		Channel: constant.ChannelEmail, Recipient: email, Template: constant.TemplateVerifyEmail,
		Data: map[string]string{"token": raw, "link": core.Link(t.AppURL, core.VerifyEmailPath, raw)},
	})
}

func (m *authModule) VerifyEmail(ctx context.Context, t *model.Tenant, req request.VerifyEmailRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}

	now := m.now()
	var out *response.AuthResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		// The row is locked, so two requests cannot both use one token.
		token, err := m.repo.LockToken(ctx, tx, t.ID, constant.TokenEmailVerification, secret.Hash(req.Token))
		if err != nil {
			return err
		}
		// Unknown, used and expired all read the same.
		if token == nil || token.UsedAt != nil || !now.Before(token.ExpiresAt) || token.PrincipalID == "" {
			return errors.ErrInvalidToken
		}

		if err := m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now); err != nil {
			return err
		}
		// Only the password that came with this link becomes the
		// account's password. The others are discarded.
		if err := m.repo.ActivatePendingPassword(ctx, tx, t.ID, token.PrincipalID, token.ID); err != nil {
			return err
		}
		if err := m.repo.VoidTokens(ctx, tx, t.ID, token.PrincipalID, constant.TokenEmailVerification, now); err != nil {
			return err
		}
		if err := m.repo.MarkEmailVerified(ctx, tx, t.ID, token.PrincipalID, now); err != nil {
			return err
		}
		if t.DefaultRoleID != "" && t.RootResourceID != "" {
			if err := m.repo.GrantDefaultRole(ctx, tx, t.ID, token.PrincipalID, t.DefaultRoleID, t.RootResourceID); err != nil {
				return err
			}
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.email_verified", Result: model.AuditSuccess,
			ActorID: token.PrincipalID, TargetType: "user", TargetID: token.PrincipalID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.email_verified", map[string]any{"user_id": token.PrincipalID}); err != nil {
			return err
		}

		// Confirming the link proves control of the mailbox, so the
		// browser that confirmed is signed in.
		out, err = m.startSession(ctx, tx, t, token.PrincipalID, "email_link", meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("verify email", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------

func (m *authModule) SignIn(ctx context.Context, t *model.Tenant, req request.SignInRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}

	now := m.now()
	accountKey := core.LimitKey(req.Email)
	var (
		user  *model.UserAuth
		limit *model.RateLimit
	)
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		if limit, err = m.repo.GetRateLimit(ctx, tx, t.ID, constant.BucketSignInAccount, accountKey); err != nil {
			return err
		}
		user, err = m.repo.FindUserByEmail(ctx, tx, t.ID, req.Email)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sign in: %w", err)
	}
	locked := limit.LockedUntil != nil && now.Before(*limit.LockedUntil)

	// Exactly one password check always runs: against the real hash, or
	// against a dummy when there is no account or no password. An unknown
	// email, a locked account and a wrong password therefore take the
	// same time and get the same answer.
	hash := m.dummyHash
	hasPassword := user != nil && user.PasswordHash != ""
	if hasPassword {
		hash = user.PasswordHash
	}
	matches, usedParams, verr := secret.VerifyPassword(req.Password, hash)
	if verr != nil {
		m.log.Error(ctx, "stored password hash could not be read", "error", verr.Error())
		matches = false
	}

	if locked || !hasPassword || !matches {
		reason := "wrong_password"
		switch {
		case locked:
			reason = "locked"
		case user == nil:
			reason = "unknown_account"
		case !hasPassword:
			reason = "no_password"
		}
		if err := m.recordFailedSignIn(ctx, t, req.Email, accountKey, user, reason, locked, meta, now); err != nil {
			return nil, err
		}
		return nil, errors.ErrInvalidCredentials
	}

	// The password is right. Only now may the answer depend on the account.
	if user.Status != constant.PrincipalActive {
		if err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "signin.failed", Result: model.AuditDenied, ReasonCode: "account_" + user.Status,
				ActorID: user.PrincipalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})
		}); err != nil {
			return nil, fmt.Errorf("sign in: %w", err)
		}
		return nil, errors.ErrAccountSuspended
	}

	// Replace a hash that was made with weaker settings than today's.
	var upgraded string
	if usedParams.Weaker(m.params) {
		if upgraded, err = secret.HashPassword(req.Password, m.params); err != nil {
			return nil, fmt.Errorf("sign in: %w", err)
		}
	}

	var out *response.AuthResponse
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if upgraded != "" {
			if err := m.repo.SetPassword(ctx, tx, t.ID, user.PrincipalID, upgraded); err != nil {
				return err
			}
		}
		if err := m.repo.ResetRateLimit(ctx, tx, t.ID, constant.BucketSignInAccount, accountKey); err != nil {
			return err
		}
		if err := m.count(ctx, tx, t.ID, constant.MetricSignIns); err != nil {
			return err
		}
		out, err = m.finishPrimary(ctx, tx, t, primary{principalID: user.PrincipalID, method: constant.MethodPassword, kind: req.SessionKind, at: now}, meta)
		return err
	})
	if err != nil {
		return nil, passThrough("sign in", err)
	}
	m.notify.Wake()
	return out, nil
}

// recordFailedSignIn counts the failure, applies the growing delay or the
// lock, and writes the audit entry. The counter is kept per email
// address, known or not, so a lock never reveals that an account exists.
func (m *authModule) recordFailedSignIn(ctx context.Context, t *model.Tenant, email string, accountKey []byte,
	user *model.UserAuth, reason string, alreadyLocked bool, meta model.RequestMeta, now time.Time) error {
	justLocked := false
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		// An attempt made during a lock is refused without being
		// evaluated, so it does not count towards the next lock.
		if !alreadyLocked {
			limit, err := m.repo.HitRateLimit(ctx, tx, t.ID, constant.BucketSignInAccount, accountKey, now, constant.LockoutWindow)
			if err != nil {
				return err
			}
			if delay := core.LockoutDelay(limit.Count); delay > 0 {
				if err := m.repo.LockRateLimit(ctx, tx, t.ID, constant.BucketSignInAccount, accountKey, now.Add(delay)); err != nil {
					return err
				}
			}
			justLocked = limit.Count == constant.LockoutLockAfter
		}

		// Tell the owner once, when the lock starts. Only a real account
		// has an owner to tell.
		if justLocked && user != nil {
			if err := m.notify.Enqueue(ctx, tx, t, model.Message{
				Channel: constant.ChannelEmail, Recipient: email, Template: constant.TemplateAccountLocked,
			}); err != nil {
				return err
			}
		}

		entry := model.AuditEntry{
			Action: "signin.failed", Result: model.AuditFailure, ReasonCode: reason,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}
		if user != nil {
			entry.ActorID = user.PrincipalID
		}
		return m.audit.Append(ctx, tx, t.ID, entry)
	})
	if err != nil {
		return fmt.Errorf("sign in: record failure: %w", err)
	}
	if justLocked {
		m.notify.Wake()
	}
	return nil
}

// ---------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------

// startSession creates a session inside the caller's transaction.
func (m *authModule) startSession(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method string,
	meta model.RequestMeta, now time.Time) (*response.AuthResponse, error) {
	return m.startSessionWith(ctx, tx, t, principalID, constant.SessionBrowser, []model.AuthMethod{{Method: method, At: now}}, nil, meta, now)
}

// startSessionWith creates the session: a browser session held by a
// cookie, or a token session held by an access and a refresh token.
// It also remembers the device and announces a new one (SIGN-11).
func (m *authModule) startSessionWith(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, kind string,
	methods []model.AuthMethod, secondFactorAt *time.Time, meta model.RequestMeta, now time.Time) (*response.AuthResponse, error) {
	user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// A guest has no account, only a principal.
		p, err := m.repo.GetPrincipal(ctx, tx, t.ID, principalID)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, fmt.Errorf("start session: principal %s does not exist", principalID)
		}
		user = &model.User{ID: p.ID, Name: p.DisplayName, Status: p.Status, CreatedAt: p.CreatedAt, Guest: p.Kind == constant.PrincipalKindGuest}
	}
	if kind == "" {
		kind = constant.SessionBrowser
	}

	deviceID, deviceToken, err := m.rememberDevice(ctx, tx, t, user, meta, now)
	if err != nil {
		return nil, err
	}

	// The browser gets the raw id. The database gets only its hash.
	raw := secret.Token(32)
	absolute := now.Add(t.SessionAbsolute)
	idle := now.Add(t.SessionIdle)
	if idle.After(absolute) {
		idle = absolute
	}
	if len(methods) == 0 {
		methods = []model.AuthMethod{{Method: "unknown", At: now}}
	}
	sessionID, err := m.repo.CreateSession(ctx, tx, t.ID, model.NewSession{
		PrincipalID: principalID, IDHash: secret.Hash(raw), Kind: kind,
		AuthMethods: methods, AssuranceLevel: user.AssuranceLevel, SecondFactorAt: secondFactorAt, DeviceID: deviceID,
		IP: meta.IP, UserAgent: meta.UserAgent,
		Now: now, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
	})
	if err != nil {
		return nil, err
	}
	method := methods[len(methods)-1].Method
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "signin.succeeded", Result: model.AuditSuccess,
		ActorID: principalID, SessionID: sessionID,
		Data:      map[string]any{"method": method, "kind": kind},
		RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return nil, err
	}
	if err := m.notify.Emit(ctx, tx, t.ID, "session.created", map[string]any{
		"user_id": principalID, "session_id": sessionID, "method": method, "kind": kind,
	}); err != nil {
		return nil, err
	}
	out := &response.AuthResponse{
		User:         toUser(user),
		Session:      response.Session{ID: sessionID, ExpiresAt: absolute, SecondFactorAt: secondFactorAt},
		SessionToken: raw,
		DeviceToken:  deviceToken,
	}
	if kind == constant.SessionToken {
		if err := m.issueTokenPair(ctx, tx, t, principalID, sessionID, raw, out, now); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// rememberDevice finds the device behind the request, or records it and
// tells the person about the new one. It returns the device id and the
// token the browser should keep, when it has none yet.
func (m *authModule) rememberDevice(ctx context.Context, tx pgx.Tx, t *model.Tenant, user *model.User, meta model.RequestMeta, now time.Time) (string, string, error) {
	if user.Guest {
		return "", "", nil
	}
	token := meta.DeviceToken
	if token != "" {
		d, err := m.repo.FindDevice(ctx, tx, t.ID, user.ID, secret.Hash(token))
		if err != nil {
			return "", "", err
		}
		if d != nil {
			return d.ID, "", m.repo.TouchDevice(ctx, tx, t.ID, d.ID, now)
		}
	}
	// A browser we have not seen for this person. Keep its id if it has
	// one, so it is known next time, else give it one.
	issued := ""
	if token == "" {
		token = secret.Token(32)
		issued = token
	}
	known, err := m.repo.CountDevices(ctx, tx, t.ID, user.ID)
	if err != nil {
		return "", "", err
	}
	id, err := m.repo.CreateDevice(ctx, tx, t.ID, user.ID, secret.Hash(token), core.DeviceLabel(meta.UserAgent), now)
	if err != nil {
		return "", "", err
	}
	// The very first device is the one the account was made from. Every
	// later one is announced.
	if known > 0 && user.Email != "" {
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: user.Email, Template: constant.TemplateNewDevice,
			Data: map[string]string{
				"when": now.UTC().Format(time.RFC1123), "browser": core.DeviceLabel(meta.UserAgent), "address": meta.IP,
				"link": core.Link(t.AppURL, core.ForgotPath, ""),
			},
		}); err != nil {
			return "", "", err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "device.new", Result: model.AuditSuccess, ActorID: user.ID, TargetType: "device", TargetID: id,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return "", "", err
		}
	}
	return id, issued, nil
}

func (m *authModule) authenticate(ctx context.Context, tx pgx.Tx, t *model.Tenant, sessionToken string, now time.Time) (*model.Session, error) {
	return m.authenticateFor(ctx, tx, t, sessionToken, now, false)
}

// authenticateFor finds the live session behind a token. When the
// application requires a second factor and this person has none yet, the
// session opens only the routes that set one up (enrolling is true).
func (m *authModule) authenticateFor(ctx context.Context, tx pgx.Tx, t *model.Tenant, sessionToken string, now time.Time, enrolling bool) (*model.Session, error) {
	if sessionToken == "" {
		return nil, errors.ErrUnauthorized
	}
	var session *model.Session
	var err error
	if looksLikeJWT(sessionToken) {
		session, err = m.sessionFromAccessToken(ctx, tx, t, sessionToken, now)
	} else {
		session, err = m.repo.FindSession(ctx, tx, t.ID, secret.Hash(sessionToken))
	}
	if err != nil {
		return nil, err
	}
	if session == nil ||
		!now.Before(session.IdleExpiresAt) ||
		!now.Before(session.AbsoluteExpiresAt) ||
		session.PrincipalStatus != constant.PrincipalActive {
		return nil, errors.ErrUnauthorized
	}
	if !enrolling && t.MFAPolicy == constant.MFARequired && session.SecondFactorAt == nil && !isGuestSession(session) {
		return nil, errSetupRequired
	}
	// The active organization's address allow-list applies to every
	// request (ENT-7).
	if session.ActiveResourceID != "" && m.orgs != nil {
		policies, err := m.orgs.GetPolicies(ctx, tx, t.ID, session.ActiveResourceID)
		if err != nil {
			return nil, err
		}
		if policies != nil && len(policies.IPAllowlist) > 0 && !core.AddressAllowed(metaIP(ctx), policies.IPAllowlist) {
			return nil, errAddressNotAllowed
		}
	}
	// Move the idle timeout forward, at most once a minute.
	if now.Sub(session.LastSeenAt) >= constant.SessionTouchInterval {
		if err := m.repo.TouchSession(ctx, tx, t.ID, session.ID, now, now.Add(t.SessionIdle)); err != nil {
			return nil, err
		}
	}
	return session, nil
}

var errAddressNotAllowed = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "address_not_allowed", "this organization does not allow sign-in from this address")

var errSSORequired = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "sso_required", "this address must sign in through its company's identity provider")

type ipKey struct{}

// WithClientIP puts the caller's address in the context, for policies
// that look at it.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipKey{}, ip)
}

func metaIP(ctx context.Context) string {
	ip, _ := ctx.Value(ipKey{}).(string)
	return ip
}

func isGuestSession(s *model.Session) bool {
	for _, m := range s.AuthMethods {
		if m.Method == constant.MethodGuest {
			return true
		}
	}
	return false
}

func (m *authModule) CurrentUser(ctx context.Context, t *model.Tenant, sessionToken string) (*response.SessionResponse, error) {
	now := m.now()
	var out *response.SessionResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		if user == nil {
			p, err := m.repo.GetPrincipal(ctx, tx, t.ID, session.PrincipalID)
			if err != nil {
				return err
			}
			if p == nil {
				return errors.ErrUnauthorized
			}
			user = &model.User{ID: p.ID, Name: p.DisplayName, Status: p.Status, CreatedAt: p.CreatedAt, Guest: p.Kind == constant.PrincipalKindGuest}
		}
		out = &response.SessionResponse{
			User: toUser(user),
			Session: response.Session{
				ID: session.ID, ExpiresAt: session.AbsoluteExpiresAt, SecondFactorAt: session.SecondFactorAt,
				ActiveOrganizationID: session.ActiveResourceID, ActiveOrganization: session.ActiveExternalID,
			},
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("current user", err)
	}
	return out, nil
}

func (m *authModule) IssueToken(ctx context.Context, t *model.Tenant, sessionToken string) (*response.TokenResponse, error) {
	now := m.now()
	expires := now.Add(constant.SessionTokenTTL)
	var token string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		kid, key, err := m.keys.SigningKey(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		claims := map[string]any{
			"iss": "aos:" + t.ID,
			"tid": t.ID,
			"sub": session.PrincipalID,
			"sid": session.ID,
			"aal": session.AssuranceLevel,
			"iat": now.Unix(),
			"exp": expires.Unix(),
		}
		if session.ActiveResourceID != "" {
			claims["org"] = session.ActiveExternalID
			claims["org_id"] = session.ActiveResourceID
		}
		token, err = jwt.Sign(kid, key, claims)
		return err
	})
	if err != nil {
		return nil, passThrough("issue token", err)
	}
	return &response.TokenResponse{Token: token, ExpiresAt: expires}, nil
}

func (m *authModule) SignOut(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) error {
	if sessionToken == "" {
		return nil
	}
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		var session *model.Session
		var err error
		if looksLikeJWT(sessionToken) {
			session, err = m.sessionFromAccessToken(ctx, tx, t, sessionToken, now)
		} else {
			session, err = m.repo.FindSession(ctx, tx, t.ID, secret.Hash(sessionToken))
		}
		if err != nil {
			return err
		}
		if session == nil {
			return nil // already signed out
		}
		revoked, err := m.repo.RevokeSession(ctx, tx, t.ID, session.ID, "sign_out", now)
		if err != nil || !revoked {
			return err
		}
		if err := m.repo.RevokeTokenFamiliesOf(ctx, tx, t.ID, session.ID, "sign_out", now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "session.revoked", Result: model.AuditSuccess, ReasonCode: "sign_out",
			ActorID: session.PrincipalID, SessionID: session.ID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "session.revoked", map[string]any{
			"user_id": session.PrincipalID, "session_id": session.ID, "reason": "sign_out",
		})
	})
	if err != nil {
		return fmt.Errorf("sign out: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------

func (m *authModule) ForgotPassword(ctx context.Context, t *model.Tenant, req request.ForgotPasswordRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	withinLimit, err := m.hit(ctx, t, constant.BucketEmail, req.Email, constant.EmailLimitPerHour, constant.EmailLimitWindow)
	if err != nil {
		return err
	}
	if !withinLimit {
		return nil // same answer, nothing sent
	}

	now := m.now()
	raw := secret.Token(32)
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		user, err := m.repo.FindUserByEmail(ctx, tx, t.ID, req.Email)
		if err != nil {
			return err
		}
		// No account, an unconfirmed address, or a suspended account:
		// nothing is sent, and the caller is told the same as always.
		if user == nil || !user.EmailVerified || user.Status != constant.PrincipalActive {
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "password.reset_requested", Result: model.AuditFailure, ReasonCode: "no_eligible_account",
				RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})
		}

		// A new link cancels any older one.
		if err := m.repo.VoidTokens(ctx, tx, t.ID, user.PrincipalID, constant.TokenPasswordReset, now); err != nil {
			return err
		}
		if _, err := m.repo.CreateToken(ctx, tx, t.ID, model.NewToken{
			Purpose: constant.TokenPasswordReset, PrincipalID: user.PrincipalID, Target: req.Email,
			Hash: secret.Hash(raw), ExpiresAt: now.Add(constant.PasswordResetTTL),
		}); err != nil {
			return err
		}
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: req.Email, Template: constant.TemplatePasswordReset,
			Data: map[string]string{"token": raw, "link": core.Link(t.AppURL, core.ResetPasswordPath, raw)},
		}); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "password.reset_requested", Result: model.AuditSuccess,
			ActorID: user.PrincipalID, TargetType: "user", TargetID: user.PrincipalID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return fmt.Errorf("forgot password: %w", err)
	}
	m.notify.Wake()
	return nil
}

func (m *authModule) ResetPassword(ctx context.Context, t *model.Tenant, req request.ResetPasswordRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	if err := m.refusePwnedPassword(ctx, req.Password, "password"); err != nil {
		return err
	}
	hash, err := secret.HashPassword(req.Password, m.params)
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}

	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		token, err := m.repo.LockToken(ctx, tx, t.ID, constant.TokenPasswordReset, secret.Hash(req.Token))
		if err != nil {
			return err
		}
		if token == nil || token.UsedAt != nil || !now.Before(token.ExpiresAt) || token.PrincipalID == "" {
			return errors.ErrInvalidToken
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, token.PrincipalID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.ErrInvalidToken
		}

		if err := m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now); err != nil {
			return err
		}
		if err := m.repo.SetPassword(ctx, tx, t.ID, token.PrincipalID, hash); err != nil {
			return err
		}
		// A reset ends every session. It does not start one: the person
		// signs in again, second factor included once that exists.
		revoked, err := m.repo.RevokeAllSessions(ctx, tx, t.ID, token.PrincipalID, "password_reset", now)
		if err != nil {
			return err
		}
		if err := m.repo.VoidTokens(ctx, tx, t.ID, token.PrincipalID, constant.TokenEmailChange, now); err != nil {
			return err
		}
		// The owner has proved control of the mailbox, so a lock from
		// earlier failed attempts ends too.
		if err := m.repo.ResetRateLimit(ctx, tx, t.ID, constant.BucketSignInAccount, core.LimitKey(user.Email)); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "password.reset", Result: model.AuditSuccess,
			ActorID: token.PrincipalID, TargetType: "user", TargetID: token.PrincipalID,
			Data:      map[string]any{"sessions_revoked": revoked},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "password.reset", map[string]any{"user_id": token.PrincipalID}); err != nil {
			return err
		}
		return m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: user.Email, Template: constant.TemplatePasswordChanged,
		})
	})
	if err != nil {
		return passThrough("reset password", err)
	}
	m.notify.Wake()
	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// hit adds one to a counter and reports whether the caller is still
// within the limit. It runs in its own transaction, so the count is kept
// even when the request that caused it fails.
func (m *authModule) hit(ctx context.Context, t *model.Tenant, bucket, key string, limit int, window time.Duration) (bool, error) {
	var state *model.RateLimit
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		state, err = m.repo.HitRateLimit(ctx, tx, t.ID, bucket, core.LimitKey(key), m.now(), window)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("rate limit: %w", err)
	}
	return state.Count <= limit, nil
}

// limitAddress caps the requests one client address may make to the
// routes that take an email or a password. Being refused here says
// nothing about any account.
func (m *authModule) limitAddress(ctx context.Context, t *model.Tenant, meta model.RequestMeta) error {
	if meta.IP == "" {
		return nil
	}
	ok, err := m.hit(ctx, t, constant.BucketAddress, meta.IP, constant.AddressLimitPerMinute, constant.AddressLimitWindow)
	if err != nil {
		return err
	}
	if !ok {
		return errors.ErrRateLimited
	}
	return nil
}

// passThrough returns an error meant for the caller as it is, and wraps
// anything else with the name of the operation.
func passThrough(operation string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsAppError(err); ok {
		return err
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func toUser(u *model.User) response.User {
	return response.User{
		ID: u.ID, Email: u.Email, Name: u.Name, Status: u.Status, EmailVerified: u.EmailVerified,
		AssuranceLevel: u.AssuranceLevel, CreatedAt: u.CreatedAt, Guest: u.Guest,
	}
}
