package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/module/auth/core"
	"github.com/flash-softeware/aos/platform/postgres"
	"github.com/flash-softeware/aos/platform/secret"
)

// ---------------------------------------------------------------------
// Sessions: the device list
// ---------------------------------------------------------------------

func (m *authModule) Authenticate(ctx context.Context, t *model.Tenant, sessionToken string) (*model.Session, error) {
	now := m.now()
	var session *model.Session
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		session, err = m.authenticate(ctx, tx, t, sessionToken, now)
		return err
	})
	if err != nil {
		return nil, passThrough("authenticate", err)
	}
	return session, nil
}

func (m *authModule) StartSession(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method string, meta model.RequestMeta) (*response.AuthResponse, error) {
	return m.startSession(ctx, tx, t, principalID, method, meta, m.now())
}

func (m *authModule) ListSessions(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.SessionInfo, error) {
	now := m.now()
	var out []response.SessionInfo
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		sessions, err := m.repo.ListSessions(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		out = make([]response.SessionInfo, 0, len(sessions))
		for _, s := range sessions {
			if !now.Before(s.ExpiresAt) {
				continue
			}
			out = append(out, toSessionInfo(s, s.ID == session.ID))
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list sessions", err)
	}
	return out, nil
}

func (m *authModule) RevokeSession(ctx context.Context, t *model.Tenant, sessionToken, sessionID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(sessionID) {
		return errors.NotFound("session")
	}
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		current, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		target, err := m.repo.FindSessionByID(ctx, tx, t.ID, sessionID)
		if err != nil {
			return err
		}
		// A person can end only their own sessions. Another person's
		// session reads as "not found", not as "forbidden".
		if target == nil || target.PrincipalID != current.PrincipalID {
			return errors.NotFound("session")
		}
		if _, err := m.repo.RevokeSession(ctx, tx, t.ID, target.ID, "revoked_by_owner", now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "session.revoked", Result: model.AuditSuccess, ReasonCode: "revoked_by_owner",
			ActorID: current.PrincipalID, SessionID: current.ID, TargetType: "session", TargetID: target.ID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "session.revoked", map[string]any{
			"user_id": current.PrincipalID, "session_id": target.ID, "reason": "revoked_by_owner",
		})
	})
	return passThrough("revoke session", err)
}

func (m *authModule) SignOutEverywhere(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) error {
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		current, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		revoked, err := m.repo.RevokeAllSessions(ctx, tx, t.ID, current.PrincipalID, "sign_out_everywhere", now)
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "session.revoked_all", Result: model.AuditSuccess, ReasonCode: "sign_out_everywhere",
			ActorID: current.PrincipalID, SessionID: current.ID, Data: map[string]any{"sessions_revoked": revoked},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "session.revoked_all", map[string]any{"user_id": current.PrincipalID})
	})
	return passThrough("sign out everywhere", err)
}

// ---------------------------------------------------------------------
// Changing the password and the email address
// ---------------------------------------------------------------------

// confirmPassword checks the signed-in person's password for a sensitive
// action. It costs one hash computation, like a sign-in.
func (m *authModule) confirmPassword(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, password string) (*model.User, error) {
	user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.ErrUnauthorized
	}
	auth, err := m.repo.FindUserByEmail(ctx, tx, t.ID, user.Email)
	if err != nil {
		return nil, err
	}
	hash := m.dummyHash
	if auth != nil && auth.PasswordHash != "" {
		hash = auth.PasswordHash
	}
	ok, _, verr := secret.VerifyPassword(password, hash)
	if verr != nil || !ok || auth == nil || auth.PasswordHash == "" {
		return nil, errors.ErrInvalidCredentials
	}
	return user, nil
}

func (m *authModule) ChangePassword(ctx context.Context, t *model.Tenant, sessionToken string, req request.ChangePasswordRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	if err := m.refusePwnedPassword(ctx, req.NewPassword, "new_password"); err != nil {
		return err
	}
	hash, err := secret.HashPassword(req.NewPassword, m.params)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		current, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		user, err := m.confirmPassword(ctx, tx, t, current.PrincipalID, req.CurrentPassword)
		if err != nil {
			return err
		}
		if err := m.repo.SetPassword(ctx, tx, t.ID, user.ID, hash); err != nil {
			return err
		}
		// Every other session ends. This one stays. A pending change of
		// email address is cancelled too: the person may be reacting to it.
		if _, err := m.repo.RevokeOtherSessions(ctx, tx, t.ID, user.ID, current.ID, "password_changed", now); err != nil {
			return err
		}
		if err := m.repo.VoidTokens(ctx, tx, t.ID, user.ID, constant.TokenEmailChange, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "password.changed", Result: model.AuditSuccess, ActorID: user.ID, SessionID: current.ID,
			TargetType: "user", TargetID: user.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "password.changed", map[string]any{"user_id": user.ID}); err != nil {
			return err
		}
		return m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: user.Email, Template: constant.TemplatePasswordChanged,
		})
	})
	if err != nil {
		return passThrough("change password", err)
	}
	m.notify.Wake()
	return nil
}

func (m *authModule) ChangeEmail(ctx context.Context, t *model.Tenant, sessionToken string, req request.ChangeEmailRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	withinLimit, err := m.hit(ctx, t, constant.BucketEmail, req.NewEmail, constant.EmailLimitPerHour, constant.EmailLimitWindow)
	if err != nil {
		return err
	}

	now := m.now()
	raw := secret.Token(32)
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		current, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		user, err := m.confirmPassword(ctx, tx, t, current.PrincipalID, req.Password)
		if err != nil {
			return err
		}
		if user.Email == req.NewEmail {
			return errors.Validation(map[string]string{"new_email": "is already the address of this account"})
		}
		if !withinLimit {
			return nil // the answer stays the same, nothing is sent
		}

		taken, err := m.repo.FindUserByEmail(ctx, tx, t.ID, req.NewEmail)
		if err != nil {
			return err
		}
		if taken != nil {
			// The new address belongs to someone else. Its owner is told,
			// the link never arrives, and the caller learns nothing.
			if err := m.notify.Enqueue(ctx, tx, t, model.Message{
				Channel: constant.ChannelEmail, Recipient: req.NewEmail, Template: constant.TemplateExistingAccount,
			}); err != nil {
				return err
			}
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "email.change_requested", Result: model.AuditFailure, ReasonCode: "address_taken",
				ActorID: user.ID, SessionID: current.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})
		}

		if err := m.repo.VoidTokens(ctx, tx, t.ID, user.ID, constant.TokenEmailChange, now); err != nil {
			return err
		}
		if _, err := m.repo.CreateToken(ctx, tx, t.ID, model.NewToken{
			Purpose: constant.TokenEmailChange, PrincipalID: user.ID, Target: req.NewEmail,
			Hash: secret.Hash(raw), ExpiresAt: now.Add(constant.EmailChangeTTL),
			Payload: map[string]string{"new_email": req.NewEmail},
		}); err != nil {
			return err
		}
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: req.NewEmail, Template: constant.TemplateEmailChange,
			Data: map[string]string{"token": raw, "link": core.Link(t.AppURL, core.ConfirmEmailPath, raw)},
		}); err != nil {
			return err
		}
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: user.Email, Template: constant.TemplateEmailChangeNote,
			Data: map[string]string{"new_email": req.NewEmail},
		}); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "email.change_requested", Result: model.AuditSuccess, ActorID: user.ID, SessionID: current.ID,
			TargetType: "user", TargetID: user.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return passThrough("change email", err)
	}
	m.notify.Wake()
	return nil
}

func (m *authModule) ConfirmEmail(ctx context.Context, t *model.Tenant, req request.ConfirmEmailRequest, meta model.RequestMeta) (*response.User, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.User
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		token, err := m.repo.LockToken(ctx, tx, t.ID, constant.TokenEmailChange, secret.Hash(req.Token))
		if err != nil {
			return err
		}
		if token == nil || token.UsedAt != nil || !now.Before(token.ExpiresAt) || token.PrincipalID == "" {
			return errors.ErrInvalidToken
		}
		newEmail := token.Payload["new_email"]
		if newEmail == "" {
			return errors.ErrInvalidToken
		}
		if err := m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now); err != nil {
			return err
		}
		// The address may have been taken since the link was sent.
		taken, err := m.repo.FindUserByEmail(ctx, tx, t.ID, newEmail)
		if err != nil {
			return err
		}
		if taken != nil {
			return errors.ErrInvalidToken
		}
		if err := m.repo.UpdateEmail(ctx, tx, t.ID, token.PrincipalID, newEmail, now); err != nil {
			return err
		}
		// Every session ends: the person signs in again with the new address.
		if _, err := m.repo.RevokeAllSessions(ctx, tx, t.ID, token.PrincipalID, "email_changed", now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.email_changed", Result: model.AuditSuccess, ActorID: token.PrincipalID,
			TargetType: "user", TargetID: token.PrincipalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.email_changed", map[string]any{"user_id": token.PrincipalID}); err != nil {
			return err
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, token.PrincipalID)
		if err != nil {
			return err
		}
		u := toUser(user)
		out = &u
		return nil
	})
	if err != nil {
		return nil, passThrough("confirm email", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Deleting and exporting
// ---------------------------------------------------------------------

func (m *authModule) DeleteAccount(ctx context.Context, t *model.Tenant, sessionToken string, req request.PasswordConfirmRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	now := m.now()

	// First the password, in a short transaction, so the before-hook is
	// asked only for a person who proved who they are.
	var user *model.User
	var current *model.Session
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		if current, err = m.authenticate(ctx, tx, t, sessionToken, now); err != nil {
			return err
		}
		user, err = m.confirmPassword(ctx, tx, t, current.PrincipalID, req.Password)
		return err
	})
	if err != nil {
		return passThrough("delete account", err)
	}
	// The application can refuse, for example while money is in transit.
	if err := m.notify.Hook(ctx, t, constant.HookUserBeforeDelete, map[string]any{"user_id": user.ID, "email": user.Email}); err != nil {
		return err
	}
	return m.deletePrincipal(ctx, t, user.ID, current, "self", meta, now)
}

func (m *authModule) deletePrincipal(ctx context.Context, t *model.Tenant, principalID string, current *model.Session, by string, meta model.RequestMeta, now time.Time) error {
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if err := m.repo.MarkPrincipalDeleted(ctx, tx, t.ID, principalID, now, now.Add(constant.DeletionGrace)); err != nil {
			return err
		}
		if _, err := m.repo.RevokeAllSessions(ctx, tx, t.ID, principalID, "account_deleted", now); err != nil {
			return err
		}
		entry := model.AuditEntry{
			Action: "user.deleted", Result: model.AuditSuccess, ReasonCode: by, TargetType: "user", TargetID: principalID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}
		if current != nil {
			entry.ActorID, entry.SessionID = current.PrincipalID, current.ID
		}
		if err := m.audit.Append(ctx, tx, t.ID, entry); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "user.deleted", map[string]any{
			"user_id": principalID, "purge_after": now.Add(constant.DeletionGrace).UTC(),
		})
	})
	if err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	m.notify.Wake()
	return nil
}

func (m *authModule) Export(ctx context.Context, t *model.Tenant, sessionToken string, req request.PasswordConfirmRequest, meta model.RequestMeta) (*response.ExportResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out response.ExportResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		current, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		user, err := m.confirmPassword(ctx, tx, t, current.PrincipalID, req.Password)
		if err != nil {
			return err
		}
		out.User = toUser(user)

		sessions, err := m.repo.ListSessions(ctx, tx, t.ID, user.ID)
		if err != nil {
			return err
		}
		for _, s := range sessions {
			out.Sessions = append(out.Sessions, toSessionInfo(s, s.ID == current.ID))
		}
		grants, err := m.iam.ListGrantsForPrincipal(ctx, tx, t.ID, user.ID)
		if err != nil {
			return err
		}
		for _, g := range grants {
			out.Grants = append(out.Grants, response.Grant{
				ID: g.ID, PrincipalID: user.ID, Role: g.Role, Effect: g.Effect, ExpiresAt: g.ExpiresAt,
				Resource: response.Resource{Type: g.ResourceType, ExternalID: g.ResourceID},
			})
		}
		entries, err := m.audit.ListForPrincipal(ctx, tx, t.ID, user.ID, 1000)
		if err != nil {
			return err
		}
		for _, e := range entries {
			out.Audit = append(out.Audit, response.AuditEntry{
				Seq: e.Seq, OccurredAt: e.OccurredAt, Action: e.Action, Result: e.Result,
				ReasonCode: e.ReasonCode, TargetType: e.TargetType, TargetID: e.TargetID,
			})
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.exported", Result: model.AuditSuccess, ActorID: user.ID, SessionID: current.ID,
			TargetType: "user", TargetID: user.ID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return nil, passThrough("export", err)
	}
	if out.Sessions == nil {
		out.Sessions = []response.SessionInfo{}
	}
	if out.Grants == nil {
		out.Grants = []response.Grant{}
	}
	if out.Audit == nil {
		out.Audit = []response.AuditEntry{}
	}
	return &out, nil
}

// ---------------------------------------------------------------------
// Accounts an admin creates
// ---------------------------------------------------------------------

func (m *authModule) CreateUser(ctx context.Context, t *model.Tenant, req request.CreateUserRequest, meta model.RequestMeta) (*response.User, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	raw := secret.Token(32)
	var out *response.User
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		existing, err := m.repo.FindUserByEmail(ctx, tx, t.ID, req.Email)
		if err != nil {
			return err
		}
		// An admin is trusted with the fact that an address is taken.
		if existing != nil {
			return errors.Conflict("email_taken", "an account with this email address already exists")
		}
		if err := m.withinLimit(ctx, tx, t.ID, constant.MetricUsers, func() (int64, error) { return m.repo.CountUsers(ctx, tx, t.ID) }); err != nil {
			return err
		}
		principalID, err := m.repo.CreateUser(ctx, tx, t.ID, req.Email, req.Name)
		if err != nil {
			return err
		}
		// The person chooses their own password through the link. No
		// password is set here, and the admin never sees one.
		if _, err := m.repo.CreateToken(ctx, tx, t.ID, model.NewToken{
			Purpose: constant.TokenAccountSetup, PrincipalID: principalID, Target: req.Email,
			Hash: secret.Hash(raw), ExpiresAt: now.Add(constant.AccountSetupTTL),
		}); err != nil {
			return err
		}
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: req.Email, Template: constant.TemplateAccountSetup,
			Data: map[string]string{"token": raw, "link": core.Link(t.AppURL, core.SetupAccountPath, raw)},
		}); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.created", Result: model.AuditSuccess, ReasonCode: "by_admin",
			TargetType: "user", TargetID: principalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.created", map[string]any{"user_id": principalID, "by": "admin"}); err != nil {
			return err
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
		if err != nil {
			return err
		}
		u := toUser(user)
		out = &u
		return nil
	})
	if err != nil {
		return nil, passThrough("create user", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *authModule) SetupAccount(ctx context.Context, t *model.Tenant, req request.SetupAccountRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	if err := m.refusePwnedPassword(ctx, req.Password, "password"); err != nil {
		return nil, err
	}
	hash, err := secret.HashPassword(req.Password, m.params)
	if err != nil {
		return nil, fmt.Errorf("set up account: %w", err)
	}
	now := m.now()
	var out *response.AuthResponse
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		token, err := m.repo.LockToken(ctx, tx, t.ID, constant.TokenAccountSetup, secret.Hash(req.Token))
		if err != nil {
			return err
		}
		if token == nil || token.UsedAt != nil || !now.Before(token.ExpiresAt) || token.PrincipalID == "" {
			return errors.ErrInvalidToken
		}
		if err := m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now); err != nil {
			return err
		}
		if err := m.repo.SetPassword(ctx, tx, t.ID, token.PrincipalID, hash); err != nil {
			return err
		}
		// Opening the link proves control of the address the admin gave.
		if err := m.repo.MarkEmailVerified(ctx, tx, t.ID, token.PrincipalID, now); err != nil {
			return err
		}
		if t.DefaultRoleID != "" && t.RootResourceID != "" {
			if err := m.repo.GrantDefaultRole(ctx, tx, t.ID, token.PrincipalID, t.DefaultRoleID, t.RootResourceID); err != nil {
				return err
			}
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.set_up", Result: model.AuditSuccess, ActorID: token.PrincipalID,
			TargetType: "user", TargetID: token.PrincipalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.email_verified", map[string]any{"user_id": token.PrincipalID}); err != nil {
			return err
		}
		out, err = m.startSession(ctx, tx, t, token.PrincipalID, "setup_link", meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("set up account", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Admin actions on accounts
// ---------------------------------------------------------------------

func (m *authModule) GetUser(ctx context.Context, t *model.Tenant, principalID string) (*response.User, error) {
	if !postgres.IsUUID(principalID) {
		return nil, errors.NotFound("user")
	}
	var out *response.User
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.NotFound("user")
		}
		u := toUser(user)
		out = &u
		return nil
	})
	if err != nil {
		return nil, passThrough("get user", err)
	}
	return out, nil
}

func (m *authModule) ListUsers(ctx context.Context, t *model.Tenant, cursor string, limit int) (*response.UserPage, error) {
	if limit <= 0 {
		limit = constant.DefaultPageSize
	}
	if limit > constant.MaxPageSize {
		limit = constant.MaxPageSize
	}
	afterCreated, afterID, err := decodeCursor(cursor)
	if err != nil {
		return nil, errors.Validation(map[string]string{"cursor": "is not valid"})
	}
	var users []model.User
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		users, err = m.repo.ListUsers(ctx, tx, t.ID, afterCreated, afterID, limit+1)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	page := &response.UserPage{Users: make([]response.User, 0, len(users))}
	for i, u := range users {
		if i == limit {
			last := users[i-1]
			page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
			break
		}
		page.Users = append(page.Users, toUser(&u))
	}
	return page, nil
}

func (m *authModule) SuspendUser(ctx context.Context, t *model.Tenant, principalID, reason string, meta model.RequestMeta) error {
	return m.setStatus(ctx, t, principalID, constant.PrincipalSuspended, reason, "user.suspended", meta)
}

func (m *authModule) ReinstateUser(ctx context.Context, t *model.Tenant, principalID string, meta model.RequestMeta) error {
	return m.setStatus(ctx, t, principalID, constant.PrincipalActive, "", "user.reinstated", meta)
}

func (m *authModule) setStatus(ctx context.Context, t *model.Tenant, principalID, status, reason, action string, meta model.RequestMeta) error {
	if !postgres.IsUUID(principalID) {
		return errors.NotFound("user")
	}
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
		if err != nil {
			return err
		}
		if user == nil || user.Status == "deleted" {
			return errors.NotFound("user")
		}
		if err := m.repo.SetPrincipalStatus(ctx, tx, t.ID, principalID, status, reason, now); err != nil {
			return err
		}
		if status == constant.PrincipalSuspended {
			// The person is signed out everywhere at once.
			if _, err := m.repo.RevokeAllSessions(ctx, tx, t.ID, principalID, "suspended", now); err != nil {
				return err
			}
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: action, Result: model.AuditSuccess, TargetType: "user", TargetID: principalID,
			Data: map[string]any{"reason": reason}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, action, map[string]any{"user_id": principalID})
	})
	return passThrough(action, err)
}

func (m *authModule) DeleteUser(ctx context.Context, t *model.Tenant, principalID string, meta model.RequestMeta) error {
	if !postgres.IsUUID(principalID) {
		return errors.NotFound("user")
	}
	var user *model.User
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) (err error) {
		user, err = m.repo.GetUser(ctx, tx, t.ID, principalID)
		return err
	})
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if user == nil || user.Status == "deleted" {
		return errors.NotFound("user")
	}
	if err := m.notify.Hook(ctx, t, constant.HookUserBeforeDelete, map[string]any{"user_id": user.ID, "email": user.Email, "by": "admin"}); err != nil {
		return err
	}
	return m.deletePrincipal(ctx, t, principalID, nil, "admin", meta, m.now())
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// refusePwnedPassword turns a leaked password into a validation error on
// the named field. A checker that fails is not a reason to refuse.
func (m *authModule) refusePwnedPassword(ctx context.Context, password, field string) error {
	if m.breach == nil {
		return nil
	}
	leaked, err := m.breach.Breached(ctx, password)
	if err != nil {
		m.log.Warn(ctx, "breached-password check failed, password accepted", "error", err.Error())
		return nil
	}
	if leaked {
		return errors.Validation(map[string]string{field: "appears in a list of leaked passwords. choose another one"})
	}
	return nil
}

func toSessionInfo(s model.SessionInfo, current bool) response.SessionInfo {
	methods := make([]string, 0, len(s.AuthMethods))
	for _, am := range s.AuthMethods {
		methods = append(methods, am.Method)
	}
	return response.SessionInfo{
		ID: s.ID, Current: current, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
		IP: s.IP, UserAgent: s.UserAgent, AuthMethods: methods,
	}
}

func encodeCursor(createdAt time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(createdAt.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeCursor(cursor string) (time.Time, string, error) {
	if cursor == "" {
		return time.Time{}, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", err
	}
	stamp, id, ok := strings.Cut(string(raw), "|")
	if !ok || !postgres.IsUUID(id) {
		return time.Time{}, "", fmt.Errorf("bad cursor")
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	return at, id, err
}
