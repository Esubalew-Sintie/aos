package auth

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/platform/secret"
)

// Guest accounts (user-flow REG-8): a visitor who can act before they
// sign up, and keep what they did when they do.

var errNotAGuest = errors.Conflict("not_a_guest", "this session already belongs to an account")

func (m *authModule) CreateGuest(ctx context.Context, t *model.Tenant, req request.GuestRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		id, err := m.repo.CreateGuest(ctx, tx, t.ID, req.Name)
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "guest.created", Result: model.AuditSuccess, ActorID: id, TargetType: "principal", TargetID: id,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "guest.created", map[string]any{"principal_id": id}); err != nil {
			return err
		}
		out, err = m.startSessionWith(ctx, tx, t, id, constant.SessionBrowser, []model.AuthMethod{{Method: constant.MethodGuest, At: now}}, nil, meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("create guest", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *authModule) UpgradeGuest(ctx context.Context, t *model.Tenant, sessionToken string, req request.SignUpRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	if t.Status == constant.TenantRestricted || t.SignupPolicy == constant.SignupInviteOnly {
		return nil
	}
	if err := m.refusePwnedPassword(ctx, req.Password, "password"); err != nil {
		return err
	}
	hash, err := secret.HashPassword(req.Password, m.params)
	if err != nil {
		return err
	}
	if err := m.notify.Hook(ctx, t, constant.HookUserBeforeCreate, map[string]any{"email": req.Email, "name": req.Name, "guest": true}); err != nil {
		return err
	}
	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		p, err := m.repo.GetPrincipal(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		if p == nil || p.Kind != constant.PrincipalKindGuest {
			return errNotAGuest
		}
		existing, err := m.repo.FindUserByEmail(ctx, tx, t.ID, req.Email)
		if err != nil {
			return err
		}
		if existing != nil {
			// The same words as at sign-up, and the account's owner is told.
			if existing.EmailVerified {
				return m.notify.Enqueue(ctx, tx, t, model.Message{
					Channel: constant.ChannelEmail, Recipient: req.Email, Template: constant.TemplateExistingAccount,
				})
			}
			return nil
		}
		if err := m.withinLimit(ctx, tx, t.ID, constant.MetricUsers, func() (int64, error) { return m.repo.CountUsers(ctx, tx, t.ID) }); err != nil {
			return err
		}
		if err := m.repo.AttachAccount(ctx, tx, t.ID, session.PrincipalID, req.Email, req.Name); err != nil {
			return err
		}
		if err := m.count(ctx, tx, t.ID, constant.MetricSignUps); err != nil {
			return err
		}
		if err := m.addPendingPassword(ctx, tx, t, session.PrincipalID, req.Email, hash, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.created", Result: model.AuditSuccess, ReasonCode: "from_guest",
			ActorID: session.PrincipalID, SessionID: session.ID, TargetType: "user", TargetID: session.PrincipalID,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		return m.notify.Emit(ctx, tx, t.ID, "user.created", map[string]any{"user_id": session.PrincipalID, "from_guest": true})
	})
	if err != nil {
		return passThrough("upgrade guest", err)
	}
	m.notify.Wake()
	return nil
}
