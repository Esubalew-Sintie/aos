package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module/auth/core"
	"github.com/flash-software-technology/aos/platform/secret"
)

// Sign-in with a one-time code or a magic link (user-flow SIGN-4).

// SendCode always answers the same. A code and a link go to an address
// that has a verified, active account; nothing goes anywhere else.
func (m *authModule) SendCode(ctx context.Context, t *model.Tenant, req request.SendCodeRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return err
	}
	withinLimit, err := m.hit(ctx, t, constant.BucketCode, req.Email, constant.CodeLimitPerHour, constant.CodeLimitWindow)
	if err != nil {
		return err
	}
	if !withinLimit {
		return nil
	}
	code, err := core.NewNumericCode(constant.TOTPDigits)
	if err != nil {
		return err
	}
	link := secret.Token(32)
	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		user, err := m.repo.FindUserByEmail(ctx, tx, t.ID, req.Email)
		if err != nil {
			return err
		}
		if user == nil || user.Status != constant.PrincipalActive || !user.EmailVerified {
			return nil
		}
		// A new code replaces the old one.
		for _, purpose := range []string{constant.TokenOneTimeCode, constant.TokenMagicLink} {
			if err := m.repo.VoidTokens(ctx, tx, t.ID, user.PrincipalID, purpose, now); err != nil {
				return err
			}
		}
		if _, err := m.repo.CreateToken(ctx, tx, t.ID, model.NewToken{
			Purpose: constant.TokenOneTimeCode, PrincipalID: user.PrincipalID, Target: req.Email,
			Hash: secret.Hash(code), ExpiresAt: now.Add(constant.OneTimeCodeTTL), MaxAttempts: constant.OneTimeCodeMaxAttempts,
		}); err != nil {
			return err
		}
		if _, err := m.repo.CreateToken(ctx, tx, t.ID, model.NewToken{
			Purpose: constant.TokenMagicLink, PrincipalID: user.PrincipalID, Target: req.Email,
			Hash: secret.Hash(link), ExpiresAt: now.Add(constant.OneTimeCodeTTL),
		}); err != nil {
			return err
		}
		return m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: req.Email, Template: constant.TemplateSignInCode,
			Data: map[string]string{"code": code, "token": link, "link": core.Link(t.AppURL, core.MagicLinkPath, link)},
		})
	})
	if err != nil {
		return passThrough("send code", err)
	}
	m.notify.Wake()
	return nil
}

func (m *authModule) VerifyCode(ctx context.Context, t *model.Tenant, req request.VerifyCodeRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		token, err := m.repo.LockTokenByTarget(ctx, tx, t.ID, constant.TokenOneTimeCode, req.Email)
		if err != nil {
			return err
		}
		if token == nil || !now.Before(token.ExpiresAt) || token.PrincipalID == "" {
			return errWrongCode
		}
		attempts, err := m.repo.BumpTokenAttempts(ctx, tx, t.ID, token.ID)
		if err != nil {
			return err
		}
		if attempts > token.MaxAttempts {
			// Too many guesses: the code is spent. Ask for a new one.
			return m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now)
		}
		if !secret.Equal(secret.Hash(req.Code), token.Hash) {
			return nil
		}
		if err := m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now); err != nil {
			return err
		}
		if err := m.repo.VoidTokens(ctx, tx, t.ID, token.PrincipalID, constant.TokenMagicLink, now); err != nil {
			return err
		}
		out, err = m.signInWithoutPassword(ctx, tx, t, token.PrincipalID, constant.MethodOneTimeCode, req.SessionKind, meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("verify code", err)
	}
	if out == nil {
		return nil, errWrongCode
	}
	m.notify.Wake()
	return out, nil
}

func (m *authModule) MagicLink(ctx context.Context, t *model.Tenant, req request.MagicLinkRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		token, err := m.repo.LockToken(ctx, tx, t.ID, constant.TokenMagicLink, secret.Hash(req.Token))
		if err != nil {
			return err
		}
		if token == nil || token.UsedAt != nil || !now.Before(token.ExpiresAt) || token.PrincipalID == "" {
			return errors.ErrInvalidToken
		}
		if err := m.repo.MarkTokenUsed(ctx, tx, t.ID, token.ID, now); err != nil {
			return err
		}
		if err := m.repo.VoidTokens(ctx, tx, t.ID, token.PrincipalID, constant.TokenOneTimeCode, now); err != nil {
			return err
		}
		out, err = m.signInWithoutPassword(ctx, tx, t, token.PrincipalID, constant.MethodMagicLink, req.SessionKind, meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("magic link", err)
	}
	m.notify.Wake()
	return out, nil
}

// signInWithoutPassword ends a first factor that was not a password. The
// account must still be usable, and the second factor still applies.
func (m *authModule) signInWithoutPassword(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method, kind string, meta model.RequestMeta, now time.Time) (*response.AuthResponse, error) {
	user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != constant.PrincipalActive {
		return nil, errors.ErrAccountSuspended
	}
	if err := m.repo.ResetRateLimit(ctx, tx, t.ID, constant.BucketSignInAccount, core.LimitKey(user.Email)); err != nil {
		return nil, err
	}
	if err := m.count(ctx, tx, t.ID, constant.MetricSignIns); err != nil {
		return nil, err
	}
	return m.finishPrimary(ctx, tx, t, primary{principalID: principalID, method: method, kind: kind, at: now}, meta)
}
