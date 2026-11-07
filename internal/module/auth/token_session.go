package auth

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/platform/jwt"
	"github.com/flash-softeware/aos/platform/secret"
)

// Token sessions (user-flow SIGN-8), for mobile apps and other clients
// that cannot hold a cookie. Sign-in returns an access token, signed and
// short-lived, and a refresh token, random and usable once. All refresh
// tokens from one sign-in form a family. A refresh token that arrives
// again after it was used means someone has a copy: the whole family and
// the session end, and the person is told.

var (
	errRefreshInvalid = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "invalid_refresh_token", "sign in again")
	errTokenReused    = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "token_reused", "this sign-in was ended because a token was used twice. sign in again")
)

func looksLikeJWT(token string) bool {
	return strings.HasPrefix(token, "eyJ") && strings.Count(token, ".") == 2
}

// sessionFromAccessToken finds the session an access token names. The
// token is checked against the tenant's own keys.
func (m *authModule) sessionFromAccessToken(ctx context.Context, tx pgx.Tx, t *model.Tenant, token string, now time.Time) (*model.Session, error) {
	var lookupErr error
	claims, err := jwt.Verify(token, now, func(kid string) ed25519.PublicKey {
		key, err := m.keys.PublicKey(ctx, tx, t.ID, kid)
		if err != nil {
			lookupErr = err
		}
		return key
	})
	if lookupErr != nil {
		return nil, lookupErr
	}
	if err != nil {
		return nil, nil
	}
	if claims["tid"] != t.ID || claims["typ"] != "access" {
		return nil, nil
	}
	sid, _ := claims["sid"].(string)
	if sid == "" {
		return nil, nil
	}
	return m.repo.FindSessionByID(ctx, tx, t.ID, sid)
}

// issueTokenPair starts a token family for a new token session and puts
// the first pair in the answer.
func (m *authModule) issueTokenPair(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, sessionID, raw string, out *response.AuthResponse, now time.Time) error {
	familyID, err := m.repo.CreateTokenFamily(ctx, tx, t.ID, principalID, sessionID)
	if err != nil {
		return err
	}
	return m.fillTokens(ctx, tx, t, familyID, principalID, sessionID, out, now)
}

func (m *authModule) fillTokens(ctx context.Context, tx pgx.Tx, t *model.Tenant, familyID, principalID, sessionID string, out *response.AuthResponse, now time.Time) error {
	refresh := secret.Token(32)
	expires := now.Add(constant.RefreshTokenTTL)
	if out.Session.ExpiresAt.Before(expires) {
		expires = out.Session.ExpiresAt
	}
	if _, err := m.repo.CreateRefreshToken(ctx, tx, t.ID, familyID, secret.Hash(refresh), expires); err != nil {
		return err
	}
	kid, key, err := m.keys.SigningKey(ctx, tx, t.ID)
	if err != nil {
		return err
	}
	session, err := m.repo.FindSessionByID(ctx, tx, t.ID, sessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return errRefreshInvalid
	}
	claims := map[string]any{
		"iss": "aos:" + t.ID, "tid": t.ID, "sub": principalID, "sid": sessionID, "typ": "access",
		"aal": session.AssuranceLevel, "iat": now.Unix(), "exp": now.Add(constant.AccessTokenTTL).Unix(),
	}
	if session.ActiveResourceID != "" {
		claims["org"] = session.ActiveExternalID
		claims["org_id"] = session.ActiveResourceID
	}
	access, err := jwt.Sign(kid, key, claims)
	if err != nil {
		return err
	}
	out.AccessToken = access
	out.RefreshToken = refresh
	out.ExpiresIn = int(constant.AccessTokenTTL.Seconds())
	return nil
}

// Refresh trades a refresh token for a new pair.
func (m *authModule) Refresh(ctx context.Context, t *model.Tenant, req request.RefreshRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthResponse
	reused := false
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		rt, err := m.repo.LockRefreshToken(ctx, tx, t.ID, secret.Hash(req.RefreshToken))
		if err != nil {
			return err
		}
		if rt == nil || rt.FamilyRevoked || rt.SessionID == "" {
			return errRefreshInvalid
		}
		if rt.UsedAt != nil {
			// Reuse. Someone has a copy of a token that was already spent.
			// What is written here must stay written, so the transaction
			// commits and the refusal follows it.
			reused = true
			return m.reuseDetected(ctx, tx, t, rt, meta, now)
		}
		if !now.Before(rt.ExpiresAt) {
			return errRefreshInvalid
		}
		session, err := m.repo.FindSessionByID(ctx, tx, t.ID, rt.SessionID)
		if err != nil {
			return err
		}
		if session == nil || !now.Before(session.AbsoluteExpiresAt) || !now.Before(session.IdleExpiresAt) || session.PrincipalStatus != constant.PrincipalActive {
			return errRefreshInvalid
		}
		if err := m.repo.MarkRefreshTokenUsed(ctx, tx, t.ID, rt.ID, now); err != nil {
			return err
		}
		if err := m.repo.TouchSession(ctx, tx, t.ID, session.ID, now, now.Add(t.SessionIdle)); err != nil {
			return err
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		out = &response.AuthResponse{
			Session: response.Session{ID: session.ID, ExpiresAt: session.AbsoluteExpiresAt, SecondFactorAt: session.SecondFactorAt,
				ActiveOrganizationID: session.ActiveResourceID, ActiveOrganization: session.ActiveExternalID},
		}
		if user != nil {
			out.User = toUser(user)
		}
		return m.fillTokens(ctx, tx, t, rt.FamilyID, session.PrincipalID, session.ID, out, now)
	})
	if err != nil {
		return nil, passThrough("refresh", err)
	}
	m.notify.Wake()
	if reused {
		return nil, errTokenReused
	}
	return out, nil
}

func (m *authModule) reuseDetected(ctx context.Context, tx pgx.Tx, t *model.Tenant, rt *model.RefreshToken, meta model.RequestMeta, now time.Time) error {
	if err := m.repo.RevokeTokenFamily(ctx, tx, t.ID, rt.FamilyID, "reuse_detected", now); err != nil {
		return err
	}
	if _, err := m.repo.RevokeSession(ctx, tx, t.ID, rt.SessionID, "token_reuse", now); err != nil {
		return err
	}
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "token.reuse_detected", Result: model.AuditDenied, ActorID: rt.PrincipalID, SessionID: rt.SessionID,
		Data: map[string]any{"family_id": rt.FamilyID}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return err
	}
	if err := m.notify.Emit(ctx, tx, t.ID, "session.revoked", map[string]any{
		"user_id": rt.PrincipalID, "session_id": rt.SessionID, "reason": "token_reuse",
	}); err != nil {
		return err
	}
	if u, err := m.repo.GetUser(ctx, tx, t.ID, rt.PrincipalID); err == nil && u != nil {
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: u.Email, Template: constant.TemplateTokenReused,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *authModule) StartTokenSession(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method string, meta model.RequestMeta) (*response.AuthResponse, error) {
	now := m.now()
	return m.startSessionWith(ctx, tx, t, principalID, constant.SessionToken, []model.AuthMethod{{Method: method, At: now}}, nil, meta, now)
}
