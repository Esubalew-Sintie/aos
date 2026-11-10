package auth

import (
	"context"
	"fmt"
	"net/http"
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

// The second factor (user-flow SIGN-2 and SIGN-9). It applies to every
// sign-in method: password, one-time code, magic link, social. No path
// skips it.

var (
	errSignInExpired  = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "signin_expired", "please sign in again")
	errWrongCode      = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "wrong_code", "the code is wrong")
	errNoFactor       = errors.Conflict("no_second_factor", "no authenticator app is set up")
	errFactorRequired = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "second_factor_required", "this application requires a second factor. it cannot be removed")
	errSetupRequired  = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "second_factor_setup_required", "set up a second factor to continue")
	errNotEnrolling   = errors.Conflict("totp_not_started", "ask for a new authenticator secret first")
)

// primary is what a first factor proved, before the second is asked for.
type primary struct {
	principalID string
	method      string
	kind        string // session kind wanted: browser or token
	at          time.Time
}

// finishPrimary ends a successful first factor. It either asks for the
// second factor, with a pending token and no session, or starts the
// session.
func (m *authModule) finishPrimary(ctx context.Context, tx pgx.Tx, t *model.Tenant, p primary, meta model.RequestMeta) (*response.AuthResponse, error) {
	// An address bound to a company's identity provider may not sign in
	// any other way (ENT-6), except the break-glass owner.
	if p.method != constant.MethodEnterprise && m.enterprise != nil {
		if user, err := m.repo.GetUser(ctx, tx, t.ID, p.principalID); err == nil && user != nil && user.Email != "" {
			conn, err := m.enterprise.ConnectionForDomain(ctx, tx, t.ID, core.EmailDomain(user.Email))
			if err != nil {
				return nil, err
			}
			if conn != nil {
				policies, err := m.orgs.GetPolicies(ctx, tx, t.ID, conn.OrganizationID)
				if err != nil {
					return nil, err
				}
				if policies != nil && policies.EnforceSSO && policies.BreakGlassPrincipalID != p.principalID {
					if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
						Action: "signin.failed", Result: model.AuditDenied, ReasonCode: "sso_required", ActorID: p.principalID,
						OrganizationID: conn.OrganizationID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
					}); err != nil {
						return nil, err
					}
					return nil, errSSORequired
				}
				if policies != nil && policies.BreakGlassPrincipalID == p.principalID && policies.EnforceSSO {
					if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
						Action: "signin.break_glass", Result: model.AuditSuccess, ActorID: p.principalID, OrganizationID: conn.OrganizationID,
						RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
					}); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	factors, err := m.factors(ctx, tx, t, p.principalID)
	if err != nil {
		return nil, err
	}
	var methods []string
	if factors.TOTP {
		methods = append(methods, constant.MethodTOTP)
		if factors.RecoveryCodesLeft > 0 {
			methods = append(methods, constant.MethodRecoveryCode)
		}
	}
	if factors.Passkeys > 0 {
		methods = append(methods, constant.MethodPasskey)
	}
	if len(methods) > 0 {
		raw := secret.Token(32)
		if _, err := m.repo.CreateChallenge(ctx, tx, t.ID, model.NewChallenge{
			Kind: constant.ChallengePendingSignIn, PrincipalID: p.principalID, TokenHash: secret.Hash(raw),
			Data:      map[string]any{"method": p.method, "kind": p.kind, "at": p.at.Format(time.RFC3339Nano)},
			ExpiresAt: p.at.Add(constant.PendingSignInTTL),
		}); err != nil {
			return nil, err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "signin.second_factor_needed", Result: model.AuditSuccess, ActorID: p.principalID,
			Data: map[string]any{"method": p.method}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return nil, err
		}
		return &response.AuthResponse{SecondFactorRequired: true, PendingToken: raw, Methods: methods}, nil
	}
	out, err := m.startSessionWith(ctx, tx, t, p.principalID, p.kind, []model.AuthMethod{{Method: p.method, At: p.at}}, nil, meta, p.at)
	if err != nil {
		return nil, err
	}
	// The application wants a second factor and this person has none yet.
	if t.MFAPolicy == constant.MFARequired && factors.Passkeys == 0 {
		out.SecondFactorSetupRequired = true
	}
	return out, nil
}

func (m *authModule) factors(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID string) (model.Factors, error) {
	var f model.Factors
	totp, err := m.repo.GetTOTP(ctx, tx, t.ID, principalID)
	if err != nil {
		return f, err
	}
	f.TOTP = totp != nil && totp.Confirmed
	if f.Passkeys, err = m.repo.CountPasskeys(ctx, tx, t.ID, principalID); err != nil {
		return f, err
	}
	if f.RecoveryCodesLeft, err = m.repo.CountRecoveryCodes(ctx, tx, t.ID, principalID); err != nil {
		return f, err
	}
	return f, nil
}

// SecondFactor completes a pending sign-in.
func (m *authModule) SecondFactor(ctx context.Context, t *model.Tenant, req request.SecondFactorRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthResponse
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.repo.LockChallengeByToken(ctx, tx, t.ID, constant.ChallengePendingSignIn, secret.Hash(req.PendingToken))
		if err != nil {
			return err
		}
		// Unknown, used and expired all read the same.
		if c == nil || c.ConsumedAt != nil || !now.Before(c.ExpiresAt) {
			return errSignInExpired
		}
		attempts, err := m.repo.BumpChallengeAttempts(ctx, tx, t.ID, c.ID)
		if err != nil {
			return err
		}
		if attempts > constant.SecondFactorMaxAttempts {
			// Too many wrong codes cancel the sign-in. Start again from the password.
			if err := m.repo.ConsumeChallenge(ctx, tx, t.ID, c.ID, now); err != nil {
				return err
			}
			return errSignInExpired
		}
		var ok bool
		if req.Method == constant.MethodPasskey {
			ok, err = m.verifyPasskeyFactor(ctx, tx, t, c.PrincipalID, req.ChallengeID, req.Credential, now)
		} else {
			ok, err = m.verifyFactor(ctx, tx, t, c.PrincipalID, req.Method, req.Code, now, meta)
		}
		if err != nil {
			return err
		}
		if !ok {
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "second_factor.failed", Result: model.AuditFailure, ActorID: c.PrincipalID,
				Data: map[string]any{"method": req.Method, "attempt": attempts}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})
		}
		if err := m.repo.ConsumeChallenge(ctx, tx, t.ID, c.ID, now); err != nil {
			return err
		}
		first, _ := c.Data["method"].(string)
		kind, _ := c.Data["kind"].(string)
		at := now
		if s, _ := c.Data["at"].(string); s != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
				at = parsed
			}
		}
		methods := []model.AuthMethod{{Method: first, At: at}, {Method: req.Method, At: now}}
		out, err = m.startSessionWith(ctx, tx, t, c.PrincipalID, kind, methods, &now, meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("second factor", err)
	}
	if out == nil {
		// The code was wrong, and that was recorded.
		return nil, errWrongCode
	}
	m.notify.Wake()
	return out, nil
}

// verifyFactor checks a code against what the person has set up. A used
// recovery code is spent here. A wrong code is false, not an error.
func (m *authModule) verifyFactor(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method, code string, now time.Time, meta model.RequestMeta) (bool, error) {
	switch method {
	case constant.MethodTOTP:
		factor, err := m.repo.GetTOTP(ctx, tx, t.ID, principalID)
		if err != nil {
			return false, err
		}
		if factor == nil || !factor.Confirmed {
			return false, nil
		}
		plain, err := m.totpSecret(ctx, tx, t, principalID, factor)
		if err != nil {
			return false, err
		}
		step, ok := core.VerifyTOTP(plain, code, now, factor.LastUsedStep)
		if !ok {
			return false, nil
		}
		return true, m.repo.SetTOTPLastStep(ctx, tx, t.ID, factor.ID, step)
	case constant.MethodRecoveryCode:
		used, err := m.repo.UseRecoveryCode(ctx, tx, t.ID, principalID, secret.Hash(core.NormalizeRecoveryCode(code)), now)
		if err != nil || !used {
			return false, err
		}
		left, err := m.repo.CountRecoveryCodes(ctx, tx, t.ID, principalID)
		if err != nil {
			return false, err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "recovery_code.used", Result: model.AuditSuccess, ActorID: principalID,
			Data: map[string]any{"left": left}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return false, err
		}
		if u, err := m.repo.GetUser(ctx, tx, t.ID, principalID); err == nil && u != nil {
			if err := m.notify.Enqueue(ctx, tx, t, model.Message{
				Channel: constant.ChannelEmail, Recipient: u.Email, Template: constant.TemplateRecoveryCodeUsed,
				Data: map[string]string{"left": fmt.Sprint(left)},
			}); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	return false, nil
}

func (m *authModule) totpSecret(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID string, f *model.TOTPFactor) ([]byte, error) {
	key, err := m.keys.DataKeyByID(ctx, tx, t.ID, f.DataKeyID)
	if err != nil {
		return nil, err
	}
	return secret.Open(key, f.SecretEncrypted, totpContext(t.ID, principalID))
}

func totpContext(tenantID, principalID string) []byte {
	return []byte("totp:" + tenantID + ":" + principalID)
}

// ---------------------------------------------------------------------
// Setting a second factor up, and taking it down
// ---------------------------------------------------------------------

func (m *authModule) Factors(ctx context.Context, t *model.Tenant, sessionToken string) (*response.Factors, error) {
	now := m.now()
	var out *response.Factors
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		f, err := m.factors(ctx, tx, t, session.PrincipalID)
		if err != nil {
			return err
		}
		out = &response.Factors{
			TOTP: f.TOTP, Passkeys: f.Passkeys, RecoveryCodesLeft: f.RecoveryCodesLeft,
			SecondFactorAt: session.SecondFactorAt, Required: t.MFAPolicy == constant.MFARequired,
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("factors", err)
	}
	return out, nil
}

func (m *authModule) EnrollTOTP(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) (*response.TOTPEnrollment, error) {
	now := m.now()
	plain, err := core.NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	var out *response.TOTPEnrollment
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.ErrUnauthorized // a guest has no account to protect
		}
		keyID, key, err := m.keys.DataKey(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		sealed, err := secret.Seal(key, plain, totpContext(t.ID, session.PrincipalID))
		if err != nil {
			return err
		}
		if _, err := m.repo.CreateTOTP(ctx, tx, t.ID, session.PrincipalID, sealed, keyID); err != nil {
			return err
		}
		out = &response.TOTPEnrollment{Secret: core.EncodeTOTPSecret(plain), URI: core.TOTPURI(t.Name, user.Email, plain)}
		return nil
	})
	if err != nil {
		return nil, passThrough("enroll totp", err)
	}
	return out, nil
}

func (m *authModule) ConfirmTOTP(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) (*response.RecoveryCodes, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	codes, err := core.NewRecoveryCodes(constant.RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, secret.Hash(core.NormalizeRecoveryCode(c)))
	}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		if err := m.limitFactor(ctx, tx, t, session.PrincipalID, now); err != nil {
			return err
		}
		factor, err := m.repo.GetTOTP(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		if factor == nil || factor.Confirmed {
			return errNotEnrolling
		}
		plain, err := m.totpSecret(ctx, tx, t, session.PrincipalID, factor)
		if err != nil {
			return err
		}
		step, ok := core.VerifyTOTP(plain, req.Code, now, 0)
		if !ok {
			return errWrongCode
		}
		if err := m.repo.ConfirmTOTP(ctx, tx, t.ID, factor.ID, now); err != nil {
			return err
		}
		if err := m.repo.SetTOTPLastStep(ctx, tx, t.ID, factor.ID, step); err != nil {
			return err
		}
		if err := m.repo.ReplaceRecoveryCodes(ctx, tx, t.ID, session.PrincipalID, hashes); err != nil {
			return err
		}
		// Confirming counts as giving the factor: the session is fresh.
		if err := m.repo.SetSecondFactorAt(ctx, tx, t.ID, session.ID, constant.MethodTOTP, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "second_factor.enabled", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "user", TargetID: session.PrincipalID, Data: map[string]any{"method": constant.MethodTOTP},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if u, err := m.repo.GetUser(ctx, tx, t.ID, session.PrincipalID); err == nil && u != nil {
			if err := m.notify.Enqueue(ctx, tx, t, model.Message{
				Channel: constant.ChannelEmail, Recipient: u.Email, Template: constant.TemplateSecondFactorEnabled,
			}); err != nil {
				return err
			}
		}
		return m.notify.Emit(ctx, tx, t.ID, "user.second_factor_enabled", map[string]any{"user_id": session.PrincipalID, "method": constant.MethodTOTP})
	})
	if err != nil {
		return nil, passThrough("confirm totp", err)
	}
	m.notify.Wake()
	return &response.RecoveryCodes{Codes: codes}, nil
}

// limitFactor bounds how often codes may be tried against an account
// outside a pending sign-in.
func (m *authModule) limitFactor(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID string, now time.Time) error {
	state, err := m.repo.HitRateLimit(ctx, tx, t.ID, constant.BucketSecondFactor, core.LimitKey(principalID), now, constant.SecondFactorLimitWindow)
	if err != nil {
		return err
	}
	if state.Count > constant.SecondFactorLimitPerWindow {
		return errors.ErrRateLimited
	}
	return nil
}

// requireFactor checks a code against the person's confirmed factor, for
// a sensitive change. It returns the session.
func (m *authModule) requireFactor(ctx context.Context, tx pgx.Tx, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, now time.Time, meta model.RequestMeta) (*model.Session, error) {
	session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
	if err != nil {
		return nil, err
	}
	if err := m.limitFactor(ctx, tx, t, session.PrincipalID, now); err != nil {
		return nil, err
	}
	factor, err := m.repo.GetTOTP(ctx, tx, t.ID, session.PrincipalID)
	if err != nil {
		return nil, err
	}
	if factor == nil || !factor.Confirmed {
		return nil, errNoFactor
	}
	ok, err := m.verifyFactor(ctx, tx, t, session.PrincipalID, req.Method, req.Code, now, meta)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errWrongCode
	}
	return session, nil
}

func (m *authModule) DisableTOTP(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if t.MFAPolicy == constant.MFARequired {
		return errFactorRequired
	}
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.requireFactor(ctx, tx, t, sessionToken, req, now, meta)
		if err != nil {
			return err
		}
		return m.removeFactors(ctx, tx, t, session.PrincipalID, session.ID, "", meta)
	})
	if err != nil {
		return passThrough("disable totp", err)
	}
	m.notify.Wake()
	return nil
}

// removeFactors takes every second factor away. by is empty for the
// person themselves, or names the admin.
func (m *authModule) removeFactors(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, sessionID, by string, meta model.RequestMeta) error {
	if err := m.repo.DeleteTOTP(ctx, tx, t.ID, principalID); err != nil {
		return err
	}
	if err := m.repo.ReplaceRecoveryCodes(ctx, tx, t.ID, principalID, nil); err != nil {
		return err
	}
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "second_factor.disabled", Result: model.AuditSuccess, ActorID: principalID, SessionID: sessionID,
		TargetType: "user", TargetID: principalID, Data: map[string]any{"by": by},
		RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return err
	}
	if u, err := m.repo.GetUser(ctx, tx, t.ID, principalID); err == nil && u != nil {
		data := map[string]string{}
		if by != "" {
			data["by_admin"] = "yes"
		}
		if err := m.notify.Enqueue(ctx, tx, t, model.Message{
			Channel: constant.ChannelEmail, Recipient: u.Email, Template: constant.TemplateSecondFactorDisabled, Data: data,
		}); err != nil {
			return err
		}
	}
	return m.notify.Emit(ctx, tx, t.ID, "user.second_factor_disabled", map[string]any{"user_id": principalID})
}

func (m *authModule) RegenerateRecoveryCodes(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) (*response.RecoveryCodes, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	codes, err := core.NewRecoveryCodes(constant.RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, secret.Hash(core.NormalizeRecoveryCode(c)))
	}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.requireFactor(ctx, tx, t, sessionToken, req, now, meta)
		if err != nil {
			return err
		}
		if err := m.repo.ReplaceRecoveryCodes(ctx, tx, t.ID, session.PrincipalID, hashes); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "recovery_codes.regenerated", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "user", TargetID: session.PrincipalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return nil, passThrough("regenerate recovery codes", err)
	}
	m.notify.Wake()
	return &response.RecoveryCodes{Codes: codes}, nil
}

// StepUp refreshes the session's second factor for a sensitive action.
func (m *authModule) StepUp(ctx context.Context, t *model.Tenant, sessionToken string, req request.FactorCodeRequest, meta model.RequestMeta) (*response.StepUpResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.requireFactor(ctx, tx, t, sessionToken, req, now, meta)
		if err != nil {
			return err
		}
		if err := m.repo.SetSecondFactorAt(ctx, tx, t.ID, session.ID, req.Method, now); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "step_up.succeeded", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			Data: map[string]any{"method": req.Method}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	if err != nil {
		return nil, passThrough("step up", err)
	}
	m.notify.Wake()
	return &response.StepUpResponse{SecondFactorAt: now}, nil
}

func (m *authModule) ResetSecondFactor(ctx context.Context, t *model.Tenant, principalID string, meta model.RequestMeta) error {
	if err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.NotFound("user")
		}
		// Every session goes with it: whoever holds one must prove
		// themselves again, with the new factor once there is one.
		if _, err := m.repo.RevokeAllSessions(ctx, tx, t.ID, principalID, "second factor reset", m.now()); err != nil {
			return err
		}
		return m.removeFactors(ctx, tx, t, principalID, "", "admin", meta)
	}); err != nil {
		return passThrough("reset second factor", err)
	}
	m.notify.Wake()
	return nil
}

// FinishExternalSignIn ends a sign-in through a company identity
// provider (ENT-3 step 7 and 8).
func (m *authModule) FinishExternalSignIn(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, method, kind string, secondFactorAt *time.Time, activeOrg string, meta model.RequestMeta) (*response.AuthResponse, error) {
	now := m.now()
	if err := m.count(ctx, tx, t.ID, constant.MetricSignIns); err != nil {
		return nil, err
	}
	var out *response.AuthResponse
	var err error
	if secondFactorAt != nil {
		out, err = m.startSessionWith(ctx, tx, t, principalID, kind, []model.AuthMethod{{Method: method, At: now}}, secondFactorAt, meta, now)
	} else {
		out, err = m.finishPrimary(ctx, tx, t, primary{principalID: principalID, method: method, kind: kind, at: now}, meta)
	}
	if err != nil {
		return nil, err
	}
	if out.SecondFactorRequired || activeOrg == "" {
		return out, nil
	}
	if err := m.repo.SetActiveResource(ctx, tx, t.ID, out.Session.ID, activeOrg); err != nil {
		return nil, err
	}
	// The organization's session length applies (ENT-7).
	if policies, err := m.orgs.GetPolicies(ctx, tx, t.ID, activeOrg); err == nil && policies != nil && policies.SessionMaxSeconds > 0 {
		cap := now.Add(time.Duration(policies.SessionMaxSeconds) * time.Second)
		if cap.Before(out.Session.ExpiresAt) {
			if err := m.repo.CapSession(ctx, tx, t.ID, out.Session.ID, cap); err != nil {
				return nil, err
			}
			out.Session.ExpiresAt = cap
		}
	}
	out.Session.ActiveOrganizationID = activeOrg
	return out, nil
}
