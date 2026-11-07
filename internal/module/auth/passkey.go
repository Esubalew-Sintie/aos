package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
)

// Passkeys (user-flow SIGN-3). A passkey is bound to the application's
// domain, taken from the tenant's address. The browser signs a challenge
// the engine issued; the engine checks the origin, the domain, the
// signature, that the device verified the user, and that the counter
// did not go backwards.

var (
	errPasskeysUnavailable = errors.Conflict("passkeys_unavailable", "set the application's address first. a passkey is bound to its domain")
	errPasskeyFailed       = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "passkey_failed", "the passkey could not be verified")
	errPasskeyCloned       = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "passkey_cloned", "this passkey may have been copied. it was refused. sign in another way and remove it")
	errLastFactor          = errors.New(errors.ErrorTypeForbidden, http.StatusForbidden, "second_factor_required", "this application requires a second factor. add another before removing this one")
)

// relyingParty builds the WebAuthn configuration from the tenant: the
// domain of its address, and the origins its pages are served from.
func (m *authModule) relyingParty(ctx context.Context, tx pgx.Tx, t *model.Tenant) (*webauthn.WebAuthn, error) {
	if t.AppURL == "" {
		return nil, errPasskeysUnavailable
	}
	u, err := url.Parse(t.AppURL)
	if err != nil || u.Hostname() == "" {
		return nil, errPasskeysUnavailable
	}
	origins, err := m.tenants.ListAllowedOrigins(ctx, tx, t.ID)
	if err != nil {
		return nil, err
	}
	origins = append(origins, u.Scheme+"://"+u.Host)
	rp, err := webauthn.New(&webauthn.Config{
		RPID: u.Hostname(), RPDisplayName: t.Name, RPOrigins: origins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: false, Timeout: constant.PasskeyCeremonyTTL, TimeoutUVD: constant.PasskeyCeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: false, Timeout: constant.PasskeyCeremonyTTL, TimeoutUVD: constant.PasskeyCeremonyTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return rp, nil
}

// passkeyUser is what the library sees of a person.
type passkeyUser struct {
	id          string
	name        string
	display     string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.display }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func toCredential(p model.Passkey) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
	for _, t := range p.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID: p.CredentialID, PublicKey: p.PublicKey, Transport: transports,
		Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: p.BackupEligible, BackupState: p.BackedUp},
		Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: uint32(p.SignCount)},
	}
}

func (m *authModule) passkeyUser(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID string) (*passkeyUser, []model.Passkey, error) {
	user, err := m.repo.GetUser(ctx, tx, t.ID, principalID)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, errors.ErrUnauthorized // a guest has no account to bind a passkey to
	}
	keys, err := m.repo.ListPasskeys(ctx, tx, t.ID, principalID)
	if err != nil {
		return nil, nil, err
	}
	pu := &passkeyUser{id: principalID, name: user.Email, display: user.Name}
	if pu.display == "" {
		pu.display = user.Email
	}
	for _, k := range keys {
		pu.credentials = append(pu.credentials, toCredential(k))
	}
	return pu, keys, nil
}

// storeCeremony keeps the library's session data until the browser answers.
func (m *authModule) storeCeremony(ctx context.Context, tx pgx.Tx, t *model.Tenant, kind, principalID string, session *webauthn.SessionData, now time.Time) (string, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	return m.repo.CreateChallenge(ctx, tx, t.ID, model.NewChallenge{
		Kind: kind, PrincipalID: principalID, Data: map[string]any{"session": json.RawMessage(raw)},
		ExpiresAt: now.Add(constant.PasskeyCeremonyTTL),
	})
}

// takeCeremony finds a live ceremony and spends it. Its session data
// comes back.
func (m *authModule) takeCeremony(ctx context.Context, tx pgx.Tx, t *model.Tenant, kind, id string, now time.Time) (*model.Challenge, *webauthn.SessionData, error) {
	c, err := m.repo.LockChallenge(ctx, tx, t.ID, id)
	if err != nil {
		return nil, nil, err
	}
	if c == nil || c.Kind != kind || c.ConsumedAt != nil || !now.Before(c.ExpiresAt) {
		return nil, nil, errPasskeyFailed
	}
	if err := m.repo.ConsumeChallenge(ctx, tx, t.ID, c.ID, now); err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(c.Data["session"])
	if err != nil {
		return nil, nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, nil, fmt.Errorf("passkey ceremony: %w", err)
	}
	return c, &session, nil
}

// ---------------------------------------------------------------------
// Adding and removing passkeys
// ---------------------------------------------------------------------

func (m *authModule) BeginPasskeyRegistration(ctx context.Context, t *model.Tenant, sessionToken string, meta model.RequestMeta) (*response.PasskeyChallenge, error) {
	now := m.now()
	var out *response.PasskeyChallenge
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		rp, err := m.relyingParty(ctx, tx, t)
		if err != nil {
			return err
		}
		user, keys, err := m.passkeyUser(ctx, tx, t, session.PrincipalID)
		if err != nil {
			return err
		}
		exclusions := make([]protocol.CredentialDescriptor, 0, len(keys))
		for _, k := range keys {
			exclusions = append(exclusions, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: k.CredentialID})
		}
		// A passkey must be discoverable, so sign-in needs no email, and
		// must verify the user, so it counts as two factors.
		creation, data, err := rp.BeginRegistration(user,
			webauthn.WithExclusions(exclusions),
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired,
			}),
		)
		if err != nil {
			return fmt.Errorf("begin passkey registration: %w", err)
		}
		id, err := m.storeCeremony(ctx, tx, t, constant.ChallengePasskeyRegistration, session.PrincipalID, data, now)
		if err != nil {
			return err
		}
		options, err := json.Marshal(creation)
		if err != nil {
			return err
		}
		out = &response.PasskeyChallenge{ChallengeID: id, Options: options}
		return nil
	})
	if err != nil {
		return nil, passThrough("begin passkey registration", err)
	}
	return out, nil
}

func (m *authModule) FinishPasskeyRegistration(ctx context.Context, t *model.Tenant, sessionToken string, req request.PasskeyFinishRequest, meta model.RequestMeta) (*response.Passkey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.Passkey
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		c, data, err := m.takeCeremony(ctx, tx, t, constant.ChallengePasskeyRegistration, req.ChallengeID, now)
		if err != nil {
			return err
		}
		if c.PrincipalID != session.PrincipalID {
			return errPasskeyFailed
		}
		rp, err := m.relyingParty(ctx, tx, t)
		if err != nil {
			return err
		}
		user, _, err := m.passkeyUser(ctx, tx, t, session.PrincipalID)
		if err != nil {
			return err
		}
		parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
		if err != nil {
			return errPasskeyFailed
		}
		cred, err := rp.CreateCredential(user, *data, parsed)
		if err != nil {
			m.log.Debug(ctx, "passkey registration refused", "error", err.Error())
			return errPasskeyFailed
		}
		if !cred.Flags.UserVerified {
			return errPasskeyFailed
		}
		transports := make([]string, 0, len(cred.Transport))
		for _, tr := range cred.Transport {
			transports = append(transports, string(tr))
		}
		name := req.Name
		if name == "" {
			name = "Passkey added " + now.UTC().Format("2 Jan 2006")
		}
		id, err := m.repo.CreatePasskey(ctx, tx, t.ID, model.Passkey{
			PrincipalID: session.PrincipalID, CredentialID: cred.ID, PublicKey: cred.PublicKey, SignCount: int64(cred.Authenticator.SignCount),
			Transports: transports, AAGUID: cred.Authenticator.AAGUID, BackupEligible: cred.Flags.BackupEligible, BackedUp: cred.Flags.BackupState, Name: name,
		})
		if err != nil {
			return err
		}
		// Adding a passkey proves possession and verification: the
		// session is fresh.
		if err := m.repo.SetSecondFactorAt(ctx, tx, t.ID, session.ID, constant.MethodPasskey, now); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "passkey.added", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "passkey", TargetID: id, Data: map[string]any{"name": name},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.passkey_added", map[string]any{"user_id": session.PrincipalID, "passkey_id": id}); err != nil {
			return err
		}
		out = &response.Passkey{ID: id, Name: name, Transports: transports, BackedUp: cred.Flags.BackupState, CreatedAt: now}
		return nil
	})
	if err != nil {
		return nil, passThrough("finish passkey registration", err)
	}
	m.notify.Wake()
	return out, nil
}

func (m *authModule) ListPasskeys(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Passkey, error) {
	now := m.now()
	out := []response.Passkey{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticateFor(ctx, tx, t, sessionToken, now, true)
		if err != nil {
			return err
		}
		keys, err := m.repo.ListPasskeys(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		for _, k := range keys {
			transports := k.Transports
			if transports == nil {
				transports = []string{}
			}
			out = append(out, response.Passkey{ID: k.ID, Name: k.Name, Transports: transports, BackedUp: k.BackedUp, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list passkeys", err)
	}
	return out, nil
}

func (m *authModule) DeletePasskey(ctx context.Context, t *model.Tenant, sessionToken, id string, meta model.RequestMeta) error {
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		if t.MFAPolicy == constant.MFARequired {
			f, err := m.factors(ctx, tx, t, session.PrincipalID)
			if err != nil {
				return err
			}
			if !f.TOTP && f.Passkeys <= 1 {
				return errLastFactor
			}
		}
		ok, err := m.repo.DeletePasskey(ctx, tx, t.ID, session.PrincipalID, id)
		if err != nil {
			return err
		}
		if !ok {
			return errors.NotFound("passkey")
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "passkey.removed", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "passkey", TargetID: id, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough("delete passkey", err)
}

// ---------------------------------------------------------------------
// Signing in with a passkey
// ---------------------------------------------------------------------

func (m *authModule) BeginPasskeySignIn(ctx context.Context, t *model.Tenant, meta model.RequestMeta) (*response.PasskeyChallenge, error) {
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.PasskeyChallenge
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		rp, err := m.relyingParty(ctx, tx, t)
		if err != nil {
			return err
		}
		// No email is typed: the browser offers the passkeys it holds.
		assertion, data, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return fmt.Errorf("begin passkey sign-in: %w", err)
		}
		id, err := m.storeCeremony(ctx, tx, t, constant.ChallengePasskeySignIn, "", data, now)
		if err != nil {
			return err
		}
		options, err := json.Marshal(assertion)
		if err != nil {
			return err
		}
		out = &response.PasskeyChallenge{ChallengeID: id, Options: options}
		return nil
	})
	if err != nil {
		return nil, passThrough("begin passkey sign-in", err)
	}
	return out, nil
}

// checkAssertion verifies the browser's answer to a sign-in challenge and
// returns the passkey that signed it, with its counter already updated.
func (m *authModule) checkAssertion(ctx context.Context, tx pgx.Tx, t *model.Tenant, challengeID string, credential json.RawMessage, now time.Time) (*model.Passkey, error) {
	_, data, err := m.takeCeremony(ctx, tx, t, constant.ChallengePasskeySignIn, challengeID, now)
	if err != nil {
		return nil, err
	}
	rp, err := m.relyingParty(ctx, tx, t)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return nil, errPasskeyFailed
	}
	var stored *model.Passkey
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		k, err := m.repo.FindPasskey(ctx, tx, t.ID, rawID)
		if err != nil {
			return nil, err
		}
		if k == nil || k.PrincipalID != string(userHandle) {
			return nil, fmt.Errorf("unknown passkey")
		}
		stored = k
		user, _, err := m.passkeyUser(ctx, tx, t, k.PrincipalID)
		return user, err
	}
	_, cred, err := rp.ValidatePasskeyLogin(lookup, *data, parsed)
	if err != nil {
		m.log.Debug(ctx, "passkey sign-in refused", "error", err.Error())
		return nil, errPasskeyFailed
	}
	if cred.Authenticator.CloneWarning {
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "passkey.clone_suspected", Result: model.AuditDenied, ActorID: stored.PrincipalID, TargetType: "passkey", TargetID: stored.ID,
		}); err != nil {
			return nil, err
		}
		return nil, errPasskeyCloned
	}
	if err := m.repo.UsePasskey(ctx, tx, t.ID, stored.ID, int64(cred.Authenticator.SignCount), cred.Flags.BackupState, now); err != nil {
		return nil, err
	}
	return stored, nil
}

func (m *authModule) FinishPasskeySignIn(ctx context.Context, t *model.Tenant, req request.PasskeyFinishRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthResponse
	var refusal error
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		key, err := m.checkAssertion(ctx, tx, t, req.ChallengeID, req.Credential, now)
		if err != nil {
			// The refusal, and anything written about it, must be kept.
			if _, ok := errors.AsAppError(err); ok {
				refusal = err
				return nil
			}
			return err
		}
		user, err := m.repo.GetUser(ctx, tx, t.ID, key.PrincipalID)
		if err != nil {
			return err
		}
		if user == nil || user.Status != constant.PrincipalActive {
			return errors.ErrAccountSuspended
		}
		if err := m.count(ctx, tx, t.ID, constant.MetricSignIns); err != nil {
			return err
		}
		// A verified passkey is two factors in one: something held, and a
		// fingerprint, face or PIN. No second step is asked for.
		out, err = m.startSessionWith(ctx, tx, t, key.PrincipalID, req.SessionKind,
			[]model.AuthMethod{{Method: constant.MethodPasskey, At: now}}, &now, meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("passkey sign-in", err)
	}
	if refusal != nil {
		return nil, refusal
	}
	m.notify.Wake()
	return out, nil
}

// verifyPasskeyFactor uses a passkey as the second factor of a pending
// sign-in. The passkey must belong to the person who gave the password.
func (m *authModule) verifyPasskeyFactor(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, challengeID string, credential json.RawMessage, now time.Time) (bool, error) {
	key, err := m.checkAssertion(ctx, tx, t, challengeID, credential, now)
	if err != nil {
		if _, ok := errors.AsAppError(err); ok {
			return false, nil
		}
		return false, err
	}
	return strings.EqualFold(key.PrincipalID, principalID), nil
}
