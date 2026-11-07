package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/constant/errors"
	"github.com/flash-softeware/aos/internal/constant/model"
	"github.com/flash-softeware/aos/internal/module/auth/core"
	"github.com/flash-softeware/aos/platform/oidc"
	"github.com/flash-softeware/aos/platform/secret"
)

// Social sign-in (user-flow REG-5 and SIGN-5) through OpenID Connect.
// The engine makes a state, a nonce and a PKCE verifier; the browser goes
// to the provider and comes back with a code; the engine exchanges it and
// checks the identity token. Then the account is found, linked or made.

var (
	errProviderUnknown  = errors.New(errors.ErrorTypeNotFound, http.StatusNotFound, "provider_not_found", "this sign-in provider is not set up")
	errSocialFailed     = errors.New(errors.ErrorTypeUnauthorized, http.StatusUnauthorized, "social_failed", "the sign-in with the provider did not complete. try again")
	errLinkFirst        = errors.Conflict("account_exists_unverified", "an account with this address exists, but the provider did not confirm the address. sign in to that account and link the provider from your profile")
	errAlreadyLinked    = errors.Conflict("identity_taken", "this provider account is already linked to another user")
	errRedirectNotOwned = errors.Validation(map[string]string{"redirect_uri": "must be on one of the application's allowed origins"})
)

func (m *authModule) providerSecret(ctx context.Context, tx pgx.Tx, t *model.Tenant, p *model.OAuthProvider) (string, error) {
	key, err := m.keys.DataKeyByID(ctx, tx, t.ID, p.DataKeyID)
	if err != nil {
		return "", err
	}
	plain, err := secret.Open(key, p.SecretEncrypted, providerContext(t.ID, p.Provider))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func providerContext(tenantID, provider string) []byte {
	return []byte("oauth_provider:" + tenantID + ":" + provider)
}

// ---------------------------------------------------------------------
// Setting providers up (backend door)
// ---------------------------------------------------------------------

func (m *authModule) PutOAuthProvider(ctx context.Context, t *model.Tenant, req request.PutOAuthProviderRequest, meta model.RequestMeta) (*response.OAuthProvider, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	// The issuer must answer before it is saved, so a typo shows now.
	if _, err := m.oidc.Discover(ctx, req.Issuer); err != nil {
		return nil, errors.Validation(map[string]string{"issuer": "could not be reached: " + err.Error()})
	}
	enabled := req.Enabled == nil || *req.Enabled
	var out *response.OAuthProvider
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		keyID, key, err := m.keys.DataKey(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		sealed, err := secret.Seal(key, []byte(req.ClientSecret), providerContext(t.ID, req.Provider))
		if err != nil {
			return err
		}
		if _, err := m.repo.UpsertOAuthProvider(ctx, tx, t.ID, model.OAuthProvider{
			Provider: req.Provider, ClientID: req.ClientID, SecretEncrypted: sealed, DataKeyID: keyID,
			Issuer: req.Issuer, Scopes: req.Scopes, Enabled: enabled,
		}); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth_provider.saved", Result: model.AuditSuccess, TargetType: "oauth_provider", TargetID: req.Provider,
			Data: map[string]any{"enabled": enabled}, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		out = &response.OAuthProvider{Provider: req.Provider, ClientID: req.ClientID, Issuer: req.Issuer, Scopes: req.Scopes, Enabled: enabled, CreatedAt: m.now()}
		return nil
	})
	if err != nil {
		return nil, passThrough("put oauth provider", err)
	}
	return out, nil
}

func (m *authModule) ListOAuthProviders(ctx context.Context, t *model.Tenant) ([]response.OAuthProvider, error) {
	out := []response.OAuthProvider{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		list, err := m.repo.ListOAuthProviders(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		for _, p := range list {
			out = append(out, response.OAuthProvider{Provider: p.Provider, ClientID: p.ClientID, Issuer: p.Issuer, Scopes: p.Scopes, Enabled: p.Enabled, CreatedAt: p.CreatedAt})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list oauth providers", err)
	}
	return out, nil
}

func (m *authModule) DeleteOAuthProvider(ctx context.Context, t *model.Tenant, provider string, meta model.RequestMeta) error {
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		ok, err := m.repo.DeleteOAuthProvider(ctx, tx, t.ID, provider)
		if err != nil {
			return err
		}
		if !ok {
			return errProviderUnknown
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth_provider.removed", Result: model.AuditSuccess, TargetType: "oauth_provider", TargetID: provider, RequestID: meta.RequestID,
		})
	})
	return passThrough("delete oauth provider", err)
}

// ---------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------

// redirectAllowed checks that the provider sends the browser back to a
// page of the application, never to a stranger's site.
func (m *authModule) redirectAllowed(ctx context.Context, tx pgx.Tx, t *model.Tenant, redirectURI string) (bool, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false, nil
	}
	origin := u.Scheme + "://" + u.Host
	if t.AppURL != "" {
		if a, err := url.Parse(t.AppURL); err == nil && a.Scheme+"://"+a.Host == origin {
			return true, nil
		}
	}
	return m.tenants.IsAllowedOrigin(ctx, tx, t.ID, origin)
}

func (m *authModule) StartSocial(ctx context.Context, t *model.Tenant, provider, sessionToken string, req request.SocialStartRequest, meta model.RequestMeta) (*response.SocialStart, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	state := secret.Token(24)
	nonce := secret.Token(16)
	verifier, err := oidc.NewVerifier()
	if err != nil {
		return nil, err
	}
	var p *model.OAuthProvider
	principalID := ""
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		if p, err = m.repo.GetOAuthProvider(ctx, tx, t.ID, strings.ToLower(provider)); err != nil {
			return err
		}
		if p == nil || !p.Enabled {
			return errProviderUnknown
		}
		ok, err := m.redirectAllowed(ctx, tx, t, req.RedirectURI)
		if err != nil {
			return err
		}
		if !ok {
			return errRedirectNotOwned
		}
		// With a session this is a link, not a sign-in.
		if sessionToken != "" {
			session, err := m.authenticate(ctx, tx, t, sessionToken, now)
			if err != nil {
				return err
			}
			principalID = session.PrincipalID
		}
		_, err = m.repo.CreateChallenge(ctx, tx, t.ID, model.NewChallenge{
			Kind: constant.ChallengeOAuthState, PrincipalID: principalID, TokenHash: secret.Hash(state),
			Data:      map[string]any{"provider": p.Provider, "nonce": nonce, "verifier": verifier, "redirect_uri": req.RedirectURI, "kind": req.SessionKind},
			ExpiresAt: now.Add(constant.SocialCeremonyTTL),
		})
		return err
	})
	if err != nil {
		return nil, passThrough("start social sign-in", err)
	}
	discovered, err := m.oidc.Discover(ctx, p.Issuer)
	if err != nil {
		m.log.Error(ctx, "social provider unreachable", "provider", p.Provider, "error", err.Error())
		return nil, errSocialFailed
	}
	return &response.SocialStart{
		AuthorizationURL: oidc.AuthorizationURL(discovered, p.ClientID, req.RedirectURI, state, nonce, verifier, p.Scopes),
		State:            state,
	}, nil
}

func (m *authModule) FinishSocial(ctx context.Context, t *model.Tenant, provider string, req request.SocialFinishRequest, meta model.RequestMeta) (*response.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := m.limitAddress(ctx, t, meta); err != nil {
		return nil, err
	}
	now := m.now()
	provider = strings.ToLower(provider)

	// First the state is spent, so a code can be tried only once.
	var (
		c   *model.Challenge
		p   *model.OAuthProvider
		sec string
	)
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		var err error
		if c, err = m.repo.LockChallengeByToken(ctx, tx, t.ID, constant.ChallengeOAuthState, secret.Hash(req.State)); err != nil {
			return err
		}
		if c == nil || c.ConsumedAt != nil || !now.Before(c.ExpiresAt) || c.Data["provider"] != provider {
			return errSocialFailed
		}
		if err := m.repo.ConsumeChallenge(ctx, tx, t.ID, c.ID, now); err != nil {
			return err
		}
		if p, err = m.repo.GetOAuthProvider(ctx, tx, t.ID, provider); err != nil {
			return err
		}
		if p == nil || !p.Enabled {
			return errProviderUnknown
		}
		sec, err = m.providerSecret(ctx, tx, t, p)
		return err
	})
	if err != nil {
		return nil, passThrough("finish social sign-in", err)
	}

	// Then the provider is asked, outside any transaction.
	discovered, err := m.oidc.Discover(ctx, p.Issuer)
	if err != nil {
		return nil, errSocialFailed
	}
	nonce, _ := c.Data["nonce"].(string)
	verifier, _ := c.Data["verifier"].(string)
	redirectURI, _ := c.Data["redirect_uri"].(string)
	kind, _ := c.Data["kind"].(string)
	identity, err := m.oidc.Exchange(ctx, discovered, p.ClientID, sec, redirectURI, req.Code, verifier, nonce, now)
	if err != nil {
		m.log.Debug(ctx, "social sign-in refused", "provider", provider, "error", err.Error())
		return nil, errSocialFailed
	}

	// Finally the account.
	var out *response.AuthResponse
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if c.PrincipalID != "" {
			return m.linkIdentity(ctx, tx, t, c.PrincipalID, provider, identity, meta, now)
		}
		principalID, err := m.resolveIdentity(ctx, tx, t, provider, identity, meta, now)
		if err != nil {
			return err
		}
		out, err = m.signInWithoutPassword(ctx, tx, t, principalID, constant.MethodSocial, kind, meta, now)
		return err
	})
	if err != nil {
		return nil, passThrough("finish social sign-in", err)
	}
	m.notify.Wake()
	return out, nil
}

// resolveIdentity applies REG-5 step 5 and 6: an identity already linked
// signs its user in; otherwise the address decides whether an account is
// made, linked, or left alone.
func (m *authModule) resolveIdentity(ctx context.Context, tx pgx.Tx, t *model.Tenant, provider string, id *oidc.Identity, meta model.RequestMeta, now time.Time) (string, error) {
	linked, err := m.repo.FindExternalIdentity(ctx, tx, t.ID, provider, id.Subject)
	if err != nil {
		return "", err
	}
	if linked != nil {
		return linked.PrincipalID, m.repo.TouchExternalIdentity(ctx, tx, t.ID, linked.ID, now)
	}
	if id.Email == "" {
		return "", errSocialFailed // nothing to make an account from
	}
	existing, err := m.repo.FindUserByEmail(ctx, tx, t.ID, id.Email)
	if err != nil {
		return "", err
	}
	var principalID string
	switch {
	case existing == nil:
		// No local account: make one. Its address counts as verified
		// only when the provider says so.
		if t.Status == constant.TenantRestricted || t.SignupPolicy == constant.SignupInviteOnly {
			return "", errSocialFailed
		}
		if t.SignupPolicy == constant.SignupDomains && !core.EmailInDomains(id.Email, t.SignupDomains) {
			return "", errSocialFailed
		}
		if err := m.notify.Hook(ctx, t, constant.HookUserBeforeCreate, map[string]any{"email": id.Email, "name": id.Name, "provider": provider}); err != nil {
			return "", err
		}
		if err := m.withinLimit(ctx, tx, t.ID, constant.MetricUsers, func() (int64, error) { return m.repo.CountUsers(ctx, tx, t.ID) }); err != nil {
			return "", err
		}
		principalID, err = m.repo.CreateUser(ctx, tx, t.ID, id.Email, id.Name)
		if err != nil {
			return "", err
		}
		if err := m.count(ctx, tx, t.ID, constant.MetricSignUps); err != nil {
			return "", err
		}
		if id.EmailVerified {
			if err := m.repo.MarkEmailVerified(ctx, tx, t.ID, principalID, now); err != nil {
				return "", err
			}
			if t.DefaultRoleID != "" && t.RootResourceID != "" {
				if err := m.repo.GrantDefaultRole(ctx, tx, t.ID, principalID, t.DefaultRoleID, t.RootResourceID); err != nil {
					return "", err
				}
			}
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "user.created", Result: model.AuditSuccess, ReasonCode: "social:" + provider, ActorID: principalID,
			TargetType: "user", TargetID: principalID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return "", err
		}
		if err := m.notify.Emit(ctx, tx, t.ID, "user.created", map[string]any{"user_id": principalID, "by": "social", "provider": provider}); err != nil {
			return "", err
		}
	case existing.Status != constant.PrincipalActive:
		return "", errors.ErrAccountSuspended
	case !id.EmailVerified:
		// The provider does not vouch for the address. Nothing is linked.
		return "", errLinkFirst
	case !existing.EmailVerified:
		// Someone signed up with this address but never confirmed it.
		// The provider's word wins: their pending password is dropped.
		if err := m.repo.VoidTokens(ctx, tx, t.ID, existing.PrincipalID, constant.TokenEmailVerification, now); err != nil {
			return "", err
		}
		if err := m.repo.MarkEmailVerified(ctx, tx, t.ID, existing.PrincipalID, now); err != nil {
			return "", err
		}
		principalID = existing.PrincipalID
	default:
		principalID = existing.PrincipalID
	}
	return principalID, m.linkIdentity(ctx, tx, t, principalID, provider, id, meta, now)
}

func (m *authModule) linkIdentity(ctx context.Context, tx pgx.Tx, t *model.Tenant, principalID, provider string, id *oidc.Identity, meta model.RequestMeta, now time.Time) error {
	linked, err := m.repo.FindExternalIdentity(ctx, tx, t.ID, provider, id.Subject)
	if err != nil {
		return err
	}
	if linked != nil {
		if linked.PrincipalID != principalID {
			return errAlreadyLinked
		}
		return m.repo.TouchExternalIdentity(ctx, tx, t.ID, linked.ID, now)
	}
	profile := map[string]any{"name": id.Name, "issuer": id.Issuer}
	if _, err := m.repo.CreateExternalIdentity(ctx, tx, t.ID, model.ExternalIdentity{
		PrincipalID: principalID, Provider: provider, Subject: id.Subject, Email: id.Email, EmailVerified: id.EmailVerified,
	}, profile); err != nil {
		return err
	}
	if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "identity.linked", Result: model.AuditSuccess, ActorID: principalID, TargetType: "user", TargetID: principalID,
		Data: map[string]any{"provider": provider}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
	}); err != nil {
		return err
	}
	return m.notify.Emit(ctx, tx, t.ID, "user.identity_linked", map[string]any{"user_id": principalID, "provider": provider})
}

func (m *authModule) ListIdentities(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Identity, error) {
	now := m.now()
	out := []response.Identity{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		list, err := m.repo.ListExternalIdentities(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		for _, i := range list {
			out = append(out, response.Identity{Provider: i.Provider, Subject: i.Subject, Email: i.Email, LinkedAt: i.CreatedAt, LastSignInAt: i.LastSignInAt})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list identities", err)
	}
	return out, nil
}

func (m *authModule) UnlinkIdentity(ctx context.Context, t *model.Tenant, sessionToken, provider string, meta model.RequestMeta) error {
	now := m.now()
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		session, err := m.authenticate(ctx, tx, t, sessionToken, now)
		if err != nil {
			return err
		}
		// Nobody may lock themselves out: a password or another way in must remain.
		user, err := m.repo.GetUser(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.ErrUnauthorized
		}
		auth, err := m.repo.FindUserByEmail(ctx, tx, t.ID, user.Email)
		if err != nil {
			return err
		}
		others, err := m.repo.ListExternalIdentities(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		passkeys, err := m.repo.CountPasskeys(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		if (auth == nil || auth.PasswordHash == "") && passkeys == 0 && len(others) <= 1 {
			return errors.Conflict("last_way_in", "set a password or add a passkey before unlinking the last provider")
		}
		ok, err := m.repo.DeleteExternalIdentity(ctx, tx, t.ID, session.PrincipalID, strings.ToLower(provider))
		if err != nil {
			return err
		}
		if !ok {
			return errors.NotFound("identity")
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "identity.unlinked", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "user", TargetID: session.PrincipalID, Data: map[string]any{"provider": provider},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough("unlink identity", err)
}
