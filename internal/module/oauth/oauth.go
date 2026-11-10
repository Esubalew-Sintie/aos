// Package oauth makes the tenant an OAuth 2.1 and OpenID Connect
// provider (user-flow MACH-5 to MACH-7): other applications sign people
// in through it, machines prove themselves with a secret, devices without
// a browser get a code, and an agent exchanges a delegation for a token.
package oauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module"
	iamcore "github.com/flash-software-technology/aos/internal/module/iam/core"
	"github.com/flash-software-technology/aos/internal/storage"
	"github.com/flash-software-technology/aos/platform/jwt"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/oidc"
	"github.com/flash-software-technology/aos/platform/postgres"
	"github.com/flash-software-technology/aos/platform/secret"
)

type oauthModule struct {
	db        *postgres.DB
	repo      storage.OAuthRepository
	users     storage.AuthRepository
	machines  storage.MachineRepository
	iam       storage.IAMRepository
	audit     storage.AuditRepository
	notify    module.Notification
	auth      module.Auth
	keys      module.KeyRing
	tenants   module.Tenant
	fetch     *oidc.Client
	publicURL string
	now       func() time.Time
	log       logger.Logger
}

func NewOAuthModule(db *postgres.DB, repo storage.OAuthRepository, users storage.AuthRepository, machines storage.MachineRepository,
	iam storage.IAMRepository, audit storage.AuditRepository, notify module.Notification, auth module.Auth, keys module.KeyRing,
	tenants module.Tenant, fetch *oidc.Client, publicURL string, now func() time.Time, log logger.Logger) module.OAuthProvider {
	return &oauthModule{db: db, repo: repo, users: users, machines: machines, iam: iam, audit: audit, notify: notify, auth: auth,
		keys: keys, tenants: tenants, fetch: fetch, publicURL: strings.TrimRight(publicURL, "/"), now: now, log: log}
}

func oauthErr(status int, code, description string) *module.OAuthError {
	return &module.OAuthError{Status: status, Code: code, Description: description}
}

func fail(status int, code, description string) (int, map[string]any) {
	return status, map[string]any{"error": code, "error_description": description}
}

// ---------------------------------------------------------------------
// Clients (backend door)
// ---------------------------------------------------------------------

func (m *oauthModule) PutClient(ctx context.Context, t *model.Tenant, req request.PutOAuthClientRequest, meta model.RequestMeta) (*response.OAuthClient, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if req.ClientID == "" {
		req.ClientID = "c_" + secret.HexID(8)
	}
	var out *response.OAuthClient
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if req.ServicePrincipalID != "" {
			kind, err := m.iam.GetPrincipalKind(ctx, tx, t.ID, req.ServicePrincipalID)
			if err != nil {
				return err
			}
			if kind != constant.PrincipalKindService && kind != constant.PrincipalKindAgent {
				return errors.Validation(map[string]string{"service_principal_id": "must be a service account or an agent"})
			}
		}
		existing, err := m.repo.GetClientByClientID(ctx, tx, t.ID, req.ClientID)
		if err != nil {
			return err
		}
		c := model.OAuthClient{
			ClientID: req.ClientID, Name: req.Name, Description: req.Description, Kind: req.Kind,
			RedirectURIs: req.RedirectURIs, AllowedScopes: req.AllowedScopes, GrantTypes: req.GrantTypes, ServicePrincipalID: req.ServicePrincipalID,
		}
		plainSecret := ""
		if req.Kind == constant.ClientConfidential && (existing == nil || existing.SecretHash == nil || req.RotateSecret) {
			plainSecret = secret.Token(32)
			c.SecretHash = secret.Hash(plainSecret)
		}
		id, err := m.repo.UpsertClient(ctx, tx, t.ID, c)
		if err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth_client.saved", Result: model.AuditSuccess, TargetType: "oauth_client", TargetID: id,
			Data: map[string]any{"client_id": req.ClientID, "kind": req.Kind, "secret_rotated": plainSecret != ""}, RequestID: meta.RequestID,
		}); err != nil {
			return err
		}
		stored, err := m.repo.GetClient(ctx, tx, t.ID, id)
		if err != nil {
			return err
		}
		r := toClient(*stored)
		r.ClientSecret = plainSecret
		out = &r
		return nil
	})
	if err != nil {
		return nil, passThrough("put client", err)
	}
	return out, nil
}

func (m *oauthModule) ListClients(ctx context.Context, t *model.Tenant) ([]response.OAuthClient, error) {
	out := []response.OAuthClient{}
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		list, err := m.repo.ListClients(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		for _, c := range list {
			out = append(out, toClient(c))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	return out, nil
}

func (m *oauthModule) DisableClient(ctx context.Context, t *model.Tenant, id string, meta model.RequestMeta) error {
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		ok, err := m.repo.DisableClient(ctx, tx, t.ID, id, m.now())
		if err != nil {
			return err
		}
		if !ok {
			return errors.NotFound("client")
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth_client.disabled", Result: model.AuditSuccess, TargetType: "oauth_client", TargetID: id, RequestID: meta.RequestID,
		})
	})
	return passThrough("disable client", err)
}

// ---------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------

func (m *oauthModule) issuer(t *model.Tenant) string {
	return m.publicURL + "/t/" + t.Slug
}

func (m *oauthModule) Discovery(t *model.Tenant) map[string]any {
	base := m.issuer(t)
	return map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"jwks_uri":                              base + "/oauth/jwks.json",
		"device_authorization_endpoint":         base + "/oauth/device",
		"introspection_endpoint":                base + "/oauth/introspect",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{constant.GrantAuthorizationCode, constant.GrantRefreshToken, constant.GrantClientCredentials, constant.GrantDeviceCode, constant.GrantTokenExchange},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{constant.ScopeOpenID, constant.ScopeProfile, constant.ScopeEmail, constant.ScopeOfflineAccess},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "act"},
		"client_id_metadata_document_supported": true,
	}
}

// ---------------------------------------------------------------------
// The authorization request and the consent
// ---------------------------------------------------------------------

// client finds a registered client, or, for a client id that is an https
// address, fetches its Client ID Metadata Document (MACH-7).
func (m *oauthModule) client(ctx context.Context, tx pgx.Tx, t *model.Tenant, clientID string) (*model.OAuthClient, error) {
	c, err := m.repo.GetClientByClientID(ctx, tx, t.ID, clientID)
	if err != nil {
		return nil, err
	}
	if c != nil && c.Kind != constant.ClientMetadataDocument {
		if c.DisabledAt != nil {
			return nil, nil
		}
		return c, nil
	}
	if !strings.HasPrefix(clientID, "https://") && !(m.fetch.AllowPrivate && strings.HasPrefix(clientID, "http://")) {
		return nil, nil
	}
	doc, err := m.fetchClientMetadata(ctx, clientID)
	if err != nil {
		m.log.Debug(ctx, "client metadata document refused", "client_id", clientID, "error", err.Error())
		return nil, nil
	}
	id, err := m.repo.UpsertClient(ctx, tx, t.ID, model.OAuthClient{
		ClientID: clientID, Name: doc.Name, Kind: constant.ClientMetadataDocument, MetadataURL: clientID,
		RedirectURIs: doc.RedirectURIs, AllowedScopes: []string{}, GrantTypes: []string{constant.GrantAuthorizationCode, constant.GrantRefreshToken},
	})
	if err != nil {
		return nil, err
	}
	return m.repo.GetClient(ctx, tx, t.ID, id)
}

type clientMetadata struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
}

func (m *oauthModule) fetchClientMetadata(ctx context.Context, clientID string) (*clientMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.fetch.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("document answered %d", resp.StatusCode)
	}
	var doc clientMetadata
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<16)).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("the document names another client id")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("the document lists no redirect uri")
	}
	if doc.AuthMethod != "" && doc.AuthMethod != "none" {
		return nil, fmt.Errorf("a metadata client must use no client authentication")
	}
	if doc.Name == "" {
		doc.Name = clientID
	}
	return &doc, nil
}

func scopesAllowed(c *model.OAuthClient, scopes []string) bool {
	for _, s := range scopes {
		if constant.StandardScopes[s] {
			continue
		}
		if !iamcore.Covers(c.AllowedScopes, []string{s}) {
			return false
		}
	}
	return true
}

func hasGrant(c *model.OAuthClient, grant string) bool {
	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

func redirectAllowed(c *model.OAuthClient, uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

func withQuery(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (m *oauthModule) Authorize(ctx context.Context, t *model.Tenant, q map[string]string, meta model.RequestMeta) (string, error) {
	clientID, redirectURI, state := q["client_id"], q["redirect_uri"], q["state"]
	if clientID == "" || redirectURI == "" {
		return "", oauthErr(http.StatusBadRequest, "invalid_request", "client_id and redirect_uri are required")
	}
	if t.AppURL == "" {
		return "", oauthErr(http.StatusBadRequest, "server_error", "this application has no address for its sign-in page")
	}
	now := m.now()
	var redirect string
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.client(ctx, tx, t, clientID)
		if err != nil {
			return err
		}
		// Nothing is sent back to an address that is not the client's own.
		if c == nil {
			return oauthErr(http.StatusBadRequest, "invalid_client", "unknown client")
		}
		if !redirectAllowed(c, redirectURI) {
			return oauthErr(http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		}
		back := func(code, description string) {
			redirect = withQuery(redirectURI, map[string]string{"error": code, "error_description": description, "state": state})
		}
		if q["response_type"] != "code" {
			back("unsupported_response_type", "only code is supported")
			return nil
		}
		if !hasGrant(c, constant.GrantAuthorizationCode) {
			back("unauthorized_client", "this client may not use the authorization code grant")
			return nil
		}
		challenge := q["code_challenge"]
		if q["code_challenge_method"] != "S256" || len(challenge) < 43 {
			if c.Kind != constant.ClientConfidential || challenge != "" {
				back("invalid_request", "a code_challenge with method S256 is required")
				return nil
			}
		}
		scopes := strings.Fields(q["scope"])
		if !scopesAllowed(c, scopes) {
			back("invalid_scope", "a requested scope is not allowed for this client")
			return nil
		}
		id, err := m.users.CreateChallenge(ctx, tx, t.ID, model.NewChallenge{
			Kind: constant.ChallengeAuthorizationRequest,
			Data: map[string]any{
				"client": c.ID, "client_id": c.ClientID, "client_name": c.Name, "redirect_uri": redirectURI, "scope": strings.Join(scopes, " "),
				"state": state, "nonce": q["nonce"], "code_challenge": challenge, "resource": q["resource"],
			},
			ExpiresAt: now.Add(constant.AuthorizationRequestTTL),
		})
		if err != nil {
			return err
		}
		// The person signs in and consents on the application's own page.
		redirect = withQuery(strings.TrimRight(t.AppURL, "/")+"/auth/authorize", map[string]string{"request_id": id})
		return nil
	})
	if err != nil {
		if oe, ok := err.(*module.OAuthError); ok {
			return "", oe
		}
		return "", fmt.Errorf("authorize: %w", err)
	}
	return redirect, nil
}

func (m *oauthModule) requestView(c *model.Challenge) (string, []string, string) {
	str := func(k string) string { v, _ := c.Data[k].(string); return v }
	return str("client"), strings.Fields(str("scope")), str("resource")
}

func (m *oauthModule) GetAuthorizationRequest(ctx context.Context, t *model.Tenant, sessionToken, requestID string) (*response.AuthorizationRequestView, error) {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.AuthorizationRequestView
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.users.LockChallenge(ctx, tx, t.ID, requestID)
		if err != nil {
			return err
		}
		if c == nil || c.Kind != constant.ChallengeAuthorizationRequest || c.ConsumedAt != nil || !now.Before(c.ExpiresAt) {
			return errors.NotFound("authorization request")
		}
		clientUUID, scopes, resource := m.requestView(c)
		consent, err := m.repo.GetConsent(ctx, tx, t.ID, session.PrincipalID, clientUUID)
		if err != nil {
			return err
		}
		name, _ := c.Data["client_name"].(string)
		clientID, _ := c.Data["client_id"].(string)
		out = &response.AuthorizationRequestView{
			RequestID: c.ID, ClientName: name, ClientID: clientID, Scopes: scopes, Resource: resource, ExpiresAt: c.ExpiresAt,
			ConsentGiven: consent != nil && iamcore.Covers(consent.Scopes, scopes),
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("get authorization request", err)
	}
	return out, nil
}

func (m *oauthModule) Consent(ctx context.Context, t *model.Tenant, sessionToken string, req request.ConsentRequest, meta model.RequestMeta) (*response.ConsentResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	now := m.now()
	raw := secret.Token(32)
	var out *response.ConsentResult
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, err := m.users.LockChallenge(ctx, tx, t.ID, req.RequestID)
		if err != nil {
			return err
		}
		if c == nil || c.Kind != constant.ChallengeAuthorizationRequest || c.ConsumedAt != nil || !now.Before(c.ExpiresAt) {
			return errors.NotFound("authorization request")
		}
		if err := m.users.ConsumeChallenge(ctx, tx, t.ID, c.ID, now); err != nil {
			return err
		}
		str := func(k string) string { v, _ := c.Data[k].(string); return v }
		clientUUID, scopes, resource := m.requestView(c)
		redirectURI, state := str("redirect_uri"), str("state")
		if !req.Approve {
			out = &response.ConsentResult{RedirectTo: withQuery(redirectURI, map[string]string{"error": "access_denied", "state": state})}
			return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "oauth.consent_denied", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
				TargetType: "oauth_client", TargetID: clientUUID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			})
		}
		if err := m.repo.UpsertConsent(ctx, tx, t.ID, session.PrincipalID, clientUUID, scopes, now); err != nil {
			return err
		}
		if _, err := m.repo.CreateCode(ctx, tx, t.ID, secret.Hash(raw), model.AuthorizationCode{
			ClientID: clientUUID, PrincipalID: session.PrincipalID, RedirectURI: redirectURI, Scopes: scopes,
			CodeChallenge: str("code_challenge"), Resource: resource, Nonce: str("nonce"), ExpiresAt: now.Add(constant.AuthorizationCodeTTL),
		}); err != nil {
			return err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth.consent_given", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "oauth_client", TargetID: clientUUID, Data: map[string]any{"scopes": scopes}, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		out = &response.ConsentResult{RedirectTo: withQuery(redirectURI, map[string]string{"code": raw, "state": state, "iss": m.issuer(t)})}
		return nil
	})
	if err != nil {
		return nil, passThrough("consent", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// The token endpoint
// ---------------------------------------------------------------------

// authenticateClient finds the client behind a token request. A
// confidential client proves itself with its secret; a public one only
// names itself.
func (m *oauthModule) authenticateClient(ctx context.Context, tx pgx.Tx, t *model.Tenant, form map[string]string, basicUser, basicSecret string) (*model.OAuthClient, *module.OAuthError) {
	clientID, clientSecret := form["client_id"], form["client_secret"]
	if basicUser != "" {
		clientID, clientSecret = basicUser, basicSecret
	}
	if clientID == "" {
		return nil, oauthErr(http.StatusUnauthorized, "invalid_client", "client authentication is required")
	}
	c, err := m.client(ctx, tx, t, clientID)
	if err != nil || c == nil {
		return nil, oauthErr(http.StatusUnauthorized, "invalid_client", "unknown client")
	}
	if c.Kind == constant.ClientConfidential {
		if clientSecret == "" || !secret.Equal(secret.Hash(clientSecret), c.SecretHash) {
			return nil, oauthErr(http.StatusUnauthorized, "invalid_client", "wrong client secret")
		}
	}
	return c, nil
}

func (m *oauthModule) Token(ctx context.Context, t *model.Tenant, form map[string]string, basicUser, basicSecret string, meta model.RequestMeta) (int, map[string]any) {
	// The developer CLI renews its token session like a mobile app does.
	if form["grant_type"] == constant.GrantRefreshToken && form["client_id"] == constant.CLIClientID && basicUser == "" {
		out, err := m.auth.Refresh(ctx, t, request.RefreshRequest{RefreshToken: form["refresh_token"]}, meta)
		if err != nil {
			if appErr, ok := errors.AsAppError(err); ok {
				return fail(http.StatusBadRequest, "invalid_grant", appErr.Message)
			}
			m.log.Error(ctx, "cli refresh failed", "error", err.Error())
			return fail(http.StatusInternalServerError, "server_error", "unexpected error")
		}
		return http.StatusOK, map[string]any{"access_token": out.AccessToken, "refresh_token": out.RefreshToken, "token_type": "Bearer", "expires_in": out.ExpiresIn}
	}
	now := m.now()
	var body map[string]any
	status := http.StatusOK
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, oe := m.authenticateClient(ctx, tx, t, form, basicUser, basicSecret)
		if oe != nil {
			status, body = fail(oe.Status, oe.Code, oe.Description)
			return nil
		}
		grant := form["grant_type"]
		if !hasGrant(c, grant) && grant != constant.GrantRefreshToken {
			status, body = fail(http.StatusBadRequest, "unauthorized_client", "this client may not use "+grant)
			return nil
		}
		var err error
		switch grant {
		case constant.GrantAuthorizationCode:
			status, body, err = m.codeGrant(ctx, tx, t, c, form, now)
		case constant.GrantRefreshToken:
			status, body, err = m.refreshGrant(ctx, tx, t, c, form, now, meta)
		case constant.GrantClientCredentials:
			status, body, err = m.clientCredentialsGrant(ctx, tx, t, c, form, now)
		case constant.GrantDeviceCode:
			status, body, err = m.deviceGrant(ctx, tx, t, c, form, now)
		case constant.GrantTokenExchange:
			status, body, err = m.exchangeGrant(ctx, tx, t, c, form, now)
		default:
			status, body = fail(http.StatusBadRequest, "unsupported_grant_type", "unknown grant_type")
		}
		return err
	})
	if err != nil {
		m.log.Error(ctx, "token endpoint failed", "error", err.Error(), "request_id", meta.RequestID)
		return fail(http.StatusInternalServerError, "server_error", "unexpected error")
	}
	if status == http.StatusOK {
		m.notify.Wake()
	}
	return status, body
}

func (m *oauthModule) codeGrant(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.OAuthClient, form map[string]string, now time.Time) (int, map[string]any, error) {
	code, err := m.repo.LockCode(ctx, tx, t.ID, secret.Hash(form["code"]))
	if err != nil {
		return 0, nil, err
	}
	if code == nil || code.ClientID != c.ID || code.UsedAt != nil || !now.Before(code.ExpiresAt) || code.RedirectURI != form["redirect_uri"] {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the code is not valid for this client")
		return s, b, nil
	}
	if code.CodeChallenge != "" && oidc.Challenge(form["code_verifier"]) != code.CodeChallenge {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the code verifier does not match")
		return s, b, nil
	}
	if err := m.repo.MarkCodeUsed(ctx, tx, t.ID, code.ID, now); err != nil {
		return 0, nil, err
	}
	audience := code.Resource
	if audience == "" {
		audience = c.ClientID
	}
	familyID, err := m.repo.CreateClientTokenFamily(ctx, tx, t.ID, code.PrincipalID, c.ID, code.Scopes, audience)
	if err != nil {
		return 0, nil, err
	}
	body, err := m.issue(ctx, tx, t, c, code.PrincipalID, "", code.Scopes, audience, code.Nonce, familyID, now)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, body, m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "oauth.tokens_issued", Result: model.AuditSuccess, ActorID: code.PrincipalID, TargetType: "oauth_client", TargetID: c.ID,
		Data: map[string]any{"grant": constant.GrantAuthorizationCode, "scopes": code.Scopes, "audience": audience},
	})
}

func (m *oauthModule) refreshGrant(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.OAuthClient, form map[string]string, now time.Time, meta model.RequestMeta) (int, map[string]any, error) {
	rt, err := m.users.LockRefreshToken(ctx, tx, t.ID, secret.Hash(form["refresh_token"]))
	if err != nil {
		return 0, nil, err
	}
	if rt == nil || rt.ClientID != c.ID || rt.FamilyRevoked || !now.Before(rt.ExpiresAt) {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
		return s, b, nil
	}
	if rt.UsedAt != nil {
		// A copy exists. The whole family ends.
		if err := m.users.RevokeTokenFamily(ctx, tx, t.ID, rt.FamilyID, "reuse_detected", now); err != nil {
			return 0, nil, err
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "token.reuse_detected", Result: model.AuditDenied, ActorID: rt.PrincipalID, TargetType: "oauth_client", TargetID: c.ID,
			Data: map[string]any{"family_id": rt.FamilyID}, RequestID: meta.RequestID, IP: meta.IP,
		}); err != nil {
			return 0, nil, err
		}
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the refresh token was used twice. every token of this sign-in was revoked")
		return s, b, nil
	}
	status, err := m.iam.GetPrincipalStatus(ctx, tx, t.ID, rt.PrincipalID)
	if err != nil {
		return 0, nil, err
	}
	if status != constant.PrincipalActive {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the account is not active")
		return s, b, nil
	}
	if err := m.users.MarkRefreshTokenUsed(ctx, tx, t.ID, rt.ID, now); err != nil {
		return 0, nil, err
	}
	scopes := rt.Scopes
	if asked := strings.Fields(form["scope"]); len(asked) > 0 {
		if !iamcore.Covers(rt.Scopes, asked) {
			s, b := fail(http.StatusBadRequest, "invalid_scope", "a refresh may only narrow the scopes")
			return s, b, nil
		}
		scopes = asked
	}
	body, err := m.issue(ctx, tx, t, c, rt.PrincipalID, "", scopes, rt.Audience, "", rt.FamilyID, now)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, body, nil
}

func (m *oauthModule) clientCredentialsGrant(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.OAuthClient, form map[string]string, now time.Time) (int, map[string]any, error) {
	if c.Kind != constant.ClientConfidential || c.ServicePrincipalID == "" {
		s, b := fail(http.StatusBadRequest, "unauthorized_client", "client credentials need a confidential client with a service account")
		return s, b, nil
	}
	status, err := m.iam.GetPrincipalStatus(ctx, tx, t.ID, c.ServicePrincipalID)
	if err != nil {
		return 0, nil, err
	}
	if status != constant.PrincipalActive {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the service account is not active")
		return s, b, nil
	}
	scopes := strings.Fields(form["scope"])
	if !scopesAllowed(c, scopes) {
		s, b := fail(http.StatusBadRequest, "invalid_scope", "a requested scope is not allowed for this client")
		return s, b, nil
	}
	audience := form["resource"]
	if audience == "" {
		audience = c.ClientID
	}
	// No refresh token: a machine simply asks again.
	body, err := m.issue(ctx, tx, t, c, c.ServicePrincipalID, "", scopes, audience, "", "", now)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, body, nil
}

func (m *oauthModule) deviceGrant(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.OAuthClient, form map[string]string, now time.Time) (int, map[string]any, error) {
	d, err := m.repo.LockDeviceCode(ctx, tx, t.ID, secret.Hash(form["device_code"]))
	if err != nil {
		return 0, nil, err
	}
	if d == nil || d.ClientID != c.ID {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "unknown device code")
		return s, b, nil
	}
	if !now.Before(d.ExpiresAt) || d.Status == "expired" {
		s, b := fail(http.StatusBadRequest, "expired_token", "the device code has expired")
		return s, b, nil
	}
	if d.LastPolledAt != nil && now.Sub(*d.LastPolledAt) < time.Duration(constant.DeviceCodeInterval)*time.Second {
		s, b := fail(http.StatusBadRequest, "slow_down", "poll less often")
		return s, b, nil
	}
	if err := m.repo.TouchDeviceCode(ctx, tx, t.ID, d.ID, now); err != nil {
		return 0, nil, err
	}
	switch d.Status {
	case "pending":
		s, b := fail(http.StatusBadRequest, "authorization_pending", "the person has not approved yet")
		return s, b, nil
	case "denied":
		s, b := fail(http.StatusBadRequest, "access_denied", "the person declined")
		return s, b, nil
	case "used":
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the device code was already used")
		return s, b, nil
	}
	if err := m.repo.SetDeviceCodeStatus(ctx, tx, t.ID, d.ID, "used"); err != nil {
		return 0, nil, err
	}
	// The developer CLI gets a real token session: the routes a signed-in
	// person uses accept it, and it renews through the refresh grant.
	if c.ClientID == constant.CLIClientID {
		session, err := m.auth.StartTokenSession(ctx, tx, t, d.PrincipalID, "device", model.RequestMeta{})
		if err != nil {
			return 0, nil, err
		}
		pk, err := m.repo.PublishableKey(ctx, tx, t.ID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{
				"access_token": session.AccessToken, "refresh_token": session.RefreshToken, "token_type": "Bearer",
				"expires_in": session.ExpiresIn, "publishable_key": pk, "user_id": session.User.ID, "email": session.User.Email,
			}, m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
				Action: "cli.signed_in", Result: model.AuditSuccess, ActorID: d.PrincipalID, SessionID: session.Session.ID,
			})
	}
	familyID, err := m.repo.CreateClientTokenFamily(ctx, tx, t.ID, d.PrincipalID, c.ID, d.Scopes, c.ClientID)
	if err != nil {
		return 0, nil, err
	}
	body, err := m.issue(ctx, tx, t, c, d.PrincipalID, "", d.Scopes, c.ClientID, "", familyID, now)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, body, m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "oauth.tokens_issued", Result: model.AuditSuccess, ActorID: d.PrincipalID, TargetType: "oauth_client", TargetID: c.ID,
		Data: map[string]any{"grant": constant.GrantDeviceCode, "scopes": d.Scopes},
	})
}

// exchangeGrant (MACH-8): an agent's client turns a delegation into a
// token that acts for the user. The token names both.
func (m *oauthModule) exchangeGrant(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.OAuthClient, form map[string]string, now time.Time) (int, map[string]any, error) {
	if c.Kind != constant.ClientConfidential || c.ServicePrincipalID == "" {
		s, b := fail(http.StatusBadRequest, "unauthorized_client", "token exchange needs a confidential client with an agent")
		return s, b, nil
	}
	agent, err := m.machines.GetMachine(ctx, tx, t.ID, c.ServicePrincipalID)
	if err != nil {
		return 0, nil, err
	}
	if agent == nil || agent.Kind != constant.PrincipalKindAgent || agent.Status != constant.PrincipalActive {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "the client's principal is not an active agent")
		return s, b, nil
	}
	delegationID := form["delegation_id"]
	if !postgres.IsUUID(delegationID) {
		s, b := fail(http.StatusBadRequest, "invalid_request", "delegation_id is required")
		return s, b, nil
	}
	delegations, err := m.machines.ListDelegations(ctx, tx, t.ID, "", agent.ID)
	if err != nil {
		return 0, nil, err
	}
	var d *model.Delegation
	for i := range delegations {
		if delegations[i].ID == delegationID {
			d = &delegations[i]
		}
	}
	if d == nil || d.RevokedAt != nil || !now.Before(d.ExpiresAt) {
		s, b := fail(http.StatusBadRequest, "invalid_grant", "no live delegation with that id for this agent")
		return s, b, nil
	}
	scopes := d.Scopes
	if asked := strings.Fields(form["scope"]); len(asked) > 0 {
		if !iamcore.Covers(d.Scopes, asked) {
			s, b := fail(http.StatusBadRequest, "invalid_scope", "a requested scope is outside the delegation")
			return s, b, nil
		}
		scopes = asked
	}
	audience := form["resource"]
	if audience == "" {
		audience = c.ClientID
	}
	body, err := m.issue(ctx, tx, t, c, d.UserID, agent.ID, scopes, audience, "", "", now)
	if err != nil {
		return 0, nil, err
	}
	// The token ends with the delegation.
	if exp, ok := body["expires_in"].(int); ok && d.ExpiresAt.Before(now.Add(time.Duration(exp)*time.Second)) {
		body["expires_in"] = int(d.ExpiresAt.Sub(now).Seconds())
	}
	body["delegation_id"] = d.ID
	return http.StatusOK, body, m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
		Action: "oauth.tokens_issued", Result: model.AuditSuccess, ActorID: agent.ID, TargetType: "user", TargetID: d.UserID,
		Data: map[string]any{"grant": constant.GrantTokenExchange, "delegation_id": d.ID, "scopes": scopes},
	})
}

// issue signs the access token (and the identity token when asked), and
// adds a refresh token when the family exists.
func (m *oauthModule) issue(ctx context.Context, tx pgx.Tx, t *model.Tenant, c *model.OAuthClient, subject, actor string, scopes []string, audience, nonce, familyID string, now time.Time) (map[string]any, error) {
	kid, key, err := m.keys.SigningKey(ctx, tx, t.ID)
	if err != nil {
		return nil, err
	}
	exp := now.Add(constant.AccessTokenTTL)
	claims := map[string]any{
		"iss": m.issuer(t), "tid": t.ID, "sub": subject, "aud": audience, "client_id": c.ClientID, "typ": constant.OAuthTokenType,
		"scope": strings.Join(scopes, " "), "iat": now.Unix(), "exp": exp.Unix(), "jti": secret.HexID(8),
	}
	if actor != "" {
		claims["act"] = map[string]any{"sub": actor}
	}
	access, err := jwt.Sign(kid, key, claims)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(constant.AccessTokenTTL.Seconds()), "scope": strings.Join(scopes, " ")}
	if familyID != "" {
		refresh := secret.Token(32)
		if _, err := m.users.CreateRefreshToken(ctx, tx, t.ID, familyID, secret.Hash(refresh), now.Add(constant.RefreshTokenTTL)); err != nil {
			return nil, err
		}
		body["refresh_token"] = refresh
	}
	if hasScope(scopes, constant.ScopeOpenID) && actor == "" {
		id := map[string]any{"iss": m.issuer(t), "sub": subject, "aud": c.ClientID, "iat": now.Unix(), "exp": exp.Unix(), "auth_time": now.Unix()}
		if nonce != "" {
			id["nonce"] = nonce
		}
		if user, err := m.users.GetUser(ctx, tx, t.ID, subject); err == nil && user != nil {
			if hasScope(scopes, constant.ScopeEmail) {
				id["email"], id["email_verified"] = user.Email, user.EmailVerified
			}
			if hasScope(scopes, constant.ScopeProfile) && user.Name != "" {
				id["name"] = user.Name
			}
		}
		idToken, err := jwt.Sign(kid, key, id)
		if err != nil {
			return nil, err
		}
		body["id_token"] = idToken
	}
	return body, nil
}

func hasScope(scopes []string, s string) bool {
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------
// Devices (MACH-6)
// ---------------------------------------------------------------------

const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func newUserCode() string {
	raw := secret.Token(16)
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		sb.WriteByte(userCodeAlphabet[int(raw[i])%len(userCodeAlphabet)])
	}
	return sb.String()
}

func (m *oauthModule) DeviceAuthorization(ctx context.Context, t *model.Tenant, form map[string]string, meta model.RequestMeta) (int, map[string]any) {
	now := m.now()
	raw := secret.Token(32)
	var body map[string]any
	status := http.StatusOK
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, oe := m.authenticateClient(ctx, tx, t, form, "", "")
		if oe != nil {
			status, body = fail(oe.Status, oe.Code, oe.Description)
			return nil
		}
		if !hasGrant(c, constant.GrantDeviceCode) {
			status, body = fail(http.StatusBadRequest, "unauthorized_client", "this client may not use the device flow")
			return nil
		}
		scopes := strings.Fields(form["scope"])
		if !scopesAllowed(c, scopes) {
			status, body = fail(http.StatusBadRequest, "invalid_scope", "a requested scope is not allowed for this client")
			return nil
		}
		userCode := newUserCode()
		if _, err := m.repo.CreateDeviceCode(ctx, tx, t.ID, secret.Hash(raw), model.DeviceCode{
			ClientID: c.ID, UserCode: userCode, Scopes: scopes, ExpiresAt: now.Add(constant.DeviceCodeTTL),
		}); err != nil {
			return err
		}
		shown := userCode[:4] + "-" + userCode[4:]
		verify := strings.TrimRight(t.AppURL, "/") + "/auth/device"
		body = map[string]any{
			"device_code": raw, "user_code": shown, "verification_uri": verify,
			"verification_uri_complete": withQuery(verify, map[string]string{"user_code": shown}),
			"expires_in":                int(constant.DeviceCodeTTL.Seconds()), "interval": constant.DeviceCodeInterval,
		}
		return nil
	})
	if err != nil {
		m.log.Error(ctx, "device authorization failed", "error", err.Error(), "request_id", meta.RequestID)
		return fail(http.StatusInternalServerError, "server_error", "unexpected error")
	}
	return status, body
}

func (m *oauthModule) ApproveDevice(ctx context.Context, t *model.Tenant, sessionToken string, req request.DeviceApproveRequest, meta model.RequestMeta) (*response.DeviceApproval, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	now := m.now()
	var out *response.DeviceApproval
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		d, err := m.repo.LockDeviceCodeByUserCode(ctx, tx, t.ID, req.UserCode)
		if err != nil {
			return err
		}
		if d == nil || d.Status != "pending" || !now.Before(d.ExpiresAt) {
			return errors.NotFound("device code")
		}
		status := "denied"
		if req.Approve {
			status = "approved"
		}
		if err := m.repo.DecideDeviceCode(ctx, tx, t.ID, d.ID, session.PrincipalID, status); err != nil {
			return err
		}
		c, err := m.repo.GetClient(ctx, tx, t.ID, d.ClientID)
		if err != nil {
			return err
		}
		name := ""
		if c != nil {
			name = c.Name
		}
		if err := m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth.device_" + status, Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "oauth_client", TargetID: d.ClientID, Data: map[string]any{"scopes": d.Scopes},
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		}); err != nil {
			return err
		}
		out = &response.DeviceApproval{ClientName: name, Scopes: d.Scopes, Status: status}
		return nil
	})
	if err != nil {
		return nil, passThrough("approve device", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Using tokens: userinfo, introspection, revocation
// ---------------------------------------------------------------------

// verifyAccess checks an access token the engine issued as a provider.
func (m *oauthModule) verifyAccess(ctx context.Context, tx pgx.Tx, t *model.Tenant, token string, now time.Time) (map[string]any, bool) {
	var lookupErr error
	claims, err := jwt.Verify(token, now, func(kid string) ed25519.PublicKey {
		key, err := m.keys.PublicKey(ctx, tx, t.ID, kid)
		if err != nil {
			lookupErr = err
		}
		return key
	})
	if err != nil || lookupErr != nil || claims["typ"] != constant.OAuthTokenType || claims["tid"] != t.ID {
		return nil, false
	}
	return claims, true
}

func (m *oauthModule) UserInfo(ctx context.Context, t *model.Tenant, bearer string) (int, map[string]any) {
	now := m.now()
	var body map[string]any
	status := http.StatusOK
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		claims, ok := m.verifyAccess(ctx, tx, t, bearer, now)
		if !ok {
			status, body = fail(http.StatusUnauthorized, "invalid_token", "the access token is not valid")
			return nil
		}
		sub, _ := claims["sub"].(string)
		scopes := strings.Fields(fmt.Sprint(claims["scope"]))
		if !hasScope(scopes, constant.ScopeOpenID) {
			status, body = fail(http.StatusForbidden, "insufficient_scope", "the openid scope is needed")
			return nil
		}
		body = map[string]any{"sub": sub}
		user, err := m.users.GetUser(ctx, tx, t.ID, sub)
		if err != nil {
			return err
		}
		if user != nil {
			if hasScope(scopes, constant.ScopeEmail) {
				body["email"], body["email_verified"] = user.Email, user.EmailVerified
			}
			if hasScope(scopes, constant.ScopeProfile) && user.Name != "" {
				body["name"] = user.Name
			}
		}
		if act, ok := claims["act"]; ok {
			body["act"] = act
		}
		return nil
	})
	if err != nil {
		return fail(http.StatusInternalServerError, "server_error", "unexpected error")
	}
	return status, body
}

func (m *oauthModule) Introspect(ctx context.Context, t *model.Tenant, form map[string]string, basicUser, basicSecret string) (int, map[string]any) {
	now := m.now()
	var body map[string]any
	status := http.StatusOK
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		if _, oe := m.authenticateClient(ctx, tx, t, form, basicUser, basicSecret); oe != nil {
			status, body = fail(oe.Status, oe.Code, oe.Description)
			return nil
		}
		claims, ok := m.verifyAccess(ctx, tx, t, form["token"], now)
		if !ok {
			body = map[string]any{"active": false}
			return nil
		}
		sub, _ := claims["sub"].(string)
		pstatus, err := m.iam.GetPrincipalStatus(ctx, tx, t.ID, sub)
		if err != nil {
			return err
		}
		if pstatus != constant.PrincipalActive {
			body = map[string]any{"active": false}
			return nil
		}
		body = map[string]any{"active": true}
		for _, k := range []string{"sub", "aud", "client_id", "scope", "exp", "iat", "iss", "act", "jti"} {
			if v, ok := claims[k]; ok {
				body[k] = v
			}
		}
		body["token_type"] = "Bearer"
		return nil
	})
	if err != nil {
		return fail(http.StatusInternalServerError, "server_error", "unexpected error")
	}
	return status, body
}

func (m *oauthModule) Revoke(ctx context.Context, t *model.Tenant, form map[string]string, basicUser, basicSecret string, meta model.RequestMeta) (int, map[string]any) {
	now := m.now()
	var body map[string]any
	status := http.StatusOK
	err := m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		c, oe := m.authenticateClient(ctx, tx, t, form, basicUser, basicSecret)
		if oe != nil {
			status, body = fail(oe.Status, oe.Code, oe.Description)
			return nil
		}
		// Only a refresh token can be revoked by value; access tokens are
		// short-lived. Unknown tokens answer the same as revoked ones.
		rt, err := m.users.LockRefreshToken(ctx, tx, t.ID, secret.Hash(form["token"]))
		if err != nil {
			return err
		}
		if rt != nil && rt.ClientID == c.ID {
			if err := m.users.RevokeTokenFamily(ctx, tx, t.ID, rt.FamilyID, "revoked_by_client", now); err != nil {
				return err
			}
		}
		body = map[string]any{}
		return nil
	})
	if err != nil {
		return fail(http.StatusInternalServerError, "server_error", "unexpected error")
	}
	return status, body
}

// ---------------------------------------------------------------------
// Consents (the person's side)
// ---------------------------------------------------------------------

func (m *oauthModule) ListConsents(ctx context.Context, t *model.Tenant, sessionToken string) ([]response.Consent, error) {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return nil, err
	}
	out := []response.Consent{}
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		list, err := m.repo.ListConsents(ctx, tx, t.ID, session.PrincipalID)
		if err != nil {
			return err
		}
		for _, c := range list {
			out = append(out, response.Consent{ClientID: c.ClientID, ClientName: c.ClientName, ClientKey: c.ClientKey, Scopes: c.Scopes, GrantedAt: c.GrantedAt})
		}
		return nil
	})
	if err != nil {
		return nil, passThrough("list consents", err)
	}
	return out, nil
}

func (m *oauthModule) RevokeConsent(ctx context.Context, t *model.Tenant, sessionToken, clientID string, meta model.RequestMeta) error {
	session, err := m.auth.Authenticate(ctx, t, sessionToken)
	if err != nil {
		return err
	}
	now := m.now()
	err = m.db.Tenant(ctx, t.ID, func(tx pgx.Tx) error {
		ok, err := m.repo.RevokeConsent(ctx, tx, t.ID, session.PrincipalID, clientID, now)
		if err != nil {
			return err
		}
		if !ok {
			return errors.NotFound("consent")
		}
		// Withdrawing the consent ends that client's tokens.
		if err := m.repo.RevokeClientTokenFamilies(ctx, tx, t.ID, session.PrincipalID, clientID, "consent_withdrawn", now); err != nil {
			return err
		}
		return m.audit.Append(ctx, tx, t.ID, model.AuditEntry{
			Action: "oauth.consent_withdrawn", Result: model.AuditSuccess, ActorID: session.PrincipalID, SessionID: session.ID,
			TargetType: "oauth_client", TargetID: clientID, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		})
	})
	return passThrough("revoke consent", err)
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func toClient(c model.OAuthClient) response.OAuthClient {
	return response.OAuthClient{
		ID: c.ID, ClientID: c.ClientID, Name: c.Name, Description: c.Description, Kind: c.Kind, RedirectURIs: c.RedirectURIs,
		AllowedScopes: c.AllowedScopes, GrantTypes: c.GrantTypes, ServicePrincipalID: c.ServicePrincipalID, CreatedAt: c.CreatedAt, DisabledAt: c.DisabledAt,
	}
}

func passThrough(operation string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsAppError(err); ok {
		return err
	}
	return fmt.Errorf("%s: %w", operation, err)
}
