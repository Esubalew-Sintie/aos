// Package oauth serves the tenant as an OAuth and OpenID Connect
// provider. The public routes under /t/{slug} answer in the protocol's
// own JSON; the management and consent routes use the envelope.
package oauth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
	httputil "github.com/flash-softeware/aos/internal/handler/rest/http"
	"github.com/flash-softeware/aos/internal/module"
	"github.com/flash-softeware/aos/platform/logger"
)

type OAuthHandler struct {
	provider module.OAuthProvider
	tenants  module.Tenant
	logger   logger.Logger
}

func NewOAuthHandler(provider module.OAuthProvider, tenants module.Tenant, logger logger.Logger) rest.OAuthHandler {
	return &OAuthHandler{provider: provider, tenants: tenants, logger: logger}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// form reads a POSTed form into a map.
func form(r *http.Request) map[string]string {
	_ = r.ParseForm()
	out := map[string]string{}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func (h *OAuthHandler) answer(w http.ResponseWriter, r *http.Request, status int, message string, data any, err error) {
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, status, message, data, nil)
}

// ---- backend door ----

func (h *OAuthHandler) PutClient(w http.ResponseWriter, r *http.Request) {
	var req request.PutOAuthClientRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.provider.PutClient(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "client saved. a secret is shown only when it is made or rotated", res, err)
}

func (h *OAuthHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	res, err := h.provider.ListClients(r.Context(), middleware.TenantFrom(r.Context()))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *OAuthHandler) DisableClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.provider.DisableClient(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "client disabled", nil, err)
}

// ---- public door ----

func (h *OAuthHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.provider.Discovery(middleware.TenantFrom(r.Context())))
}

func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	res, err := h.tenants.JWKS(r.Context(), middleware.TenantFrom(r.Context()))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, res)
}

func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			q[k] = v[0]
		}
	}
	ctx := r.Context()
	redirect, err := h.provider.Authorize(ctx, middleware.TenantFrom(ctx), q, middleware.MetaFrom(ctx))
	if err != nil {
		if oe, ok := err.(*module.OAuthError); ok {
			writeJSON(w, oe.Status, map[string]any{"error": oe.Code, "error_description": oe.Description})
			return
		}
		h.logger.Error(ctx, "authorize failed", "error", err.Error(), "request_id", middleware.MetaFrom(ctx).RequestID)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	user, secret, _ := r.BasicAuth()
	ctx := r.Context()
	status, body := h.provider.Token(ctx, middleware.TenantFrom(ctx), form(r), user, secret, middleware.MetaFrom(ctx))
	writeJSON(w, status, body)
}

func (h *OAuthHandler) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, body := h.provider.DeviceAuthorization(ctx, middleware.TenantFrom(ctx), form(r), middleware.MetaFrom(ctx))
	writeJSON(w, status, body)
}

func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	status, body := h.provider.UserInfo(r.Context(), middleware.TenantFrom(r.Context()), bearer)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	writeJSON(w, status, body)
}

func (h *OAuthHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	user, secret, _ := r.BasicAuth()
	status, body := h.provider.Introspect(r.Context(), middleware.TenantFrom(r.Context()), form(r), user, secret)
	writeJSON(w, status, body)
}

func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	user, secret, _ := r.BasicAuth()
	ctx := r.Context()
	status, body := h.provider.Revoke(ctx, middleware.TenantFrom(ctx), form(r), user, secret, middleware.MetaFrom(ctx))
	writeJSON(w, status, body)
}

// ---- frontend door ----

func (h *OAuthHandler) GetAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.provider.GetAuthorizationRequest(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *OAuthHandler) Consent(w http.ResponseWriter, r *http.Request) {
	var req request.ConsentRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.provider.Consent(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *OAuthHandler) ApproveDevice(w http.ResponseWriter, r *http.Request) {
	var req request.DeviceApproveRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.provider.ApproveDevice(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *OAuthHandler) ListConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.provider.ListConsents(ctx, t, httputil.SessionToken(r, t))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *OAuthHandler) RevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	err := h.provider.RevokeConsent(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "client_id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "consent withdrawn. the application's tokens were revoked", nil, err)
}
