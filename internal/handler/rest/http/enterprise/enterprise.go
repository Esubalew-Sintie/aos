// Package enterprise serves SSO connections, the IT admin's setup page,
// enterprise sign-in and organization policies.
package enterprise

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
	httputil "github.com/flash-softeware/aos/internal/handler/rest/http"
	"github.com/flash-softeware/aos/internal/module"
	"github.com/flash-softeware/aos/platform/logger"
)

type EnterpriseHandler struct {
	enterprise module.Enterprise
	auth       module.Auth
	logger     logger.Logger
}

func NewEnterpriseHandler(enterprise module.Enterprise, auth module.Auth, logger logger.Logger) rest.EnterpriseHandler {
	return &EnterpriseHandler{enterprise: enterprise, auth: auth, logger: logger}
}

func (h *EnterpriseHandler) answer(w http.ResponseWriter, r *http.Request, status int, message string, data any, err error) {
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, status, message, data, nil)
}

// ---- the organization admin ----

func (h *EnterpriseHandler) CreateConnection(w http.ResponseWriter, r *http.Request) {
	var req request.CreateConnectionRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.CreateConnection(ctx, middleware.TenantFrom(ctx), actor, req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "connection created. hand the setup link to your IT admin; it is shown only this once", res, err)
}

func (h *EnterpriseHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.ListConnections(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *EnterpriseHandler) NewSetupLink(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.NewSetupLink(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "new setup link. it is shown only this once", res, err)
}

func (h *EnterpriseHandler) DisableConnection(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	err := h.enterprise.DisableConnection(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "connection disabled", nil, err)
}

// ---- the setup page, opened with the link ----

func (h *EnterpriseHandler) SetupView(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.enterprise.SetupView(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *EnterpriseHandler) SetupSettings(w http.ResponseWriter, r *http.Request) {
	var req request.ConnectionSettingsRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.SetupSettings(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "settings saved. secrets are stored encrypted", res, err)
}

func (h *EnterpriseHandler) SetupMappings(w http.ResponseWriter, r *http.Request) {
	var req request.MappingsRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.SetupMappings(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "mappings saved", res, err)
}

func (h *EnterpriseHandler) SetupAddDomain(w http.ResponseWriter, r *http.Request) {
	var req request.DomainRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.SetupAddDomain(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "add the DNS record shown, then verify", res, err)
}

func (h *EnterpriseHandler) SetupVerifyDomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.enterprise.SetupVerifyDomain(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), chi.URLParam(r, "domain_id"), middleware.MetaFrom(ctx))
	if err == nil && !res.Verified {
		h.answer(w, r, http.StatusOK, "the record was not found yet. DNS changes take time to spread; try again later", res, nil)
		return
	}
	h.answer(w, r, http.StatusOK, "domain verified", res, err)
}

func (h *EnterpriseHandler) SetupTest(w http.ResponseWriter, r *http.Request) {
	var req request.SocialStartRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.SetupTest(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *EnterpriseHandler) SetupActivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.enterprise.SetupActivate(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "connection activated", res, err)
}

func (h *EnterpriseHandler) SetupCreateDirectory(w http.ResponseWriter, r *http.Request) {
	var req request.CreateDirectoryRequest
	if r.ContentLength != 0 && !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.SetupCreateDirectory(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "directory sync is ready. copy the address and the token into the identity provider; the token is shown only this once", res, err)
}

// ---- sign-in ----

func (h *EnterpriseHandler) StartSSO(w http.ResponseWriter, r *http.Request) {
	var req request.SSOStartRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.StartSSO(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *EnterpriseHandler) FinishSSO(w http.ResponseWriter, r *http.Request) {
	var req request.SocialFinishRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.enterprise.FinishSSO(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	if res.TestResult != nil {
		response.SendSuccessResponse(w, http.StatusOK, "test sign-in succeeded. no session was made", res, nil)
		return
	}
	httputil.SignedIn(w, t, res, "signed in")
}

// ---- policies ----

func (h *EnterpriseHandler) GetPolicies(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.GetPolicies(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *EnterpriseHandler) SetPolicies(w http.ResponseWriter, r *http.Request) {
	var req request.OrgPoliciesRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.enterprise.SetPolicies(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "policies saved. new sign-ins follow them at once", res, err)
}
