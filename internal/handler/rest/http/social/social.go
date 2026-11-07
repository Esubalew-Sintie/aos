// Package social serves the backend routes for social sign-in providers.
package social

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

type SocialProviderHandler struct {
	authModule module.Auth
	logger     logger.Logger
}

func NewSocialProviderHandler(authModule module.Auth, logger logger.Logger) rest.SocialProviderHandler {
	return &SocialProviderHandler{authModule: authModule, logger: logger}
}

func (h *SocialProviderHandler) Put(w http.ResponseWriter, r *http.Request) {
	var req request.PutOAuthProviderRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.authModule.PutOAuthProvider(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "provider saved. the secret is stored encrypted and never shown", res, nil)
}

func (h *SocialProviderHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.authModule.ListOAuthProviders(ctx, middleware.TenantFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *SocialProviderHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.authModule.DeleteOAuthProvider(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "provider"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "provider removed", nil, nil)
}
