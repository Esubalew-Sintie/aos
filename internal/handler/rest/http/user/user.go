// Package user serves the backend routes for accounts: what a tenant
// admin does to other people's accounts.
package user

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	httputil "github.com/flash-software-technology/aos/internal/handler/rest/http"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

type UserHandler struct {
	authModule module.Auth
	iamModule  module.IAM
	logger     logger.Logger
}

func NewUserHandler(authModule module.Auth, iamModule module.IAM, logger logger.Logger) rest.UserHandler {
	return &UserHandler{authModule: authModule, iamModule: iamModule, logger: logger}
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	res, err := h.authModule.ListUsers(ctx, middleware.TenantFrom(ctx), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

// CreateUser makes an account and emails a setup link. With a role and a
// resource, the person holds that role from the start.
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req request.CreateUserRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	meta := middleware.MetaFrom(ctx)
	user, err := h.authModule.CreateUser(ctx, t, req, meta)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	if req.Role != "" {
		if _, err := h.iamModule.CreateGrant(ctx, t, request.CreateGrantRequest{
			PrincipalID: user.ID, Role: req.Role, Resource: *req.Resource, Effect: "allow", Reason: "given at creation",
		}, meta); err != nil {
			httputil.Fail(w, r, h.logger, err)
			return
		}
	}
	response.SendSuccessResponse(w, http.StatusCreated, "user created. a setup link was sent", user, nil)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.authModule.GetUser(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *UserHandler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	var req request.SuspendUserRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	ctx := r.Context()
	if err := h.authModule.SuspendUser(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), req.Reason, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "user suspended and signed out everywhere", nil, nil)
}

func (h *UserHandler) ReinstateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.authModule.ReinstateUser(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "user reinstated", nil, nil)
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.authModule.DeleteUser(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "user deleted", nil, nil)
}

func (h *UserHandler) ResetSecondFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.authModule.ResetSecondFactor(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "second factor removed and every session ended", nil, nil)
}
