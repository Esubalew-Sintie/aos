// Package iam serves permissions, roles, resources, grants and the
// permission check.
package iam

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	httputil "github.com/flash-software-technology/aos/internal/handler/rest/http"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

type IamHandler struct {
	iamModule module.IAM
	logger    logger.Logger
}

func NewIamHandler(iamModule module.IAM, logger logger.Logger) rest.IAMHandler {
	return &IamHandler{iamModule: iamModule, logger: logger}
}

func (h *IamHandler) Can(w http.ResponseWriter, r *http.Request) {
	var req request.CanRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.Can(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	// A deny is a successful answer to the question, not an error.
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) PutPermission(w http.ResponseWriter, r *http.Request) {
	var req request.PutPermissionRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	// This route is what the SDK calls, so the permission comes from code.
	res, err := h.iamModule.PutPermission(ctx, middleware.TenantFrom(ctx), req, constant.SourceCode, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "permission saved", res, nil)
}

func (h *IamHandler) PutRole(w http.ResponseWriter, r *http.Request) {
	var req request.PutRoleRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.PutRole(ctx, middleware.TenantFrom(ctx), req, constant.SourceCode, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "role saved", res, nil)
}

func (h *IamHandler) CreateResource(w http.ResponseWriter, r *http.Request) {
	var req request.CreateResourceRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.CreateResource(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "resource saved", res, nil)
}

func (h *IamHandler) CreateGrant(w http.ResponseWriter, r *http.Request) {
	var req request.CreateGrantRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.CreateGrant(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "grant created", res, nil)
}

func (h *IamHandler) DeleteGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.iamModule.DeleteGrant(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "grant removed", nil, nil)
}

func (h *IamHandler) CanBatch(w http.ResponseWriter, r *http.Request) {
	var req request.CanBatchRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.CanBatch(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) Explain(w http.ResponseWriter, r *http.Request) {
	var req request.CanRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.Explain(ctx, middleware.TenantFrom(ctx), req)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) Filter(w http.ResponseWriter, r *http.Request) {
	var req request.FilterRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.Filter(ctx, middleware.TenantFrom(ctx), req)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) ListPrincipals(w http.ResponseWriter, r *http.Request) {
	var req request.ListPrincipalsRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.ListPrincipals(ctx, middleware.TenantFrom(ctx), req)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) Simulate(w http.ResponseWriter, r *http.Request) {
	var req request.SimulateRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.Simulate(ctx, middleware.TenantFrom(ctx), req)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) PutGroup(w http.ResponseWriter, r *http.Request) {
	var req request.PutGroupRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.iamModule.PutGroup(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "group saved", res, nil)
}

// ListPermissions lists the permission catalog.
func (h *IamHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.iamModule.ListPermissions(ctx, middleware.TenantFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

// ListRoles lists the tenant-wide roles and what each holds.
func (h *IamHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.iamModule.ListRoles(ctx, middleware.TenantFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

// ListGrants lists the grants of a principal, or on a resource.
func (h *IamHandler) ListGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	res, err := h.iamModule.ListGrants(ctx, middleware.TenantFrom(ctx), request.ListGrantsRequest{
		PrincipalID: q.Get("principal_id"), ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id"), Limit: limit,
	})
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.iamModule.ListGroups(ctx, middleware.TenantFrom(ctx), r.URL.Query().Get("organization_id"))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *IamHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.iamModule.DeleteGroup(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "group removed", nil, nil)
}

func (h *IamHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	var req request.GroupMemberRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	ctx := r.Context()
	if err := h.iamModule.AddGroupMember(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), req.PrincipalID, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "member added", nil, nil)
}

func (h *IamHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.iamModule.RemoveGroupMember(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), chi.URLParam(r, "principal_id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "member removed", nil, nil)
}
