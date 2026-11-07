// Package organization serves organizations, members and invitations.
package organization

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

type OrganizationHandler struct {
	orgModule  module.Organization
	authModule module.Auth
	logger     logger.Logger
}

func NewOrganizationHandler(orgModule module.Organization, authModule module.Auth, logger logger.Logger) rest.OrganizationHandler {
	return &OrganizationHandler{orgModule: orgModule, authModule: authModule, logger: logger}
}

func (h *OrganizationHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req request.CreateOrganizationRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.Create(ctx, middleware.TenantFrom(ctx), actor, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "organization created", res, nil)
}

func (h *OrganizationHandler) List(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.List(ctx, middleware.TenantFrom(ctx), actor)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *OrganizationHandler) Get(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.Get(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *OrganizationHandler) Switch(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.orgModule.Switch(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "organization switched", nil, nil)
}

func (h *OrganizationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.orgModule.Delete(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "organization deleted", nil, nil)
}

func (h *OrganizationHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.ListMembers(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *OrganizationHandler) ChangeMemberRole(w http.ResponseWriter, r *http.Request) {
	var req request.ChangeMemberRoleRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.orgModule.ChangeMemberRole(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), chi.URLParam(r, "principal_id"), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "role changed", nil, nil)
}

func (h *OrganizationHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.orgModule.RemoveMember(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), chi.URLParam(r, "principal_id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "member removed", nil, nil)
}

func (h *OrganizationHandler) Invite(w http.ResponseWriter, r *http.Request) {
	var req request.InviteRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.Invite(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "invitation sent", res, nil)
}

func (h *OrganizationHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.ListInvitations(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *OrganizationHandler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.orgModule.RevokeInvitation(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), chi.URLParam(r, "invitation_id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "invitation withdrawn", nil, nil)
}

// PreviewInvitation needs no session: the link itself is the proof.
func (h *OrganizationHandler) PreviewInvitation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.orgModule.Preview(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "token"))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *OrganizationHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req request.InvitationTokenRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.authModule, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.orgModule.Accept(ctx, middleware.TenantFrom(ctx), actor, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "invitation accepted", res, nil)
}

func (h *OrganizationHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	var req request.InvitationTokenRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if err := h.orgModule.Decline(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "invitation declined", nil, nil)
}

func (h *OrganizationHandler) SignUpByInvitation(w http.ResponseWriter, r *http.Request) {
	var req request.InvitationSignUpRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.orgModule.SignUp(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	httputil.SignedIn(w, t, res, "welcome. you have joined the organization")
}
