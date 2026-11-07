// Package machine serves the non-human side: service accounts, agents,
// API keys, delegations and approvals.
package machine

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/flash-softeware/aos/internal/constant"
	"github.com/flash-softeware/aos/internal/constant/dto/request"
	"github.com/flash-softeware/aos/internal/constant/dto/response"
	"github.com/flash-softeware/aos/internal/handler/middleware"
	"github.com/flash-softeware/aos/internal/handler/rest"
	httputil "github.com/flash-softeware/aos/internal/handler/rest/http"
	"github.com/flash-softeware/aos/internal/module"
	"github.com/flash-softeware/aos/platform/logger"
)

type MachineHandler struct {
	machines module.Machine
	auth     module.Auth
	logger   logger.Logger
}

func NewMachineHandler(machines module.Machine, auth module.Auth, logger logger.Logger) rest.MachineHandler {
	return &MachineHandler{machines: machines, auth: auth, logger: logger}
}

func (h *MachineHandler) answer(w http.ResponseWriter, r *http.Request, status int, message string, data any, err error) {
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, status, message, data, nil)
}

func (h *MachineHandler) create(w http.ResponseWriter, r *http.Request, kind string) {
	var req request.CreateMachineRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.machines.CreateMachine(ctx, middleware.TenantFrom(ctx), kind, req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, kind+" created", res, err)
}

func (h *MachineHandler) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	h.create(w, r, constant.PrincipalKindService)
}

func (h *MachineHandler) CreateAgent(w http.ResponseWriter, r *http.Request) {
	h.create(w, r, constant.PrincipalKindAgent)
}

func (h *MachineHandler) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	res, err := h.machines.ListMachines(r.Context(), middleware.TenantFrom(r.Context()), constant.PrincipalKindService)
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	res, err := h.machines.ListMachines(r.Context(), middleware.TenantFrom(r.Context()), constant.PrincipalKindAgent)
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) GetMachine(w http.ResponseWriter, r *http.Request) {
	res, err := h.machines.GetMachine(r.Context(), middleware.TenantFrom(r.Context()), chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) DisableMachine(w http.ResponseWriter, r *http.Request) {
	var req request.ReasonRequest
	if r.ContentLength != 0 && !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	err := h.machines.DisableMachine(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), req.Reason, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "disabled. its keys stop on the next request", nil, err)
}

func (h *MachineHandler) EnableMachine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.machines.EnableMachine(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "enabled", nil, err)
}

func (h *MachineHandler) RevokeAgent(w http.ResponseWriter, r *http.Request) {
	var req request.ReasonRequest
	if r.ContentLength != 0 && !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.machines.RevokeAgent(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), req.Reason, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "revoked. everything it held is gone", res, err)
}

func (h *MachineHandler) AgentAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	res, err := h.machines.AgentAudit(r.Context(), middleware.TenantFrom(r.Context()), chi.URLParam(r, "id"), limit)
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req request.CreateAPIKeyRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.machines.CreateAPIKey(ctx, middleware.TenantFrom(ctx), actor, req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "key created. it is shown only this once", res, err)
}

func (h *MachineHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	res, err := h.machines.ListAPIKeys(r.Context(), middleware.TenantFrom(r.Context()), actor, r.URL.Query().Get("principal_id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	err := h.machines.RevokeAPIKey(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "key revoked. it stops on the next request", nil, err)
}

func (h *MachineHandler) CheckAPIKey(w http.ResponseWriter, r *http.Request) {
	var req request.CheckAPIKeyRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.machines.CheckAPIKey(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) CreateDelegation(w http.ResponseWriter, r *http.Request) {
	var req request.CreateDelegationRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.machines.CreateDelegation(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "delegation created", res, err)
}

func (h *MachineHandler) ListDelegations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.machines.ListDelegations(ctx, t, httputil.SessionToken(r, t))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) RevokeDelegation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	err := h.machines.RevokeDelegation(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "id"), middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "delegation revoked", nil, err)
}

func (h *MachineHandler) ListApprovals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.machines.ListApprovals(ctx, t, httputil.SessionToken(r, t))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *MachineHandler) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.machines.DecideApproval(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "id"), approve, middleware.MetaFrom(ctx))
	message := "declined"
	if approve {
		message = "approved. the agent may do this once"
	}
	h.answer(w, r, http.StatusOK, message, res, err)
}

func (h *MachineHandler) ApproveApproval(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}
func (h *MachineHandler) DeclineApproval(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

func (h *MachineHandler) GetApproval(w http.ResponseWriter, r *http.Request) {
	res, err := h.machines.GetApproval(r.Context(), middleware.TenantFrom(r.Context()), chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}
