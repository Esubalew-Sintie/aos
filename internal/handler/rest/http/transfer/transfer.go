// Package transfer serves user import, tenant export and import, and
// access reviews.
package transfer

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	httputil "github.com/flash-software-technology/aos/internal/handler/rest/http"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

type TransferHandler struct {
	transfer module.Transfer
	review   module.Review
	auth     module.Auth
	logger   logger.Logger
}

func NewTransferHandler(transfer module.Transfer, review module.Review, auth module.Auth, logger logger.Logger) rest.TransferHandler {
	return &TransferHandler{transfer: transfer, review: review, auth: auth, logger: logger}
}

func (h *TransferHandler) answer(w http.ResponseWriter, r *http.Request, status int, message string, data any, err error) {
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, status, message, data, nil)
}

func (h *TransferHandler) ImportUsers(w http.ResponseWriter, r *http.Request) {
	var req request.ImportUsersRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.transfer.ImportUsers(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "import finished", res, err)
}

func (h *TransferHandler) Export(w http.ResponseWriter, r *http.Request) {
	var req request.ExportRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.transfer.Export(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "archive ready. it holds password hashes; keep it and its passphrase apart", res, err)
}

func (h *TransferHandler) Import(w http.ResponseWriter, r *http.Request) {
	var req request.ImportArchiveRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.transfer.Import(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "archive imported. everyone signs in again", res, err)
}

func (h *TransferHandler) StartReview(w http.ResponseWriter, r *http.Request) {
	var req request.StartReviewRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.review.Start(ctx, middleware.TenantFrom(ctx), actor, req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusCreated, "access review started", res, err)
}

func (h *TransferHandler) ListReviews(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.review.List(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *TransferHandler) GetReview(w http.ResponseWriter, r *http.Request) {
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.review.Get(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"))
	h.answer(w, r, http.StatusOK, "", res, err)
}

func (h *TransferHandler) DecideReview(w http.ResponseWriter, r *http.Request) {
	var req request.ReviewDecisionRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	actor, ok := httputil.Actor(w, r, h.auth, h.logger)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := h.review.Decide(ctx, middleware.TenantFrom(ctx), actor, chi.URLParam(r, "id"), chi.URLParam(r, "item_id"), req, middleware.MetaFrom(ctx))
	h.answer(w, r, http.StatusOK, "decision saved", res, err)
}
