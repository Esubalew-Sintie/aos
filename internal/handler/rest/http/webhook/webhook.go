// Package webhook serves the backend routes for the endpoints the
// engine calls: event deliveries and before-hooks.
package webhook

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

type WebhookHandler struct {
	notification module.Notification
	logger       logger.Logger
}

func NewWebhookHandler(notification module.Notification, logger logger.Logger) rest.WebhookHandler {
	return &WebhookHandler{notification: notification, logger: logger}
}

func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req request.CreateWebhookRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.notification.CreateEndpoint(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "endpoint registered. the secret is shown only now", res, nil)
}

func (h *WebhookHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.notification.ListEndpoints(ctx, middleware.TenantFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *WebhookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.notification.DeleteEndpoint(ctx, middleware.TenantFrom(ctx), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "endpoint removed", nil, nil)
}
