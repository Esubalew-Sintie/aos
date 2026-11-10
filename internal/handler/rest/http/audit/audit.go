// Package audit serves the tenant's audit log to its backend.
package audit

import (
	"net/http"
	"strconv"

	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	httputil "github.com/flash-software-technology/aos/internal/handler/rest/http"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

type AuditHandler struct {
	auditModule module.Audit
	logger      logger.Logger
}

func NewAuditHandler(auditModule module.Audit, logger logger.Logger) rest.AuditHandler {
	return &AuditHandler{auditModule: auditModule, logger: logger}
}

// List returns one page of the log, newest first. "before" is the
// next_before of the page before.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	req := request.ListAuditRequest{Limit: limit, Action: q.Get("action"), ActorID: q.Get("actor_id"), TargetID: q.Get("target_id")}
	if v := q.Get("before"); v != "" {
		before, err := strconv.ParseInt(v, 10, 64)
		if err != nil || before <= 0 {
			// Validate refuses a negative number with a clear message.
			before = -1
		}
		req.Before = before
	}
	res, err := h.auditModule.List(ctx, middleware.TenantFrom(ctx), req)
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}
