// Package dev serves helpers that exist only on a development engine.
package dev

import (
	"net"
	"net/http"

	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	"github.com/flash-software-technology/aos/platform/mailer"
)

type DevHandler struct {
	inbox *mailer.Inbox
}

func NewDevHandler(inbox *mailer.Inbox) rest.DevHandler {
	return &DevHandler{inbox: inbox}
}

// local refuses anyone but this machine: the inbox holds sign-in links.
func local(w http.ResponseWriter, r *http.Request) bool {
	ip := net.ParseIP(middleware.MetaFrom(r.Context()).IP)
	if ip == nil || !ip.IsLoopback() {
		response.SendErrorResponse(w, errors.ErrNotFound)
		return false
	}
	return true
}

func (h *DevHandler) ListMail(w http.ResponseWriter, r *http.Request) {
	if !local(w, r) {
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", h.inbox.List(r.URL.Query().Get("to")), nil)
}

func (h *DevHandler) ClearMail(w http.ResponseWriter, r *http.Request) {
	if !local(w, r) {
		return
	}
	h.inbox.Clear()
	response.SendSuccessResponse(w, http.StatusOK, "inbox emptied", nil, nil)
}
