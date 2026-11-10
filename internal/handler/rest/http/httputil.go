// Package http holds the handler implementations, one package per area,
// and the helpers they share.
package http

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

// Decode reads a JSON body into dst. It refuses unknown fields and
// anything after the first JSON value, and writes the error answer itself.
func Decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return false
	}
	return true
}

// Fail answers with err. An error that was not meant for the caller is
// logged with the request id and answered as a plain 500.
func Fail(w http.ResponseWriter, r *http.Request, log logger.Logger, err error) {
	if _, ok := errors.AsAppError(err); !ok {
		log.Error(r.Context(), "request failed",
			"error", err.Error(), "path", r.URL.Path, "request_id", middleware.MetaFrom(r.Context()).RequestID)
	}
	response.SendErrorResponse(w, err)
}

// SessionToken reads the session id from the cookie. A development
// tenant may send it in a header instead.
func SessionToken(r *http.Request, t *model.Tenant) string {
	if c, err := r.Cookie(constant.SessionCookie); err == nil && c.Value != "" {
		return c.Value
	}
	// A token session sends its access token as a bearer token.
	if bearer, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found && strings.HasPrefix(bearer, "eyJ") {
		return bearer
	}
	if t.Development() {
		return r.Header.Get(constant.HeaderSession)
	}
	return ""
}

// SetSessionCookie hands the browser its session in a host-locked cookie
// that page scripts cannot read.
func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     constant.SessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true, // page scripts cannot read it
		Secure:   true, // sent over HTTPS only
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     constant.SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// SignedIn hands a new session to the caller: the cookie, and the body.
// The session id is in the body only for a development tenant, where a
// first-party cookie is not possible.
func SignedIn(w http.ResponseWriter, t *model.Tenant, res *response.AuthResponse, message string) {
	// No session yet: the person must give a second factor first.
	if res.SecondFactorRequired {
		response.SendSuccessResponse(w, http.StatusOK, "second factor needed", res, nil)
		return
	}
	if res.DeviceToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name: constant.DeviceCookie, Value: res.DeviceToken, Path: "/",
			Expires: time.Now().Add(constant.DeviceTTL), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	// A token session carries its tokens in the body and sets no cookie.
	if res.AccessToken != "" {
		res.SessionToken = ""
		response.SendSuccessResponse(w, http.StatusOK, message, res, nil)
		return
	}
	SetSessionCookie(w, res.SessionToken, res.Session.ExpiresAt)
	if !t.Development() {
		res.SessionToken = ""
	}
	if res.SecondFactorSetupRequired {
		message = "signed in. set up a second factor to continue"
	}
	response.SendSuccessResponse(w, http.StatusOK, message, res, nil)
}

// Actor says who is making a request. Behind the backend door, with a
// secret key, it is the application itself (Root). Behind the frontend
// door it is the signed-in person, found from the session, or nobody.
// It writes the error answer itself when a session is required and absent.
func Actor(w http.ResponseWriter, r *http.Request, auth module.Auth, log logger.Logger) (model.Actor, bool) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if middleware.KeyKindFrom(ctx) == constant.KeyKindSecret {
		return model.Actor{Root: true}, true
	}
	session, err := auth.Authenticate(ctx, t, SessionToken(r, t))
	if err != nil {
		Fail(w, r, log, err)
		return model.Actor{}, false
	}
	return model.Actor{PrincipalID: session.PrincipalID, SessionID: session.ID}, true
}
