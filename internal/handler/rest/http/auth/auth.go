// Package auth serves sign-up, sign-in, sessions and password reset.
package auth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/constant/dto/request"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
	httputil "github.com/flash-software-technology/aos/internal/handler/rest/http"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

type AuthHandler struct {
	authModule   module.Auth
	tenantModule module.Tenant
	logger       logger.Logger
}

func NewAuthHandler(authModule module.Auth, tenantModule module.Tenant, logger logger.Logger) rest.AuthHandler {
	return &AuthHandler{authModule: authModule, tenantModule: tenantModule, logger: logger}
}

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req request.SignUpRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if err := h.authModule.SignUp(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	// The same words whether or not the address already had an account.
	response.SendSuccessResponse(w, http.StatusAccepted, "check your email to finish signing up", nil, nil)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req request.VerifyEmailRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.VerifyEmail(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "email confirmed")
}

func (h *AuthHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	var req request.SignInRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.SignIn(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "signed in")
}

func (h *AuthHandler) signedIn(w http.ResponseWriter, t *model.Tenant, res *response.AuthResponse, message string) {
	httputil.SignedIn(w, t, res, message)
}

func (h *AuthHandler) SignOut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.SignOut(ctx, t, httputil.SessionToken(r, t), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	httputil.ClearSessionCookie(w)
	response.SendSuccessResponse(w, http.StatusOK, "signed out", nil, nil)
}

func (h *AuthHandler) Session(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.CurrentUser(ctx, t, httputil.SessionToken(r, t))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.IssueToken(ctx, t, httputil.SessionToken(r, t))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req request.ForgotPasswordRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if err := h.authModule.ForgotPassword(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	// The same words whether or not the account exists.
	response.SendSuccessResponse(w, http.StatusAccepted, "if an account exists, we sent a link", nil, nil)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req request.ResetPasswordRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if err := h.authModule.ResetPassword(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	// A reset ends every session, this browser's included.
	httputil.ClearSessionCookie(w)
	response.SendSuccessResponse(w, http.StatusOK, "password changed. sign in with the new password", nil, nil)
}

// JWKS publishes the public keys that verify this tenant's signed
// tokens. It is written in the standard key-set layout, with no
// envelope, so any JWT library can read it.
func (h *AuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.tenantModule.JWKS(ctx, middleware.TenantFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Public keys are not secret and change rarely.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (h *AuthHandler) SignOutEverywhere(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.SignOutEverywhere(ctx, t, httputil.SessionToken(r, t), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	httputil.ClearSessionCookie(w)
	response.SendSuccessResponse(w, http.StatusOK, "signed out everywhere", nil, nil)
}

func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.ListSessions(ctx, t, httputil.SessionToken(r, t))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.RevokeSession(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "session ended", nil, nil)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req request.ChangePasswordRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.ChangePassword(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "password changed. other devices were signed out", nil, nil)
}

func (h *AuthHandler) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	var req request.ChangeEmailRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.ChangeEmail(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	// The same words whether or not the new address is free.
	response.SendSuccessResponse(w, http.StatusAccepted, "check the new address for a confirmation link", nil, nil)
}

func (h *AuthHandler) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	var req request.ConfirmEmailRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	res, err := h.authModule.ConfirmEmail(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	httputil.ClearSessionCookie(w)
	response.SendSuccessResponse(w, http.StatusOK, "email address changed. sign in with the new address", res, nil)
}

func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	var req request.PasswordConfirmRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.DeleteAccount(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	httputil.ClearSessionCookie(w)
	response.SendSuccessResponse(w, http.StatusOK, "account deleted", nil, nil)
}

func (h *AuthHandler) Export(w http.ResponseWriter, r *http.Request) {
	var req request.PasswordConfirmRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.Export(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) SetupAccount(w http.ResponseWriter, r *http.Request) {
	var req request.SetupAccountRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.SetupAccount(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "account ready")
}

// ---- strong sign-in ----

func (h *AuthHandler) SecondFactor(w http.ResponseWriter, r *http.Request) {
	var req request.SecondFactorRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.SecondFactor(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "signed in")
}

func (h *AuthHandler) Factors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.Factors(ctx, t, httputil.SessionToken(r, t))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) EnrollTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.EnrollTOTP(ctx, t, httputil.SessionToken(r, t), middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "scan the code in your authenticator app, then confirm with a code from it", res, nil)
}

func (h *AuthHandler) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	var req request.FactorCodeRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.ConfirmTOTP(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "two-step sign-in is on. keep these recovery codes somewhere safe. they are shown only this once", res, nil)
}

func (h *AuthHandler) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	var req request.FactorCodeRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.DisableTOTP(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "two-step sign-in is off", nil, nil)
}

func (h *AuthHandler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req request.FactorCodeRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.RegenerateRecoveryCodes(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "new recovery codes. the old ones no longer work", res, nil)
}

func (h *AuthHandler) StepUp(w http.ResponseWriter, r *http.Request) {
	var req request.FactorCodeRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.StepUp(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "confirmed", res, nil)
}

func (h *AuthHandler) SendCode(w http.ResponseWriter, r *http.Request) {
	var req request.SendCodeRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if err := h.authModule.SendCode(ctx, middleware.TenantFrom(ctx), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	// The same words whether or not the address has an account.
	response.SendSuccessResponse(w, http.StatusAccepted, "if an account exists, we sent a code", nil, nil)
}

func (h *AuthHandler) VerifyCode(w http.ResponseWriter, r *http.Request) {
	var req request.VerifyCodeRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.VerifyCode(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "signed in")
}

func (h *AuthHandler) MagicLink(w http.ResponseWriter, r *http.Request) {
	var req request.MagicLinkRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.MagicLink(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "signed in")
}

func (h *AuthHandler) CreateGuest(w http.ResponseWriter, r *http.Request) {
	var req request.GuestRequest
	if r.ContentLength != 0 && !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.CreateGuest(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "welcome, guest")
}

func (h *AuthHandler) UpgradeGuest(w http.ResponseWriter, r *http.Request) {
	var req request.SignUpRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.UpgradeGuest(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusAccepted, "check your email to finish signing up", nil, nil)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req request.RefreshRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.Refresh(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "tokens renewed")
}

// ---- passkeys ----

func (h *AuthHandler) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.BeginPasskeyRegistration(ctx, t, httputil.SessionToken(r, t), middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var req request.PasskeyFinishRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.FinishPasskeyRegistration(ctx, t, httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusCreated, "passkey added", res, nil)
}

func (h *AuthHandler) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.ListPasskeys(ctx, t, httputil.SessionToken(r, t))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.DeletePasskey(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "id"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "passkey removed", nil, nil)
}

func (h *AuthHandler) BeginPasskeySignIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res, err := h.authModule.BeginPasskeySignIn(ctx, middleware.TenantFrom(ctx), middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) FinishPasskeySignIn(w http.ResponseWriter, r *http.Request) {
	var req request.PasskeyFinishRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.FinishPasskeySignIn(ctx, t, req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	h.signedIn(w, t, res, "signed in")
}

// ---- social sign-in ----

func (h *AuthHandler) StartSocial(w http.ResponseWriter, r *http.Request) {
	var req request.SocialStartRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.StartSocial(ctx, t, chi.URLParam(r, "provider"), httputil.SessionToken(r, t), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) FinishSocial(w http.ResponseWriter, r *http.Request) {
	var req request.SocialFinishRequest
	if !httputil.Decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.FinishSocial(ctx, t, chi.URLParam(r, "provider"), req, middleware.MetaFrom(ctx))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	if res == nil {
		response.SendSuccessResponse(w, http.StatusOK, "account linked", nil, nil)
		return
	}
	h.signedIn(w, t, res, "signed in")
}

func (h *AuthHandler) ListIdentities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	res, err := h.authModule.ListIdentities(ctx, t, httputil.SessionToken(r, t))
	if err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "", res, nil)
}

func (h *AuthHandler) UnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := middleware.TenantFrom(ctx)
	if err := h.authModule.UnlinkIdentity(ctx, t, httputil.SessionToken(r, t), chi.URLParam(r, "provider"), middleware.MetaFrom(ctx)); err != nil {
		httputil.Fail(w, r, h.logger, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "account unlinked", nil, nil)
}
