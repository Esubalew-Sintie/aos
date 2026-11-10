package routing

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/handler/rest"
)

// InitAuthRoutes registers the frontend routes. Every one needs a
// publishable key, which names the tenant.
func InitAuthRoutes(r chi.Router, handler rest.AuthHandler, tenant *middleware.TenantMiddleware) {
	frontend := []func(next http.Handler) http.Handler{tenant.RequirePublishableKey}

	RegisterRoutes(r, []Route{
		// Strong sign-in (SIGN-2, SIGN-4, SIGN-9, REG-8).
		{Method: http.MethodPost, Path: "/v1/second-factor", Handler: handler.SecondFactor, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/factors", Handler: handler.Factors, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/totp", Handler: handler.EnrollTOTP, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/totp/confirm", Handler: handler.ConfirmTOTP, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/totp/disable", Handler: handler.DisableTOTP, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/recovery-codes", Handler: handler.RegenerateRecoveryCodes, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/step-up", Handler: handler.StepUp, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/code/send", Handler: handler.SendCode, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/code/verify", Handler: handler.VerifyCode, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/magic-link", Handler: handler.MagicLink, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/guest", Handler: handler.CreateGuest, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/guest/upgrade", Handler: handler.UpgradeGuest, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/token/refresh", Handler: handler.Refresh, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/passkeys/options", Handler: handler.BeginPasskeyRegistration, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/passkeys", Handler: handler.FinishPasskeyRegistration, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/passkeys", Handler: handler.ListPasskeys, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/me/passkeys/{id}", Handler: handler.DeletePasskey, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/passkey/options", Handler: handler.BeginPasskeySignIn, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/passkey/sign-in", Handler: handler.FinishPasskeySignIn, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/oauth/{provider}/start", Handler: handler.StartSocial, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/oauth/{provider}/finish", Handler: handler.FinishSocial, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/me/identities", Handler: handler.ListIdentities, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/me/identities/{provider}", Handler: handler.UnlinkIdentity, Middlewares: frontend},

		// Getting in
		{Method: http.MethodPost, Path: "/v1/sign-up", Handler: handler.SignUp, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/verify-email", Handler: handler.VerifyEmail, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sign-in", Handler: handler.SignIn, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/account/setup", Handler: handler.SetupAccount, Middlewares: frontend},
		// The session
		{Method: http.MethodGet, Path: "/v1/session", Handler: handler.Session, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/session/token", Handler: handler.Token, Middlewares: frontend},
		{Method: http.MethodGet, Path: "/v1/sessions", Handler: handler.ListSessions, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/sessions/{id}", Handler: handler.RevokeSession, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sign-out", Handler: handler.SignOut, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/sign-out-all", Handler: handler.SignOutEverywhere, Middlewares: frontend},
		// The account
		{Method: http.MethodPost, Path: "/v1/password/forgot", Handler: handler.ForgotPassword, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/password/reset", Handler: handler.ResetPassword, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/password/change", Handler: handler.ChangePassword, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/email/change", Handler: handler.ChangeEmail, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/email/confirm", Handler: handler.ConfirmEmail, Middlewares: frontend},
		{Method: http.MethodPost, Path: "/v1/me/export", Handler: handler.Export, Middlewares: frontend},
		{Method: http.MethodDelete, Path: "/v1/me", Handler: handler.DeleteAccount, Middlewares: frontend},
		// Keys for the application's backend
		{Method: http.MethodGet, Path: "/v1/jwks.json", Handler: handler.JWKS, Middlewares: frontend},
	})
}
