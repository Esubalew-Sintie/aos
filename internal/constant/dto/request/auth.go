package request

import (
	"encoding/json"
	"strings"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/errors"
)

type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (r *SignUpRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	f := fields{}
	if !validEmail(r.Email) {
		f["email"] = "must be a valid email address"
	}
	// A password rule says nothing about any account, so it is safe to
	// tell the caller which rule failed.
	if p := passwordProblem(r.Password); p != "" {
		f["password"] = p
	}
	if len(r.Name) > 200 {
		f["name"] = "must be at most 200 characters"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

func (r *VerifyEmailRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// SessionKind is "browser" (the default, a cookie) or "token" (an
	// access token and a refresh token, for mobile apps).
	SessionKind string `json:"session_kind"`
}

// Validate checks only that both fields are present. It must not say
// whether the email is well formed or the password long enough: at
// sign-in every failure reads "wrong email or password".
func (r *SignInRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	f := fields{}
	f.require("email", r.Email)
	f.require("password", r.Password)
	if err := checkSessionKind(&r.SessionKind); err != "" {
		f["session_kind"] = err
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

func (r *ForgotPasswordRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	f := fields{}
	f.require("email", r.Email)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (r *ResetPasswordRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if p := passwordProblem(r.Password); p != "" {
		f["password"] = p
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (r *ChangePasswordRequest) Validate() error {
	f := fields{}
	f.require("current_password", r.CurrentPassword)
	if p := passwordProblem(r.NewPassword); p != "" {
		f["new_password"] = p
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ChangeEmailRequest struct {
	NewEmail string `json:"new_email"`
	Password string `json:"password"`
}

func (r *ChangeEmailRequest) Validate() error {
	r.NewEmail = NormalizeEmail(r.NewEmail)
	f := fields{}
	if !validEmail(r.NewEmail) {
		f["new_email"] = "must be a valid email address"
	}
	f.require("password", r.Password)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type ConfirmEmailRequest struct {
	Token string `json:"token"`
}

func (r *ConfirmEmailRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// PasswordConfirmRequest carries the password that a sensitive action
// asks for again: deleting the account, exporting its data.
type PasswordConfirmRequest struct {
	Password string `json:"password"`
}

func (r *PasswordConfirmRequest) Validate() error {
	f := fields{}
	f.require("password", r.Password)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// SetupAccountRequest finishes an account that an admin created: the
// person opens the setup link and chooses a password.
type SetupAccountRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (r *SetupAccountRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if p := passwordProblem(r.Password); p != "" {
		f["password"] = p
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// SecondFactorRequest finishes a sign-in that waits for its second factor.
type SecondFactorRequest struct {
	PendingToken string `json:"pending_token"`
	// Method is "totp", "recovery_code" or "passkey".
	Method string `json:"method"`
	Code   string `json:"code"`
	// For a passkey: the challenge from /v1/passkey/options and the
	// browser's answer.
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

func (r *SecondFactorRequest) Validate() error {
	f := fields{}
	f.require("pending_token", r.PendingToken)
	switch r.Method {
	case constant.MethodTOTP, constant.MethodRecoveryCode:
		f.require("code", r.Code)
	case constant.MethodPasskey:
		if !validUUID(r.ChallengeID) {
			f["challenge_id"] = "must be an id"
		}
		if len(r.Credential) == 0 {
			f["credential"] = "is required"
		}
	default:
		f["method"] = "must be totp, recovery_code or passkey"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// FactorCodeRequest carries a code from an authenticator app or a
// recovery code, for a step-up or a settings change.
type FactorCodeRequest struct {
	// Method is "totp" (the default) or "recovery_code".
	Method string `json:"method"`
	Code   string `json:"code"`
}

func (r *FactorCodeRequest) Validate() error {
	if r.Method == "" {
		r.Method = constant.MethodTOTP
	}
	f := fields{}
	f.require("code", r.Code)
	switch r.Method {
	case constant.MethodTOTP, constant.MethodRecoveryCode:
	default:
		f["method"] = "must be totp or recovery_code"
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type SendCodeRequest struct {
	Email string `json:"email"`
}

func (r *SendCodeRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	if !validEmail(r.Email) {
		return errors.Validation(map[string]string{"email": "must be a valid email address"})
	}
	return nil
}

type VerifyCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
	// SessionKind is "browser" (the default) or "token".
	SessionKind string `json:"session_kind"`
}

func (r *VerifyCodeRequest) Validate() error {
	r.Email = NormalizeEmail(r.Email)
	r.Code = strings.ReplaceAll(strings.TrimSpace(r.Code), " ", "")
	f := fields{}
	if !validEmail(r.Email) {
		f["email"] = "must be a valid email address"
	}
	f.require("code", r.Code)
	if err := checkSessionKind(&r.SessionKind); err != "" {
		f["session_kind"] = err
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

type MagicLinkRequest struct {
	Token       string `json:"token"`
	SessionKind string `json:"session_kind"`
}

func (r *MagicLinkRequest) Validate() error {
	f := fields{}
	f.require("token", r.Token)
	if err := checkSessionKind(&r.SessionKind); err != "" {
		f["session_kind"] = err
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

func checkSessionKind(kind *string) string {
	if *kind == "" {
		*kind = constant.SessionBrowser
	}
	if *kind != constant.SessionBrowser && *kind != constant.SessionToken {
		return "must be browser or token"
	}
	return ""
}

type GuestRequest struct {
	Name string `json:"name"`
}

func (r *GuestRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if len(r.Name) > 200 {
		return errors.Validation(map[string]string{"name": "must be at most 200 characters"})
	}
	return nil
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *RefreshRequest) Validate() error {
	if r.RefreshToken == "" {
		return errors.Validation(map[string]string{"refresh_token": "is required"})
	}
	return nil
}

// PasskeyNameRequest names a passkey while it is being added.
type PasskeyNameRequest struct {
	Name string `json:"name"`
}

// PasskeyFinishRequest carries the browser's answer to a passkey challenge.
type PasskeyFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Name        string          `json:"name"`
	Credential  json.RawMessage `json:"credential"`
	SessionKind string          `json:"session_kind"`
}

func (r *PasskeyFinishRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	f := fields{}
	if !validUUID(r.ChallengeID) {
		f["challenge_id"] = "must be an id"
	}
	if len(r.Credential) == 0 || len(r.Credential) > 65536 {
		f["credential"] = "is required"
	}
	if len(r.Name) > 100 {
		f["name"] = "must be at most 100 characters"
	}
	if err := checkSessionKind(&r.SessionKind); err != "" {
		f["session_kind"] = err
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// PutOAuthProviderRequest sets a social sign-in provider up. The secret
// is stored encrypted and never shown again.
type PutOAuthProviderRequest struct {
	// Provider is "google", "apple" or "oidc".
	Provider     string   `json:"provider"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Issuer       string   `json:"issuer"`
	Scopes       []string `json:"scopes"`
	Enabled      *bool    `json:"enabled"`
}

func (r *PutOAuthProviderRequest) Validate() error {
	r.Provider = strings.ToLower(strings.TrimSpace(r.Provider))
	r.Issuer = strings.TrimRight(strings.TrimSpace(r.Issuer), "/")
	f := fields{}
	if preset, ok := constant.SocialPresets[r.Provider]; ok {
		r.Issuer = preset
	} else if r.Provider != "oidc" {
		f["provider"] = "must be google, apple or oidc"
	} else if !validOrigin(r.Issuer, true) {
		f["issuer"] = "must be the provider's address, such as https://login.example.com"
	}
	f.require("client_id", r.ClientID)
	f.require("client_secret", r.ClientSecret)
	if len(r.Scopes) == 0 {
		r.Scopes = []string{"openid", "email", "profile"}
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// SocialStartRequest begins a sign-in with a provider. The provider sends
// the browser back to redirect_uri, a page of the application.
type SocialStartRequest struct {
	RedirectURI string `json:"redirect_uri"`
	SessionKind string `json:"session_kind"`
}

func (r *SocialStartRequest) Validate() error {
	f := fields{}
	if !validOrigin(r.RedirectURI, true) {
		f["redirect_uri"] = "must be an address of the application"
	}
	if err := checkSessionKind(&r.SessionKind); err != "" {
		f["session_kind"] = err
	}
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}

// SocialFinishRequest carries what the provider sent back.
type SocialFinishRequest struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

func (r *SocialFinishRequest) Validate() error {
	f := fields{}
	f.require("state", r.State)
	f.require("code", r.Code)
	if len(f) > 0 {
		return errors.Validation(f)
	}
	return nil
}
