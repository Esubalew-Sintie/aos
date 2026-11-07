// Package errors is the engine's error model.
//
// An *AppError is safe to show to a caller: it carries an HTTP status, a
// type, a stable code and a message with no internal detail. Any other
// error is an internal failure and is answered with ErrUnexpected.
package errors

import (
	stderrors "errors"
	"net/http"
)

type ErrorType string

const (
	ErrorTypeValidation   ErrorType = "validation"
	ErrorTypeNotFound     ErrorType = "not_found"
	ErrorTypeConflict     ErrorType = "conflict"
	ErrorTypeUnauthorized ErrorType = "unauthorized"
	ErrorTypeForbidden    ErrorType = "forbidden"
	ErrorTypeRateLimit    ErrorType = "rate_limit"
	ErrorTypeBadRequest   ErrorType = "bad_request"
	ErrorTypeInternal     ErrorType = "internal"
	ErrorTypeUnknown      ErrorType = "unknown"
)

type AppError struct {
	Type    ErrorType
	Status  int
	Code    string
	Message string
	// Details names the fields that failed validation.
	Details map[string]string
}

func (e *AppError) Error() string { return e.Code + ": " + e.Message }

func New(t ErrorType, status int, code, message string) *AppError {
	return &AppError{Type: t, Status: status, Code: code, Message: message}
}

// Validation is a request that was understood and refused for its content.
func Validation(details map[string]string) *AppError {
	return &AppError{
		Type:    ErrorTypeValidation,
		Status:  http.StatusBadRequest,
		Code:    "invalid_input",
		Message: "invalid input data",
		Details: details,
	}
}

func NotFound(what string) *AppError {
	return New(ErrorTypeNotFound, http.StatusNotFound, "not_found", what+" was not found")
}

func Conflict(code, message string) *AppError {
	return New(ErrorTypeConflict, http.StatusConflict, code, message)
}

// AsAppError reports whether err is, or wraps, an *AppError.
func AsAppError(err error) (*AppError, bool) {
	var e *AppError
	if stderrors.As(err, &e) {
		return e, true
	}
	return nil, false
}

var (
	ErrUnexpected = New(ErrorTypeUnknown, http.StatusInternalServerError, "unexpected", "unexpected error. please try again")
	ErrBadRequest = New(ErrorTypeBadRequest, http.StatusBadRequest, "bad_request", "the request could not be read")
	ErrNotFound   = New(ErrorTypeNotFound, http.StatusNotFound, "not_found", "not found")
	ErrForbidden  = New(ErrorTypeForbidden, http.StatusForbidden, "forbidden", "forbidden")

	// ErrUnauthorized is "you are not signed in".
	ErrUnauthorized = New(ErrorTypeUnauthorized, http.StatusUnauthorized, "unauthenticated", "sign in to continue")

	// Sign-in and token errors read the same whatever the real cause, so
	// no caller can learn which accounts exist.
	ErrInvalidCredentials = New(ErrorTypeUnauthorized, http.StatusUnauthorized, "invalid_credentials", "wrong email or password")
	ErrInvalidToken       = New(ErrorTypeBadRequest, http.StatusBadRequest, "invalid_token", "this link is no longer valid. ask for a new one")
	ErrRateLimited        = New(ErrorTypeRateLimit, http.StatusTooManyRequests, "rate_limited", "too many attempts. try again later")

	ErrInvalidKey        = New(ErrorTypeUnauthorized, http.StatusUnauthorized, "invalid_key", "the key is missing or not valid")
	ErrTenantUnavailable = New(ErrorTypeForbidden, http.StatusForbidden, "tenant_unavailable", "this application is not available")
	ErrOriginNotAllowed  = New(ErrorTypeForbidden, http.StatusForbidden, "origin_not_allowed", "this web address may not call the API")
	ErrSignupClosed      = New(ErrorTypeForbidden, http.StatusForbidden, "signup_closed", "sign-up is not open")
	ErrAccountSuspended  = New(ErrorTypeForbidden, http.StatusForbidden, "account_suspended", "this account is suspended")
)

// LimitReached says a tenant is at a limit set by the platform.
func LimitReached(metric string) *AppError {
	return New(ErrorTypeForbidden, http.StatusForbidden, "limit_reached", "this application has reached its limit of "+metric)
}
