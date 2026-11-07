// Package response holds what the API sends back.
package response

import (
	"encoding/json"
	"net/http"

	"github.com/flash-softeware/aos/internal/constant/errors"
)

// Response is the envelope of every answer.
type Response struct {
	Status  int            `json:"status"`
	Message string         `json:"message,omitempty"`
	Data    any            `json:"data,omitempty"`
	Meta    any            `json:"meta,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

type ErrorResponse struct {
	Type    errors.ErrorType  `json:"type"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

func SendSuccessResponse(w http.ResponseWriter, statusCode int, message string, data, meta any) {
	write(w, statusCode, Response{Status: statusCode, Message: message, Data: data, Meta: meta})
}

// SendErrorResponse answers with err if it is an *errors.AppError.
// Anything else is an internal failure: the caller is told only that
// something went wrong, and never sees the cause.
func SendErrorResponse(w http.ResponseWriter, err error) {
	appErr, ok := errors.AsAppError(err)
	if !ok {
		appErr = errors.ErrUnexpected
	}
	write(w, appErr.Status, Response{
		Status: appErr.Status,
		Error: &ErrorResponse{
			Type:    appErr.Type,
			Code:    appErr.Code,
			Message: appErr.Message,
			Details: appErr.Details,
		},
	})
}

func write(w http.ResponseWriter, statusCode int, body Response) {
	w.Header().Set("Content-Type", "application/json")
	// Answers can hold session details. They must never be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}
